#!/usr/bin/env python3
"""
Shared helpers for the verified backup lifecycle (`./logstotal backup`).

Stdlib-only on purpose (like scripts/gen_secrets.py) — Docker-only hosts run it
with plain python3, no venv needed.

Subcommands:

    python3 scripts/backup_lifecycle.py backend
        Print the effective database backend for this deployment: "postgres" or
        "sqlite". Mirrors docker-entrypoint.sh's auto-detection precedence: an
        explicit DATABASE_URL wins; otherwise PostgreSQL mode engages only when
        POSTGRES_PASSWORD is set AND the bundled service gate passes ("postgres"
        in COMPOSE_PROFILES, or an explicit POSTGRES_HOST) — a leftover password
        alone stays on SQLite. The legacy .env template default
        (sqlite+aiosqlite:///./logstotal.db) is ignored only when PostgreSQL mode
        would actually engage and no custom SYNC_DATABASE_URL marks the SQLite
        pair as deliberate. Process env wins over .env.

    python3 scripts/backup_lifecycle.py receipt --backend B --artifact PATH
        Write the non-secret backups/last-verified.json receipt recording what
        `./logstotal backup` just created AND verified. Contains only the backend,
        artifact basename, UTC timestamp, verified components, and app version
        — never credentials or backup contents.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RECEIPT_BASENAME = "last-verified.json"

# The SQLite pair older .env templates shipped uncommented. Must match the
# legacy-override guard in docker-entrypoint.sh.
LEGACY_SQLITE_URL = "sqlite+aiosqlite:///./logstotal.db"
LEGACY_SQLITE_SYNC_URL = "sqlite:///./logstotal.db"


def load_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines from a .env file (comments/blank lines skipped)."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def effective_env(project_root: Path = PROJECT_ROOT) -> dict[str, str]:
    """Merge .env values with the process environment (process env wins)."""
    merged = load_env_file(project_root / ".env")
    merged.update(os.environ)
    return merged


def effective_db_backend(env: dict[str, str]) -> str:
    """Return "postgres" or "sqlite" using docker-entrypoint.sh precedence.

    PostgreSQL mode requires POSTGRES_PASSWORD **and** the bundled service gate:
    the ``postgres`` compose profile enabled, or an explicit external
    POSTGRES_HOST. COMPOSE_PROFILES is the reference for whether the bundled
    postgres service is in play — a password alone (e.g. one ``gen-secrets``
    appended while the key was commented out) does not select postgres. This
    mirrors the entrypoint's gate so `./logstotal backup` never dumps the wrong engine.
    """
    url = (env.get("DATABASE_URL") or "").strip()
    sync_url = (env.get("SYNC_DATABASE_URL") or "").strip()
    pg_password = (env.get("POSTGRES_PASSWORD") or "").strip()
    pg_host = (env.get("POSTGRES_HOST") or "").strip()
    profiles = {p.strip() for p in (env.get("COMPOSE_PROFILES") or "").split(",") if p.strip()}
    pg_enabled = bool(pg_password) and ("postgres" in profiles or bool(pg_host))

    if url == LEGACY_SQLITE_URL and pg_enabled and sync_url in ("", LEGACY_SQLITE_SYNC_URL):
        # Template residue, not a choice — same rule as the Docker entrypoint,
        # and only when PostgreSQL mode would actually engage.
        url = ""

    if "postgres" in url:
        return "postgres"
    if url:
        return "sqlite"
    return "postgres" if pg_enabled else "sqlite"


def read_app_version(project_root: Path = PROJECT_ROOT) -> str | None:
    """Read the `version:` line from the canonical VERSION file, if present."""
    version_file = project_root / "VERSION"
    if not version_file.exists():
        return None
    match = re.search(r"^version:\s*(\S+)", version_file.read_text(encoding="utf-8"), flags=re.M)
    return match.group(1) if match else None


def write_receipt(
    backend: str,
    artifact: Path,
    backups_dir: Path,
    components: list[str] | None = None,
    project_root: Path = PROJECT_ROOT,
) -> Path:
    """Write the non-secret verification receipt and return its path."""
    receipt = {
        "backend": backend,
        "artifact": artifact.name,
        "verified_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "components": components or ["database"],
        "app_version": read_app_version(project_root),
    }
    backups_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = backups_dir / RECEIPT_BASENAME
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt_path


def read_receipt(backups_dir: Path) -> dict | None:
    """Read the receipt back, or None when absent/unparseable (never raises)."""
    receipt_path = backups_dir / RECEIPT_BASENAME
    try:
        data = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Verified backup lifecycle helpers")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("backend", help="print the effective database backend (postgres|sqlite)")

    receipt_parser = sub.add_parser("receipt", help="write backups/last-verified.json")
    receipt_parser.add_argument("--backend", required=True, choices=["postgres", "sqlite"])
    receipt_parser.add_argument("--artifact", required=True, help="path of the verified artifact")

    args = parser.parse_args()

    if args.command == "backend":
        print(effective_db_backend(effective_env()))
        return 0

    artifact = Path(args.artifact)
    if not artifact.exists():
        print(f"ERROR: artifact not found: {artifact}", file=sys.stderr)
        return 1
    receipt_path = write_receipt(args.backend, artifact, PROJECT_ROOT / "backups")
    print(f"Receipt written: {receipt_path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
