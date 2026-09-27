#!/usr/bin/env python3
"""
Generate every deployment secret LogsTotal needs, in one shot.

By default it prints a copy-paste block. With --write it fills the values into
.env, but ONLY for keys that are still empty or set to a known placeholder — it
never clobbers a real secret you have already configured.

Usage:
    python3 scripts/gen_secrets.py            # print only
    python3 scripts/gen_secrets.py --write    # write empty/placeholder keys into .env
    python3 scripts/gen_secrets.py --write --force   # overwrite even real values

Stdlib-only on purpose — `./logstotal quickstart` runs it before any venv exists.
PLACEHOLDER_VALUES below must stay a superset of the placeholder constants in
app/config.py; tests/test_gen_secrets.py pins that parity.
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path

# The one colour decision — see scripts/cli_color.py. Sibling import, the
# scripts/deploy_fleet_env.py idiom: these helpers run through `run_py` on hosts with no
# venv, so nothing here may reach the application.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_color import colors

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Known placeholder values shipped in .env.example / docker-compose.yml. A key whose
# current value is empty or one of these is considered "unset" and safe to fill.
PLACEHOLDER_VALUES = {
    "change-me-to-a-long-random-string-in-production",
    "change-me-in-production",
    "set-a-strong-password",
    "GKa1b2c3d4e5f6a7b8c9d0e0f1",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "changeme123",
    "<64-char-hex-secret>",
    "<random-token>",
}


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    return v == "" or v in PLACEHOLDER_VALUES or v.startswith("change-me")


def generate() -> dict[str, str]:
    """Generate a fresh secret for each managed key."""
    return {
        "SECRET_KEY": secrets.token_hex(32),
        "ADMIN_PASSWORD": secrets.token_urlsafe(18),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
        "REDIS_PASSWORD": secrets.token_urlsafe(24),
        "S3_ACCESS_KEY": "GK" + secrets.token_hex(12),
        "S3_SECRET_KEY": secrets.token_hex(32),
        "GARAGE_RPC_SECRET": secrets.token_hex(32),
        "GARAGE_ADMIN_TOKEN": secrets.token_urlsafe(24),
    }


def _current_value(env_text: str, key: str) -> str | None:
    """Return the current value of KEY in .env text, or None if the key is absent."""
    m = re.search(rf"^{re.escape(key)}=(.*)$", env_text, flags=re.M)
    return m.group(1) if m else None


def print_block(values: dict[str, str]) -> None:
    c = colors()
    print(f"\n{c['cyan']}# ── Generated secrets — paste into .env ──────────────────────────────{c['off']}")
    # The key names dim and the values bold: this block is read to copy VALUES out of, and
    # every key in it is already known from .env.example.
    for key, val in values.items():
        print(f"{c['dim']}{key}={c['off']}{c['bold']}{val}{c['off']}")
    print(f"{c['cyan']}# ─────────────────────────────────────────────────────────────────────{c['off']}")
    print(f"\n{c['dim']}Note: POSTGRES_PASSWORD avoids URL-unsafe characters (#@%?) so it works")
    print(f"in DATABASE_URL without escaping. Run with --write to apply to .env.{c['off']}")


def write_env(values: dict[str, str], force: bool) -> int:
    env_path = PROJECT_ROOT / ".env"
    if not env_path.exists():
        c = colors(stream=sys.stderr)
        print(f"{c['bold']}{c['red']}ERROR:{c['off']} .env not found. Create it first: cp .env.example .env", file=sys.stderr)
        return 1

    text = env_path.read_text(encoding="utf-8")
    written: list[str] = []
    skipped: list[str] = []

    for key, val in values.items():
        current = _current_value(text, key)
        if current is None:
            # Key not present (often commented out). Append it so it takes effect.
            if text and not text.endswith("\n"):
                text += "\n"
            text += f"{key}={val}\n"
            written.append(key)
        elif force or _is_placeholder(current):
            text = re.sub(rf"^{re.escape(key)}=.*$", f"{key}={val}", text, count=1, flags=re.M)
            written.append(key)
        else:
            skipped.append(key)

    env_path.write_text(text, encoding="utf-8")

    c = colors()
    if written:
        print(f"{c['bold']}{c['green']}✓{c['off']} wrote {len(written)} key(s) to .env: {', '.join(written)}")
    if "ADMIN_PASSWORD" in written:
        # Sized from its own content: a hand-counted width silently breaks the box the
        # day a secret gets longer than the padding someone measured once.
        rows = [
            "ADMIN LOGIN — save this now (also stored in .env)",
            f"password: {values['ADMIN_PASSWORD']}",
        ]
        width = max(len(r) for r in rows)
        # The box is drawn in colour but PADDED ON THE PLAIN LENGTH — the escapes are
        # zero-width on screen, so measuring the coloured string pushes the right-hand
        # border out by exactly their byte count and the box stops being a box.
        print(f"\n  {c['yellow']}┌" + "─" * (width + 4) + f"┐{c['off']}")
        for row in rows:
            print(f"  {c['yellow']}│{c['off']}  {c['bold']}{row}{c['off']}{' ' * (width - len(row))}  {c['yellow']}│{c['off']}")
        print(f"  {c['yellow']}└" + "─" * (width + 4) + f"┘{c['off']}\n")
    if skipped:
        print(f"{c['cyan']}NOTE:{c['off']} skipped {len(skipped)} key(s) that already had a real value: {', '.join(skipped)}")
        print("      (use --force to overwrite those too — this will break existing sessions/data)")
    if not written and not skipped:
        print("Nothing to do.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate LogsTotal deployment secrets")
    parser.add_argument("--write", action="store_true", help="write empty/placeholder keys into .env")
    parser.add_argument("--force", action="store_true", help="with --write, overwrite even real values")
    args = parser.parse_args()

    values = generate()
    if args.write:
        return write_env(values, force=args.force)
    print_block(values)
    if args.force:
        print("\n(--force has no effect without --write)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
