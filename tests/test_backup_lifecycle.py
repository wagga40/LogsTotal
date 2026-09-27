"""Tests for scripts/backup_lifecycle.py — backend detection and the verification receipt."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from backup_lifecycle import (
    LEGACY_SQLITE_URL,
    effective_db_backend,
    load_env_file,
    read_app_version,
    read_receipt,
    write_receipt,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "backup_lifecycle.py"


class TestEffectiveDbBackend:
    def test_no_config_defaults_to_sqlite(self):
        assert effective_db_backend({}) == "sqlite"

    def test_explicit_postgres_url(self):
        env = {"DATABASE_URL": "postgresql+asyncpg://u:p@db:5432/logstotal"}
        assert effective_db_backend(env) == "postgres"

    def test_plain_libpq_postgres_url(self):
        env = {"DATABASE_URL": "postgresql://u:p@db:5432/logstotal"}
        assert effective_db_backend(env) == "postgres"

    def test_explicit_sqlite_url(self):
        env = {"DATABASE_URL": "sqlite+aiosqlite:////data/custom.db"}
        assert effective_db_backend(env) == "sqlite"

    # ── PostgreSQL gate: COMPOSE_PROFILES is the reference ────────────────────
    # POSTGRES_PASSWORD alone does not select postgres — the bundled service
    # must be in play (postgres profile) or an external POSTGRES_HOST configured.

    def test_password_with_postgres_profile_selects_postgres(self):
        env = {"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "postgres"}
        assert effective_db_backend(env) == "postgres"

    def test_password_without_profile_or_host_stays_sqlite(self):
        """The user-reported crash-loop repro: a gen-secrets password + proxy
        profile (no postgres) must NOT select postgres."""
        env = {"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy"}
        assert effective_db_backend(env) == "sqlite"

    def test_password_with_no_profiles_at_all_stays_sqlite(self):
        assert effective_db_backend({"POSTGRES_PASSWORD": "pw"}) == "sqlite"

    def test_password_with_external_postgres_host_selects_postgres(self):
        """External-host escape hatch: POSTGRES_HOST set (no profile) → postgres."""
        env = {"POSTGRES_PASSWORD": "pw", "POSTGRES_HOST": "db.internal"}
        assert effective_db_backend(env) == "postgres"

    def test_explicit_postgres_url_without_profile_selects_postgres(self):
        """Explicit DATABASE_URL is the escape hatch — wins without any profile."""
        env = {"DATABASE_URL": "postgresql+asyncpg://u:p@db:5432/logstotal"}
        assert effective_db_backend(env) == "postgres"

    def test_profiles_parsing_multi_value(self):
        env = {"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy,postgres,s3"}
        assert effective_db_backend(env) == "postgres"

    def test_profiles_parsing_tolerates_whitespace(self):
        env = {"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy, postgres"}
        assert effective_db_backend(env) == "postgres"

    def test_profiles_substring_is_not_a_match(self):
        """A profile literally named 'postgresql' must not satisfy the postgres gate."""
        env = {"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "postgresql"}
        assert effective_db_backend(env) == "sqlite"

    # ── Legacy template residue under both gate outcomes ──────────────────────

    def test_legacy_template_yields_to_postgres_when_gate_passes(self):
        """The shipped template default must not select the wrong backup engine
        once PostgreSQL mode actually engages (password + postgres profile)."""
        env = {
            "DATABASE_URL": LEGACY_SQLITE_URL,
            "POSTGRES_PASSWORD": "pw",
            "COMPOSE_PROFILES": "postgres",
        }
        assert effective_db_backend(env) == "postgres"

    def test_legacy_template_stays_sqlite_when_gate_fails(self):
        """Password present but no profile/host: the legacy SQLite line is NOT
        treated as residue — the deployment is genuinely on SQLite."""
        env = {
            "DATABASE_URL": LEGACY_SQLITE_URL,
            "POSTGRES_PASSWORD": "pw",
            "COMPOSE_PROFILES": "proxy",
        }
        assert effective_db_backend(env) == "sqlite"

    def test_legacy_template_with_custom_sync_url_stays_sqlite(self):
        """Even with the postgres gate open, a custom SYNC_DATABASE_URL marks the
        SQLite pair as deliberate and disables the residue override."""
        env = {
            "DATABASE_URL": LEGACY_SQLITE_URL,
            "SYNC_DATABASE_URL": "sqlite:////data/elsewhere.db",
            "POSTGRES_PASSWORD": "pw",
            "COMPOSE_PROFILES": "postgres",
        }
        assert effective_db_backend(env) == "sqlite"

    def test_custom_sqlite_wins_over_open_postgres_gate(self):
        """An explicit (non-legacy) SQLite DATABASE_URL wins even when the
        postgres gate is open."""
        env = {
            "DATABASE_URL": "sqlite+aiosqlite:////data/custom.db",
            "POSTGRES_PASSWORD": "pw",
            "COMPOSE_PROFILES": "postgres",
        }
        assert effective_db_backend(env) == "sqlite"


class TestLoadEnvFile:
    def test_parses_values_and_skips_comments(self, tmp_path: Path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# comment\n\nDATABASE_URL=postgresql://u:p@db/x\nEMPTY=\nNOEQUALS\n",
            encoding="utf-8",
        )
        values = load_env_file(env_file)
        assert values["DATABASE_URL"] == "postgresql://u:p@db/x"
        assert values["EMPTY"] == ""
        assert "NOEQUALS" not in values

    def test_missing_file_is_empty(self, tmp_path: Path):
        assert load_env_file(tmp_path / "absent.env") == {}


class TestReceipt:
    def test_write_and_read_roundtrip(self, tmp_path: Path):
        artifact = tmp_path / "logstotal-20260712-101010.db"
        artifact.write_bytes(b"data")
        backups = tmp_path / "backups"

        receipt_path = write_receipt("sqlite", artifact, backups, project_root=tmp_path)

        assert receipt_path == backups / "last-verified.json"
        receipt = read_receipt(backups)
        assert receipt is not None
        assert receipt["backend"] == "sqlite"
        assert receipt["artifact"] == "logstotal-20260712-101010.db"
        assert receipt["components"] == ["database"]
        assert receipt["verified_at"].endswith("+00:00")

    def test_receipt_records_app_version(self, tmp_path: Path):
        (tmp_path / "VERSION").write_text("version: 9.9.9\ngit_sha: abc\n", encoding="utf-8")
        artifact = tmp_path / "dump.sql.gz"
        artifact.write_bytes(b"data")

        write_receipt("postgres", artifact, tmp_path / "backups", project_root=tmp_path)

        receipt = read_receipt(tmp_path / "backups")
        assert receipt["app_version"] == "9.9.9"

    def test_receipt_contains_no_secret_values(self, tmp_path: Path):
        """The receipt is mounted/read by the control plane — it must stay non-secret."""
        artifact = tmp_path / "dump.sql.gz"
        artifact.write_bytes(b"data")
        backups = tmp_path / "backups"

        receipt_path = write_receipt("postgres", artifact, backups, project_root=tmp_path)

        text = receipt_path.read_text(encoding="utf-8")
        allowed_keys = {"backend", "artifact", "verified_at", "components", "app_version"}
        assert set(json.loads(text)) == allowed_keys

    def test_read_receipt_never_raises(self, tmp_path: Path):
        assert read_receipt(tmp_path) is None
        (tmp_path / "last-verified.json").write_text("not json", encoding="utf-8")
        assert read_receipt(tmp_path) is None
        (tmp_path / "last-verified.json").write_text('["a list"]', encoding="utf-8")
        assert read_receipt(tmp_path) is None


class TestReadAppVersion:
    def test_reads_version_line(self, tmp_path: Path):
        (tmp_path / "VERSION").write_text("version: 1.2.3\n", encoding="utf-8")
        assert read_app_version(tmp_path) == "1.2.3"

    def test_reads_a_legacy_four_key_manifest(self, tmp_path: Path):
        """Hosts installed before the manifest shrank still carry the build-metadata keys.

        Older manifests carry git_sha / git_branch / build_date alongside the version, and an
        upgraded host keeps whatever file it already had until the next release lands on it
        — so every reader has to ignore the extra keys rather than choke on them.
        """
        (tmp_path / "VERSION").write_text(
            "version: 1.2.3\ngit_sha: abc1234\ngit_branch: main\nbuild_date: 2026-01-01T00:00:00Z\n",
            encoding="utf-8",
        )
        assert read_app_version(tmp_path) == "1.2.3"

    def test_missing_file_returns_none(self, tmp_path: Path):
        assert read_app_version(tmp_path) is None


class TestCli:
    def _run_backend(self, extra_env: dict[str, str]) -> str:
        env = {**os.environ}
        for var in ("DATABASE_URL", "SYNC_DATABASE_URL", "POSTGRES_PASSWORD", "POSTGRES_HOST", "COMPOSE_PROFILES"):
            env.pop(var, None)
        env.update(extra_env)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "backend"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def test_backend_cli_postgres(self):
        out = self._run_backend({"DATABASE_URL": "postgresql+asyncpg://u:p@db:5432/logstotal"})
        assert out == "postgres"

    def test_backend_cli_sqlite(self):
        out = self._run_backend({"DATABASE_URL": "sqlite+aiosqlite:////data/custom.db"})
        assert out == "sqlite"

    def test_backend_cli_password_without_profile_is_sqlite(self):
        out = self._run_backend({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "proxy"})
        assert out == "sqlite"

    def test_backend_cli_password_with_profile_is_postgres(self):
        out = self._run_backend({"POSTGRES_PASSWORD": "pw", "COMPOSE_PROFILES": "postgres"})
        assert out == "postgres"

    def test_receipt_cli_rejects_missing_artifact(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "receipt", "--backend", "sqlite", "--artifact", "/nonexistent/x.db"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
        assert "not found" in result.stderr
