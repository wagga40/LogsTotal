"""Tests for scripts/env_diff.py — .env vs .env.example key diffing."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "env_diff.py"
ENV_EXAMPLE_PATH = Path(__file__).resolve().parent.parent / ".env.example"


@pytest.fixture()
def env_diff():
    spec = importlib.util.spec_from_file_location("env_diff", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module defines a dataclass under `from __future__
    # import annotations`, and dataclasses resolves annotations via sys.modules[cls.__module__]
    # — without this, exec_module raises (module not found in sys.modules).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXAMPLE_TEXT = """\
# ── Application ─────────────────────────────────────────
SECRET_KEY=change-me-to-a-long-random-string-in-production

# ── Redis / Queue ───────────────────────────────────────
REDIS_HOST=localhost
# REDIS_PASSWORD=

# ── New Feature ─────────────────────────────────────────
# NEW_FEATURE_FLAG=false
"""


# ── Pure function tests ───────────────────────────────────────────────────────


def test_parse_example_keys_captures_default_line_and_section(env_diff):
    keys = env_diff.parse_example_keys(EXAMPLE_TEXT)
    assert keys["NEW_FEATURE_FLAG"].default_line == "# NEW_FEATURE_FLAG=false"
    assert keys["NEW_FEATURE_FLAG"].section == "# ── New Feature ─────────────────────────────────────────"
    assert keys["REDIS_HOST"].section == "# ── Redis / Queue ───────────────────────────────────────"
    assert keys["REDIS_PASSWORD"].default_line == "# REDIS_PASSWORD="


def test_prose_example_lines_do_not_shadow_real_default(env_diff):
    """An indented `#   KEY=...` prose/example mention earlier in the file must not
    win over the real non-indented `# KEY=` declaration — the reported default line
    and section must come from the declaration, not the prose."""
    text = (
        "# ── Section A ─────────────\n"
        "# Examples:\n"
        "#   COMPOSE_PROFILES=postgres\n"
        "#   COMPOSE_PROFILES=postgres,s3\n"
        "\n"
        "# ── Section B ─────────────\n"
        "# COMPOSE_PROFILES=\n"
        "\n"
        "# ── Section C ─────────────\n"
        "#   PROSE_ONLY_KEY=indented-example-only\n"
    )
    keys = env_diff.parse_example_keys(text)
    assert keys["COMPOSE_PROFILES"].default_line == "# COMPOSE_PROFILES="
    assert "Section B" in keys["COMPOSE_PROFILES"].section
    # No non-indented declaration exists → fall back to the prose occurrence.
    assert keys["PROSE_ONLY_KEY"].default_line == "#   PROSE_ONLY_KEY=indented-example-only"
    assert "Section C" in keys["PROSE_ONLY_KEY"].section


def test_real_env_example_picks_declarations_not_prose(env_diff):
    """Smoke test against the repo's actual .env.example: the two keys whose prose
    'Examples:' mentions precede their real declaration must resolve to the
    declaration line."""
    keys = env_diff.parse_example_keys(ENV_EXAMPLE_PATH.read_text(encoding="utf-8"))
    assert keys["COMPOSE_PROFILES"].default_line == "# COMPOSE_PROFILES="
    assert keys["REDIS_EXPOSE"].default_line == "# REDIS_EXPOSE=127.0.0.1:6379"


def test_diff_env_reports_new_key_with_default_line_and_section(env_diff):
    """Case 1: a key documented in .env.example but never mentioned in .env is
    reported, carrying its verbatim default line and section context."""
    env_text = "SECRET_KEY=real-value\nREDIS_HOST=localhost\n"
    missing, unknown = env_diff.diff_env(EXAMPLE_TEXT, env_text)

    missing_by_key = {m.key: m for m in missing}
    assert "NEW_FEATURE_FLAG" in missing_by_key
    assert missing_by_key["NEW_FEATURE_FLAG"].default_line == "# NEW_FEATURE_FLAG=false"
    assert "New Feature" in missing_by_key["NEW_FEATURE_FLAG"].section
    assert unknown == []


def test_commented_out_key_in_env_counts_as_seen(env_diff):
    """Case 2: a key that's commented out in .env (operator knows about it, chose
    the default) must NOT show up in the missing report."""
    env_text = "SECRET_KEY=real-value\nREDIS_HOST=localhost\n# REDIS_PASSWORD=super-secret-not-used\n# NEW_FEATURE_FLAG=false\n"
    missing, unknown = env_diff.diff_env(EXAMPLE_TEXT, env_text)

    missing_keys = {m.key for m in missing}
    assert "REDIS_PASSWORD" not in missing_keys
    assert "NEW_FEATURE_FLAG" not in missing_keys
    assert missing == []
    assert unknown == []


def test_set_but_unknown_key_reported(env_diff):
    """Case 3: a key set (uncommented) in .env that .env.example doesn't document
    at all is a typo candidate and must be reported as unknown."""
    env_text = "SECRET_KEY=real-value\nREDIS_HOST=localhost\n# REDIS_PASSWORD=\n# NEW_FEATURE_FLAG=false\nFAKE_KEY=1\n"
    missing, unknown = env_diff.diff_env(EXAMPLE_TEXT, env_text)

    assert unknown == ["FAKE_KEY"]
    assert missing == []


def test_diff_env_both_clean(env_diff):
    """Case 4: a .env that covers every documented key and sets nothing unknown
    produces empty reports."""
    env_text = "SECRET_KEY=real-value\nREDIS_HOST=localhost\n# REDIS_PASSWORD=\n# NEW_FEATURE_FLAG=false\n"
    missing, unknown = env_diff.diff_env(EXAMPLE_TEXT, env_text)
    assert missing == []
    assert unknown == []


def test_render_report_ok_line_when_both_clean(env_diff, capsys):
    env_diff.render_report([], [])
    out = capsys.readouterr().out
    assert out.strip() == "OK   .env covers all documented keys; no unknown keys."


def test_render_report_never_prints_unknown_key_value(env_diff, capsys):
    """Report B must never echo the value assigned to an unknown key — only the
    key name — since that value could be a real secret in the operator's .env."""
    env_diff.render_report([], ["FAKE_KEY"])
    out = capsys.readouterr().out
    assert "FAKE_KEY" in out
    assert "typo" in out.lower()
    assert "FAKE_KEY=" not in out  # only the key name is printed, never a "KEY=value" pairing


# ── main() end-to-end tests ───────────────────────────────────────────────────


def test_main_both_clean_exits_zero(env_diff, tmp_path, capsys):
    """Case 4 (end-to-end): clean .env → OK output, exit 0."""
    example = tmp_path / ".env.example"
    example.write_text(EXAMPLE_TEXT, encoding="utf-8")
    env = tmp_path / ".env"
    env.write_text("SECRET_KEY=real-value\nREDIS_HOST=localhost\n# REDIS_PASSWORD=\n# NEW_FEATURE_FLAG=false\n", encoding="utf-8")

    rc = env_diff.main(["--env", str(env), "--example", str(example)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK   " in out


def test_main_strict_exit_codes(env_diff, tmp_path):
    """Case 5: --strict exits 1 when dirty, 0 when clean; default is always 0."""
    example = tmp_path / ".env.example"
    example.write_text(EXAMPLE_TEXT, encoding="utf-8")

    clean_env = tmp_path / "clean.env"
    clean_env.write_text("SECRET_KEY=real-value\nREDIS_HOST=localhost\n# REDIS_PASSWORD=\n# NEW_FEATURE_FLAG=false\n", encoding="utf-8")
    assert env_diff.main(["--env", str(clean_env), "--example", str(example), "--strict"]) == 0

    dirty_env = tmp_path / "dirty.env"
    dirty_env.write_text("SECRET_KEY=real-value\nFAKE_KEY=1\n", encoding="utf-8")
    assert env_diff.main(["--env", str(dirty_env), "--example", str(example)]) == 0  # informational by default
    assert env_diff.main(["--env", str(dirty_env), "--example", str(example), "--strict"]) == 1


def test_main_missing_env_errors(env_diff, tmp_path, capsys):
    """Case 6: missing .env → clean error, exit 1, no traceback."""
    example = tmp_path / ".env.example"
    example.write_text(EXAMPLE_TEXT, encoding="utf-8")
    missing_env = tmp_path / ".env"  # never created

    rc = env_diff.main(["--env", str(missing_env), "--example", str(example)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert ".env not found" in err


def test_main_missing_example_errors(env_diff, tmp_path, capsys):
    """Missing .env.example is also a clean error, exit 1 (not part of the brief's
    six numbered cases, but explicitly required error handling)."""
    env = tmp_path / ".env"
    env.write_text("SECRET_KEY=x\n", encoding="utf-8")
    missing_example = tmp_path / ".env.example"  # never created

    rc = env_diff.main(["--env", str(env), "--example", str(missing_example)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err


def test_main_missing_env_is_an_error_by_default(env_diff, tmp_path, capsys):
    """Typed by hand, or on a single-host upgrade, "no .env" is the useful answer."""
    example = tmp_path / ".env.example"
    example.write_text("# KEY=value\n", encoding="utf-8")

    rc = env_diff.main(["--env", str(tmp_path / ".env"), "--example", str(example)])

    assert rc == 1
    assert "ERROR: .env not found" in capsys.readouterr().err


def test_main_missing_env_is_tolerated_when_optional(env_diff, tmp_path, capsys):
    """The multi-server upgrade runs from a workstation that has no `.env` at all.

    `upgrade.sh` calls this step "informational" and prints "review these against each
    host's env file" immediately above it — the control plane's real `.env` lives on the
    control plane, and both `package.sh` (`-x!.env`) and the deploy rsync (`--exclude=.env`)
    exclude the local file by name, so it could never be the one that ships.

    `upgrade.sh` runs under `set -e`, so an exit 1 here would abort an upgrade of a healthy
    fleet *after* the verified backup and after the checkout, leaving a detached HEAD and an
    undeployed fleet. A step that cannot change anything must not be able to stop everything.
    """
    example = tmp_path / ".env.example"
    example.write_text("# ALPHA=1\n# BETA=2\n", encoding="utf-8")

    rc = env_diff.main(["--env", str(tmp_path / ".env"), "--example", str(example), "--optional"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "No local .env" in out
    assert "2 keys" in out


def test_the_multiserver_upgrade_passes_optional(env_diff):
    """The flag is worthless if the one call site that needs it does not pass it.

    Pinned as text because the failure is invisible to every other test: the script is
    correct shell, the flag exists and works, and the upgrade still dies on a fleet that
    has nothing wrong with it.
    """
    from pathlib import Path

    script = (Path(__file__).resolve().parent.parent / "scripts" / "upgrade.sh").read_text(encoding="utf-8")
    multiserver = script[script.index("do_multiserver()") :]
    assert "task env:diff -- --optional" in multiserver, "the multi-server upgrade must tolerate a missing local .env"
