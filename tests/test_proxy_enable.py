"""Tests for scripts/proxy_enable.py — one-command HTTPS/.env proxy setup."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "proxy_enable.py"


#: Every environment variable `proxy_enable.main()` falls back to. Scrubbed for the whole
#: module, because an ambient value silently answers the question under test — `PROXY_TLS=off`
#: alone flips COOKIE_INSECURE, ENABLE_HSTS and PROXY_TLS in
#: test_main_writes_env_and_reports_summary, and `BASIC_AUTH_USER` fails six.
#:
#: These are not exotic: Taskfile.yml declares `dotenv: ['.env']`, so go-task exports whatever
#: a developer or a deploy left in there, and `task test` inherits it. Half the main() tests
#: already scrubbed a var or two by hand and the other half did not, which guards nothing —
#: the same reason `_SCRUBBED` exists in tests/test_release_resolver.py.
_AMBIENT = ("DOMAIN", "PROXY_TLS", "ACME_EMAIL", "BASIC_AUTH_USER", "BASIC_AUTH_HASH")


@pytest.fixture(autouse=True)
def _scrub_ambient_env(monkeypatch):
    for key in _AMBIENT:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture()
def proxy_enable():
    spec = importlib.util.spec_from_file_location("proxy_enable", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module defines a dataclass under `from __future__
    # import annotations`, and dataclasses resolves annotations via sys.modules[cls.__module__]
    # — without this, exec_module raises (module not found in sys.modules).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# A fixture resembling .env.example's real structure: a couple of active values,
# the proxy-relevant keys all commented out in their documented sections.
FRESH_ENV = """\
SECRET_KEY=change-me-to-a-long-random-string-in-production
DEBUG=false
# COOKIE_INSECURE=false

ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme123

# ── Docker Compose Profiles ────────────────────────────────────────────
# Examples:
#   COMPOSE_PROFILES=postgres
#   COMPOSE_PROFILES=postgres,s3,proxy
#
# COMPOSE_PROFILES=

DATABASE_URL=sqlite+aiosqlite:///./logstotal.db

# HSTS — only enable when serving over HTTPS.
# ENABLE_HSTS=false

# ── Reverse Proxy (optional) ──────────────────────────────────────────────
# DOMAIN=logs.example.com
# ACME_EMAIL=admin@example.com
# WEB_PORT=127.0.0.1:8000:8000
"""

DOMAIN = "logs.example.com"
ACME_EMAIL = "admin@example.com"


# ── Pure apply_proxy_settings() tests ─────────────────────────────────────────


def test_fresh_env_sets_every_key_the_mode_implies(proxy_enable):
    new_text, results = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL)

    by_key = {r.key: r for r in results}
    assert by_key["COMPOSE_PROFILES"].value == "proxy"
    assert by_key["DOMAIN"].value == DOMAIN
    assert by_key["PROXY_TLS"].value == "acme"
    assert by_key["ACME_EMAIL"].value == ACME_EMAIL
    assert by_key["WEB_PORT"].value == "127.0.0.1:8000:8000"
    assert by_key["COOKIE_INSECURE"].value == "false"
    assert by_key["ENABLE_HSTS"].value == "true"
    assert all(r.status == "set" for r in results)
    assert {r.key for r in results} == set(proxy_enable._KEY_ORDER)

    assert "\nCOMPOSE_PROFILES=proxy\n" in new_text
    assert f"\nDOMAIN={DOMAIN}\n" in new_text
    assert "\nPROXY_TLS=acme\n" in new_text
    assert f"\nACME_EMAIL={ACME_EMAIL}\n" in new_text
    assert "\nWEB_PORT=127.0.0.1:8000:8000\n" in new_text
    assert "\nCOOKIE_INSECURE=false\n" in new_text
    assert "\nENABLE_HSTS=true\n" in new_text


@pytest.mark.parametrize(
    ("tls", "cookie_insecure", "enable_hsts"),
    [
        ("acme", "false", "true"),
        # Real TLS, so the cookie stays Secure — but HSTS stays off, because a browser that
        # has not installed Caddy's local root would be pinned into a failure it cannot
        # click through.
        ("internal", "false", "false"),
        ("custom", "false", "true"),
        # Plain HTTP through Caddy: a Secure cookie here is silently dropped, and the
        # symptom is "the password is wrong".
        ("off", "true", "false"),
    ],
)
def test_each_tls_mode_writes_the_cookie_and_hsts_keys_it_needs(proxy_enable, tls, cookie_insecure, enable_hsts):
    new_text, results = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL, tls=tls)

    by_key = {r.key: r for r in results}
    assert by_key["PROXY_TLS"].value == tls
    assert by_key["COOKIE_INSECURE"].value == cookie_insecure
    assert by_key["ENABLE_HSTS"].value == enable_hsts
    assert f"\nPROXY_TLS={tls}\n" in new_text
    assert f"\nCOOKIE_INSECURE={cookie_insecure}\n" in new_text
    assert f"\nENABLE_HSTS={enable_hsts}\n" in new_text


def test_the_default_mode_is_acme_so_existing_callers_are_unchanged(proxy_enable):
    """scripts/deploy_fleet_env.py and every caller predating the other three modes pass
    three positional-ish arguments and must keep getting exactly what they got before."""
    with_default, _ = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL)
    explicit, _ = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL, tls="acme")
    assert with_default == explicit


def test_an_unknown_mode_raises_rather_than_writing_a_half_configured_env(proxy_enable):
    with pytest.raises(ValueError, match="unknown TLS mode"):
        proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL, tls="internl")


def test_switching_mode_rewrites_the_dependent_keys(proxy_enable):
    """The failure this prevents: adopting PROXY_TLS=off on a previously-HTTPS .env and
    leaving COOKIE_INSECURE=false behind, which reads as "my password stopped working"."""
    https_text, _ = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL, tls="acme")
    assert "\nCOOKIE_INSECURE=false\n" in https_text

    plain_text, results = proxy_enable.apply_proxy_settings(https_text, domain=DOMAIN, acme_email=ACME_EMAIL, tls="off")
    by_key = {r.key: r for r in results}
    assert by_key["COOKIE_INSECURE"].status == "set"
    assert by_key["ENABLE_HSTS"].status == "set"
    assert "\nCOOKIE_INSECURE=true\n" in plain_text
    assert "\nENABLE_HSTS=false\n" in plain_text
    assert "\nCOOKIE_INSECURE=false\n" not in plain_text


def test_fresh_env_preserves_unrelated_lines_exactly(proxy_enable):
    new_text, _ = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL)

    for line in [
        "SECRET_KEY=change-me-to-a-long-random-string-in-production",
        "DEBUG=false",
        "ADMIN_EMAIL=admin@example.com",
        "ADMIN_PASSWORD=changeme123",
        "DATABASE_URL=sqlite+aiosqlite:///./logstotal.db",
        "# ── Docker Compose Profiles ────────────────────────────────────────────",
        "#   COMPOSE_PROFILES=postgres,s3,proxy",
    ]:
        assert line in new_text


def test_active_line_wins_over_commented_occurrence(proxy_enable):
    """When both a commented `# DOMAIN=...` line and an active `DOMAIN=...` line
    exist, the active line is what gets updated — the commented line is left
    alone as documentation, never duplicated or turned into a second active line."""
    env_text = FRESH_ENV.replace(
        "# DOMAIN=logs.example.com\n",
        "# DOMAIN=logs.example.com\nDOMAIN=old-value.example.org\n",
    )
    new_text, results = proxy_enable.apply_proxy_settings(env_text, domain=DOMAIN, acme_email=ACME_EMAIL)

    by_key = {r.key: r for r in results}
    assert by_key["DOMAIN"].status == "set"
    assert by_key["DOMAIN"].value == DOMAIN
    active_lines = re.findall(r"^DOMAIN=.*$", new_text, flags=re.M)
    assert active_lines == [f"DOMAIN={DOMAIN}"]  # old active value replaced, not duplicated
    assert "# DOMAIN=logs.example.com" in new_text  # commented line preserved untouched


def test_commented_only_domain_line_gets_active_line_added_in_section(proxy_enable):
    """The active DOMAIN= line must land right after the last `# DOMAIN=` occurrence,
    keeping it in its documented section rather than appended somewhere unrelated."""
    new_text, _ = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL)
    lines = new_text.splitlines()
    commented_idx = lines.index("# DOMAIN=logs.example.com")
    assert lines[commented_idx + 1] == f"DOMAIN={DOMAIN}"


def test_compose_profiles_appends_to_existing_list(proxy_enable):
    env_text = FRESH_ENV.replace("# COMPOSE_PROFILES=\n", "COMPOSE_PROFILES=postgres\n")
    new_text, results = proxy_enable.apply_proxy_settings(env_text, domain=DOMAIN, acme_email=ACME_EMAIL)

    by_key = {r.key: r for r in results}
    assert by_key["COMPOSE_PROFILES"].value == "postgres,proxy"
    assert by_key["COMPOSE_PROFILES"].status == "set"
    active_lines = re.findall(r"^COMPOSE_PROFILES=.*$", new_text, flags=re.M)
    assert active_lines == ["COMPOSE_PROFILES=postgres,proxy"]  # replaced in place, not duplicated


def test_compose_profiles_already_containing_proxy_is_unchanged(proxy_enable):
    env_text = FRESH_ENV.replace("# COMPOSE_PROFILES=\n", "COMPOSE_PROFILES=postgres,proxy\n")
    new_text, results = proxy_enable.apply_proxy_settings(env_text, domain=DOMAIN, acme_email=ACME_EMAIL)

    by_key = {r.key: r for r in results}
    assert by_key["COMPOSE_PROFILES"].status == "unchanged"
    assert by_key["COMPOSE_PROFILES"].value == "postgres,proxy"
    active_lines = re.findall(r"^COMPOSE_PROFILES=.*$", new_text, flags=re.M)
    assert active_lines == ["COMPOSE_PROFILES=postgres,proxy"]  # untouched, not duplicated


def test_compose_profiles_empty_active_value_becomes_proxy(proxy_enable):
    env_text = FRESH_ENV.replace("# COMPOSE_PROFILES=\n", "COMPOSE_PROFILES=\n")
    new_text, results = proxy_enable.apply_proxy_settings(env_text, domain=DOMAIN, acme_email=ACME_EMAIL)

    by_key = {r.key: r for r in results}
    assert by_key["COMPOSE_PROFILES"].value == "proxy"
    assert "COMPOSE_PROFILES=proxy" in new_text


def test_key_missing_entirely_appended_under_marker(proxy_enable):
    """A key never mentioned at all (not even commented) must be appended at EOF
    under the `# --- set by task proxy:enable ---` marker."""
    env_text = FRESH_ENV.replace("# ACME_EMAIL=admin@example.com\n", "")
    assert "ACME_EMAIL" not in env_text

    new_text, results = proxy_enable.apply_proxy_settings(env_text, domain=DOMAIN, acme_email=ACME_EMAIL)
    by_key = {r.key: r for r in results}
    assert by_key["ACME_EMAIL"].status == "set"
    assert by_key["ACME_EMAIL"].value == ACME_EMAIL

    assert proxy_enable.MARKER in new_text
    marker_idx = new_text.index(proxy_enable.MARKER)
    acme_idx = new_text.index(f"ACME_EMAIL={ACME_EMAIL}")
    assert acme_idx > marker_idx


def test_already_correct_env_is_all_unchanged(proxy_enable):
    """Running twice in a row (pure function, second pass fed the first pass's
    output) reports every key already correct and produces byte-identical text."""
    once_text, _ = proxy_enable.apply_proxy_settings(FRESH_ENV, domain=DOMAIN, acme_email=ACME_EMAIL)
    twice_text, results = proxy_enable.apply_proxy_settings(once_text, domain=DOMAIN, acme_email=ACME_EMAIL)

    assert twice_text == once_text
    assert all(r.status == "unchanged" for r in results)


# ── main() end-to-end tests (file I/O, exit codes) ────────────────────────────


def test_main_writes_env_and_reports_summary(proxy_enable, tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")

    rc = proxy_enable.main(["--domain", DOMAIN, "--acme-email", ACME_EMAIL, "--env", str(env)])
    assert rc == 0

    text = env.read_text(encoding="utf-8")
    assert "COMPOSE_PROFILES=proxy" in text
    assert f"DOMAIN={DOMAIN}" in text
    assert f"ACME_EMAIL={ACME_EMAIL}" in text
    assert "WEB_PORT=127.0.0.1:8000:8000" in text
    assert "COOKIE_INSECURE=false" in text
    assert "ENABLE_HSTS=true" in text

    out = capsys.readouterr().out
    assert "COMPOSE_PROFILES=proxy" in out
    assert f"DOMAIN={DOMAIN}" in out
    # Never echo unrelated .env content (secrets).
    assert "change-me-to-a-long-random-string-in-production" not in out
    assert "changeme123" not in out


def test_main_idempotent_rerun_is_byte_identical(proxy_enable, tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")

    proxy_enable.main(["--domain", DOMAIN, "--acme-email", ACME_EMAIL, "--env", str(env)])
    text_after_first = env.read_text(encoding="utf-8")
    capsys.readouterr()

    rc = proxy_enable.main(["--domain", DOMAIN, "--acme-email", ACME_EMAIL, "--env", str(env)])
    assert rc == 0
    assert env.read_text(encoding="utf-8") == text_after_first

    out = capsys.readouterr().out
    assert "already correct" in out.lower()


def test_main_missing_env_file_errors(proxy_enable, tmp_path, capsys):
    missing_env = tmp_path / ".env"  # never created

    rc = proxy_enable.main(["--domain", DOMAIN, "--acme-email", ACME_EMAIL, "--env", str(missing_env)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert ".env not found" in err or "not found" in err


def test_main_internal_mode_needs_no_email_and_runs_no_dns_check(proxy_enable, tmp_path, monkeypatch, capsys):
    """An internal deployment must not have to invent an ACME_EMAIL to get past the gate.

    The DNS check is skipped too: comparing an internal name against this host's *public*
    IP is a guaranteed false alarm, and a WARN nobody should act on is worse than silence.
    """
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")

    rc = proxy_enable.main(["--domain", "logs.internal", "--tls", "internal", "--env", str(env)])
    assert rc == 0

    text = env.read_text(encoding="utf-8")
    assert "PROXY_TLS=internal" in text
    assert "COOKIE_INSECURE=false" in text
    assert "ENABLE_HSTS=false" in text

    out = capsys.readouterr().out
    assert "DNS check" not in out
    assert "root.crt" in out, "an internal CA is useless until its root is installed — say so"


def test_main_off_mode_says_nothing_here_terminates_tls(proxy_enable, tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")

    assert proxy_enable.main(["--domain", "logs.internal", "--tls", "off", "--env", str(env)]) == 0

    text = env.read_text(encoding="utf-8")
    assert "PROXY_TLS=off" in text
    assert "COOKIE_INSECURE=true" in text
    out = capsys.readouterr().out
    assert "80 and 443" not in out, "that advice is ACME-specific and misleading here"
    assert "terminates TLS" in out


def test_main_rejects_an_unknown_mode_before_touching_the_env(proxy_enable, tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")

    assert proxy_enable.main(["--domain", DOMAIN, "--tls", "internal", "--env", str(env), "--acme-email", ACME_EMAIL]) == 0
    before = env.read_text(encoding="utf-8")
    monkeypatch.setenv("PROXY_TLS", "internl")
    assert proxy_enable.main(["--domain", DOMAIN, "--env", str(env)]) == 1
    assert env.read_text(encoding="utf-8") == before
    assert "is not one of" in capsys.readouterr().err


def test_main_missing_domain_or_acme_email_errors(proxy_enable, tmp_path, monkeypatch, capsys):
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")

    rc = proxy_enable.main(["--env", str(env)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "ERROR" in err
    assert "DOMAIN" in err and "ACME_EMAIL" in err
    assert "./logstotal proxy:enable" in err  # exact invocation shown


def test_main_domain_and_acme_email_fall_back_to_env_vars(proxy_enable, tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(FRESH_ENV, encoding="utf-8")
    monkeypatch.setenv("DOMAIN", DOMAIN)
    monkeypatch.setenv("ACME_EMAIL", ACME_EMAIL)

    rc = proxy_enable.main(["--env", str(env)])
    assert rc == 0
    text = env.read_text(encoding="utf-8")
    assert f"DOMAIN={DOMAIN}" in text
    assert f"ACME_EMAIL={ACME_EMAIL}" in text


# ── DNS check tests (injected resolver/fetcher, no network) ──────────────────


def test_check_dns_match_no_warning(proxy_enable):
    msg = proxy_enable.check_dns(DOMAIN, resolve=lambda d: ["203.0.113.10"], fetch_public_ip=lambda: "203.0.113.10")
    assert "WARN" not in msg
    assert "INFO" not in msg


def test_check_dns_mismatch_warns(proxy_enable):
    msg = proxy_enable.check_dns(DOMAIN, resolve=lambda d: ["198.51.100.1"], fetch_public_ip=lambda: "203.0.113.10")
    assert msg.startswith("WARN:")


def test_check_dns_resolver_failure_is_skipped_info(proxy_enable):
    def _boom(domain):
        raise OSError("network unreachable")

    msg = proxy_enable.check_dns(DOMAIN, resolve=_boom, fetch_public_ip=lambda: "203.0.113.10")
    assert msg.startswith("INFO:")
    assert "skipped" in msg.lower()


def test_check_dns_fetch_failure_is_skipped_info(proxy_enable):
    def _boom():
        raise TimeoutError("timed out")

    msg = proxy_enable.check_dns(DOMAIN, resolve=lambda d: ["203.0.113.10"], fetch_public_ip=_boom)
    assert msg.startswith("INFO:")
    assert "skipped" in msg.lower()


# ── Basic auth ───────────────────────────────────────────────────────────────
#
# There was no command for this at all: the recipe lived as copy-paste prose in
# .env.example, docs/configuration.md (twice), docs/install/prerequisites.md and
# docs/troubleshooting.md, and `task proxy:enable` — the one command whose whole job
# is "turn HTTPS on" — did not touch either key.


def test_basic_auth_sets_both_keys(proxy_enable):
    text, results = proxy_enable.apply_basic_auth("SECRET_KEY=x\n", "ops", "$2a$14$abc")
    assert [r.key for r in results] == ["BASIC_AUTH_USER", "BASIC_AUTH_HASH"]
    assert "BASIC_AUTH_USER=ops" in text


def test_the_hash_is_single_quoted(proxy_enable):
    """Compose interpolates `$` in env values and a bcrypt hash is mostly `$`;
    docker-caddy-entrypoint.sh rejects whitespace and braces but not that, so an
    unquoted hash reaches Caddy as a different string and every login fails silently."""
    text, _ = proxy_enable.apply_basic_auth("A=1\n", "ops", "$2a$14$abc")
    assert "BASIC_AUTH_HASH='$2a$14$abc'" in text


def test_an_already_quoted_hash_is_not_double_quoted(proxy_enable):
    text, _ = proxy_enable.apply_basic_auth("A=1\n", "ops", "'$2a$14$abc'")
    assert "BASIC_AUTH_HASH='$2a$14$abc'" in text
    assert "''" not in text


def test_basic_auth_is_idempotent(proxy_enable):
    once, _ = proxy_enable.apply_basic_auth("A=1\n", "ops", "$2a$14$abc")
    twice, results = proxy_enable.apply_basic_auth(once, "ops", "$2a$14$abc")
    assert twice == once
    assert {r.status for r in results} == {"unchanged"}


def test_half_a_credential_pair_is_a_no_op(proxy_enable):
    """docker-caddy-entrypoint.sh refuses to start when only one of the two is set,
    so writing half of them would take the whole control plane down."""
    assert proxy_enable.apply_basic_auth("A=1\n", "ops", "") == ("A=1\n", [])
    assert proxy_enable.apply_basic_auth("A=1\n", "", "$2a$14$abc") == ("A=1\n", [])


def test_the_six_https_keys_are_untouched_by_basic_auth(proxy_enable):
    text, _ = proxy_enable.apply_proxy_settings("A=1\n", "logs.example.com", "ops@example.com")
    with_auth, _ = proxy_enable.apply_basic_auth(text, "ops", "$2a$14$abc")
    for key in proxy_enable._KEY_ORDER:
        assert f"{key}=" in with_auth
