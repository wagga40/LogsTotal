"""What `docker-caddy-entrypoint.sh` renders, per PROXY_TLS mode.

Until this file existed the entrypoint had exactly one test — `bash -n` in
tests/test_shell_scripts.py — so nothing anywhere asserted what the proxy actually serves.
That was survivable while it had one behaviour; with four TLS modes it is not, and the
`acme` bytes below are the ones every existing deployment is already running.

Driven through LOGSTOTAL_CADDY_DRYRUN=1, the docker-entrypoint.sh idiom: render to stdout,
skip the exec. The seam sits after every validation, so the refusals are on this path too.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = REPO_ROOT / "docker-caddy-entrypoint.sh"

# /bin/sh on the caddy image is busybox ash. dash is the closest widely-installed stand-in
# and is stricter than bash-as-sh, which is what makes it worth preferring when present.
SHELL = shutil.which("dash") or "sh"


def _render(**env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [SHELL, str(ENTRYPOINT)],
        env={"PATH": "/usr/bin:/bin", "LOGSTOTAL_CADDY_DRYRUN": "1", **env},
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )


def _ok(**env: str) -> str:
    result = _render(**env)
    assert result.returncode == 0, f"exit {result.returncode}: {result.stderr}"
    return result.stdout


# ── acme: the shape that already exists in the field ─────────────────────────


def test_acme_with_an_email_is_the_config_deployments_already_run():
    assert _ok(DOMAIN="logs.example.com", ACME_EMAIL="ops@example.com") == ("{\n    email ops@example.com\n}\n\nlogs.example.com {\n    reverse_proxy web:8000\n}\n")


def test_acme_without_an_email_omits_the_global_block_entirely():
    """Rendering `email` with no argument is a parse error, i.e. a crash loop — which is
    what the manual HTTPS setup produces."""
    result = _render(DOMAIN="logs.example.com")
    assert result.returncode == 0
    assert result.stdout == "logs.example.com {\n    reverse_proxy web:8000\n}\n"
    assert "ACME_EMAIL is not set" in result.stderr


def test_acme_is_the_default_when_proxy_tls_is_unset():
    assert _ok(DOMAIN="logs.example.com", ACME_EMAIL="ops@example.com") == _ok(DOMAIN="logs.example.com", ACME_EMAIL="ops@example.com", PROXY_TLS="acme")


def test_the_default_domain_is_localhost():
    assert _ok().startswith("localhost {")


# ── the three modes that make an internal deployment possible ────────────────


def test_internal_asks_caddy_for_its_own_ca():
    assert _ok(DOMAIN="logs.internal", PROXY_TLS="internal") == ("logs.internal {\n    tls internal\n    reverse_proxy web:8000\n}\n")


def test_off_turns_automatic_https_off_by_naming_the_scheme():
    """A bare hostname is what triggers Caddy's Automatic HTTPS; an explicit http:// is the
    only thing that turns it off for a site."""
    assert _ok(DOMAIN="logs.internal", PROXY_TLS="off") == ("http://logs.internal {\n    reverse_proxy web:8000\n}\n")


def test_custom_names_the_operators_certificate(tmp_path: Path):
    cert, key = tmp_path / "fullchain.pem", tmp_path / "privkey.pem"
    cert.write_text("cert")
    key.write_text("key")
    rendered = _ok(
        DOMAIN="logs.internal",
        PROXY_TLS="custom",
        CADDY_CERT_DIR=str(tmp_path),
        PROXY_TLS_CERT=str(cert),
        PROXY_TLS_KEY=str(key),
    )
    assert rendered == f"logs.internal {{\n    tls {cert} {key}\n    reverse_proxy web:8000\n}}\n"


@pytest.mark.parametrize("mode", ["internal", "custom", "off"])
def test_only_acme_talks_to_a_ca_so_only_acme_mentions_the_email(mode, tmp_path: Path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("c")
    key.write_text("k")
    result = _render(
        DOMAIN="logs.internal",
        PROXY_TLS=mode,
        CADDY_CERT_DIR=str(tmp_path),
        PROXY_TLS_CERT=str(cert),
        PROXY_TLS_KEY=str(key),
    )
    assert result.returncode == 0
    assert "ACME_EMAIL" not in result.stderr
    assert "email" not in result.stdout


# ── basic auth composes with every mode ──────────────────────────────────────


@pytest.mark.parametrize(("mode", "first_line"), [("acme", "logs.internal {"), ("off", "http://logs.internal {")])
def test_basic_auth_composes_with_the_tls_mode(mode, first_line):
    rendered = _ok(
        DOMAIN="logs.internal",
        PROXY_TLS=mode,
        BASIC_AUTH_USER="ops",
        BASIC_AUTH_HASH="$2a$14$abc",
    )
    assert rendered.splitlines()[0] == first_line
    assert "    basicauth * {\n        ops $2a$14$abc\n    }" in rendered
    # basicauth must precede the upstream, or unauthenticated requests are proxied.
    assert rendered.index("basicauth") < rendered.index("reverse_proxy")


# ── refusals: every one of these is a crash loop if it renders instead ───────


def test_an_unknown_mode_is_refused_rather_than_silently_served():
    result = _render(DOMAIN="logs.internal", PROXY_TLS="internl")
    assert result.returncode == 1
    assert "invalid PROXY_TLS 'internl'" in result.stderr


def test_custom_refuses_half_a_certificate_pair(tmp_path: Path):
    cert = tmp_path / "c.pem"
    cert.write_text("c")
    result = _render(DOMAIN="x", PROXY_TLS="custom", CADDY_CERT_DIR=str(tmp_path), PROXY_TLS_CERT=str(cert))
    assert result.returncode == 1
    assert "PROXY_TLS_CERT and PROXY_TLS_KEY" in result.stderr


def test_custom_refuses_a_path_outside_the_bind_mount(tmp_path: Path):
    key = tmp_path / "k.pem"
    key.write_text("k")
    result = _render(
        DOMAIN="x",
        PROXY_TLS="custom",
        CADDY_CERT_DIR=str(tmp_path),
        PROXY_TLS_CERT="/etc/shadow",
        PROXY_TLS_KEY=str(key),
    )
    assert result.returncode == 1
    assert "must be under" in result.stderr


def test_custom_refuses_traversal_back_out_of_the_bind_mount(tmp_path: Path):
    key = tmp_path / "k.pem"
    key.write_text("k")
    result = _render(
        DOMAIN="x",
        PROXY_TLS="custom",
        CADDY_CERT_DIR=str(tmp_path),
        PROXY_TLS_CERT=f"{tmp_path}/../../etc/shadow",
        PROXY_TLS_KEY=str(key),
    )
    assert result.returncode == 1
    assert "'..' are not allowed" in result.stderr


def test_custom_says_which_file_is_missing_rather_than_crash_looping(tmp_path: Path):
    key = tmp_path / "k.pem"
    key.write_text("k")
    result = _render(
        DOMAIN="x",
        PROXY_TLS="custom",
        CADDY_CERT_DIR=str(tmp_path),
        PROXY_TLS_CERT=f"{tmp_path}/absent.pem",
        PROXY_TLS_KEY=str(key),
    )
    assert result.returncode == 1
    assert "not found" in result.stderr


@pytest.mark.parametrize("domain", ["logs.internal:8443", "http://logs.internal", "a b", "x{y}"])
def test_the_domain_validator_still_refuses_injection_shapes(domain):
    """Every mode goes through it — `off` renders http:// itself rather than accepting it
    in DOMAIN, so the validator never had to loosen."""
    assert _render(DOMAIN=domain, PROXY_TLS="off").returncode == 1


def test_basic_auth_still_refuses_half_a_pair():
    assert _render(DOMAIN="x", BASIC_AUTH_USER="ops").returncode == 1
