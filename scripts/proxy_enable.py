#!/usr/bin/env python3
"""
Enable the Caddy HTTPS reverse-proxy profile in one command.

Moving a plain-HTTP LogsTotal deployment to HTTPS by hand means editing six
.env keys scattered across different sections of the file — miss one and you get
silent login failures (Secure cookie over HTTP) or a publicly-exposed :8000. This
script makes those six edits atomically and idempotently:

    COMPOSE_PROFILES  += proxy   (appended; any other profiles are preserved)
    DOMAIN             = <value>
    ACME_EMAIL         = <value>
    WEB_PORT           = 127.0.0.1:8000:8000   (Caddy becomes the only public port)
    COOKIE_INSECURE    = false
    ENABLE_HSTS        = true

Optionally it also sets BASIC_AUTH_USER / BASIC_AUTH_HASH. The hash is written
single-quoted because Compose interpolates `$`, and a bcrypt hash is mostly `$`.

Usage:
    DOMAIN=logs.example.com ACME_EMAIL=you@example.com ./logstotal proxy:enable
    python3 scripts/proxy_enable.py --domain logs.example.com --acme-email you@example.com

Stdlib-only on purpose — same constraint as scripts/gen_secrets.py.

Edit semantics mirror scripts/gen_secrets.py's proven "find the active line"
approach (see its `_current_value`/`write_env`), extended so a brand-new setting
lands next to its documented section instead of always at EOF:
  * an existing *uncommented* `KEY=...` line is replaced in place;
  * otherwise, if only commented `# KEY=...` occurrence(s) exist, the active line
    is inserted right after the LAST one (.env.example ships these commented, in
    their own section — this keeps the new value there instead of far away);
  * otherwise (key never mentioned at all) it is appended at EOF under a
    `# --- set by ./logstotal proxy:enable ---` marker.
A run that changes nothing rewrites nothing (checked before writing), and writes
that do happen go through a temp file + os.replace so a crash mid-write can't
corrupt .env.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import tempfile
import threading
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# The one colour decision — see scripts/cli_color.py. Sibling import, the
# scripts/deploy_fleet_env.py idiom: these helpers run through `run_py` on hosts with no
# venv, so nothing here may reach the application.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_color import colors

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MARKER = "# --- set by ./logstotal proxy:enable ---"

# Keys touched, in the fixed order they are applied and reported.
_KEY_ORDER = ("COMPOSE_PROFILES", "DOMAIN", "PROXY_TLS", "ACME_EMAIL", "WEB_PORT", "COOKIE_INSECURE", "ENABLE_HSTS")

# How each TLS mode wants the two dependent keys. These are not cosmetic: get either wrong
# and login fails *silently* — a Secure cookie over plain HTTP is dropped by the browser,
# so the password looks wrong. That is the whole reason this script writes them at all,
# and the reason the four modes cannot share one set of values.
#
# `internal` is the one that surprises people: it is real TLS, so cookies stay Secure, but
# HSTS stays OFF. A browser that has not installed Caddy's local root gets a certificate
# warning it can click through — unless HSTS told it not to, which turns a warning into a
# site that cannot be opened at all.
_TLS_MODES = {
    "acme": {"COOKIE_INSECURE": "false", "ENABLE_HSTS": "true"},
    "internal": {"COOKIE_INSECURE": "false", "ENABLE_HSTS": "false"},
    "custom": {"COOKIE_INSECURE": "false", "ENABLE_HSTS": "true"},
    "off": {"COOKIE_INSECURE": "true", "ENABLE_HSTS": "false"},
}


@dataclass
class KeyResult:
    """Outcome of applying one .env key edit — value is the NEW (non-secret) value."""

    key: str
    status: str  # "unchanged" | "set"
    value: str


def _active_re(key: str) -> re.Pattern[str]:
    """Matches an active (uncommented) `KEY=...` line, whole-line, in .env text."""
    return re.compile(rf"^{re.escape(key)}=(.*)$", re.MULTILINE)


def _commented_re(key: str) -> re.Pattern[str]:
    """Matches a commented `# KEY=...` line (any indentation before/after the #)."""
    return re.compile(rf"^[ \t]*#[ \t]*{re.escape(key)}=.*$", re.MULTILINE)


# Return shape shared by both apply helpers below:
#   (new_text, result_if_resolved_now, (key, value)_if_deferred_to_eof_marker)
_ApplyResult = tuple[str, "KeyResult | None", "tuple[str, str] | None"]


def _apply_simple_key(text: str, key: str, desired: str) -> _ApplyResult:
    active = _active_re(key).search(text)
    if active:
        current = active.group(1)
        if current == desired:
            return text, KeyResult(key, "unchanged", desired), None
        new_text = text[: active.start()] + f"{key}={desired}" + text[active.end() :]
        return new_text, KeyResult(key, "set", desired), None

    commented = list(_commented_re(key).finditer(text))
    if commented:
        last = commented[-1]
        new_text = text[: last.end()] + "\n" + f"{key}={desired}" + text[last.end() :]
        return new_text, KeyResult(key, "set", desired), None

    return text, None, (key, desired)


def _apply_compose_profiles(text: str, profile: str = "proxy") -> _ApplyResult:
    key = "COMPOSE_PROFILES"
    active = _active_re(key).search(text)
    if active:
        current = active.group(1)
        profiles = [p.strip() for p in current.split(",") if p.strip()]
        if profile in profiles:
            return text, KeyResult(key, "unchanged", current), None
        profiles.append(profile)
        new_value = ",".join(profiles)
        new_text = text[: active.start()] + f"{key}={new_value}" + text[active.end() :]
        return new_text, KeyResult(key, "set", new_value), None

    commented = list(_commented_re(key).finditer(text))
    if commented:
        last = commented[-1]
        new_text = text[: last.end()] + "\n" + f"{key}={profile}" + text[last.end() :]
        return new_text, KeyResult(key, "set", profile), None

    return text, None, (key, profile)


def apply_proxy_settings(text: str, domain: str, acme_email: str, tls: str = "acme") -> tuple[str, list[KeyResult]]:
    """Pure: apply the seven .env edits, returning (new_text, results in fixed order).

    Idempotent: feeding a previous run's output back in reports every key
    "unchanged" and returns the text unmodified.

    `tls` defaults to "acme": certificates from a public CA.
    """
    if tls not in _TLS_MODES:
        raise ValueError(f"unknown TLS mode {tls!r}; expected one of: {', '.join(sorted(_TLS_MODES))}")
    mode = _TLS_MODES[tls]
    results: list[KeyResult] = []
    pending: list[tuple[str, str]] = []

    def _step(step_result: _ApplyResult) -> str:
        new_text, result, pend = step_result
        if result is not None:
            results.append(result)
        if pend is not None:
            pending.append(pend)
        return new_text

    text = _step(_apply_compose_profiles(text))
    text = _step(_apply_simple_key(text, "DOMAIN", domain))
    text = _step(_apply_simple_key(text, "PROXY_TLS", tls))
    text = _step(_apply_simple_key(text, "ACME_EMAIL", acme_email))
    text = _step(_apply_simple_key(text, "WEB_PORT", "127.0.0.1:8000:8000"))
    text = _step(_apply_simple_key(text, "COOKIE_INSECURE", mode["COOKIE_INSECURE"]))
    text = _step(_apply_simple_key(text, "ENABLE_HSTS", mode["ENABLE_HSTS"]))

    if pending:
        if text and not text.endswith("\n"):
            text += "\n"
        text += f"\n{MARKER}\n"
        for key, value in pending:
            text += f"{key}={value}\n"
            results.append(KeyResult(key, "set", value))

    # Report in the fixed, documented order regardless of resolution order above.
    results_by_key = {r.key: r for r in results}
    ordered = [results_by_key[key] for key in _KEY_ORDER]
    return text, ordered


# Basic auth is a separate pure entry point, not two more entries in _KEY_ORDER.
# Those six ARE "turn HTTPS on" and are reported as one set; these two are optional
# and only meaningful when Caddy is already in front, so a run without them touches
# neither.
_BASIC_AUTH_KEYS = ("BASIC_AUTH_USER", "BASIC_AUTH_HASH")


def apply_basic_auth(text: str, user: str, bcrypt_hash: str) -> tuple[str, list[KeyResult]]:
    """Pure: put Caddy basic-auth credentials into .env text. Idempotent.

    The hash is written SINGLE-QUOTED. A bcrypt hash is mostly `$` sigils, Compose
    interpolates `${...}` and `$X` in env values, and docker-caddy-entrypoint.sh
    validates for whitespace and braces but not for `$` — so an unquoted hash reaches
    Caddy as a different string and every login is rejected, with nothing in any log
    saying why. The documented manual recipe says "with SINGLE QUOTES" for the same
    reason; this is that instruction made mechanical.

    Returns (text, results) unchanged when either value is empty: half a credential
    pair makes docker-caddy-entrypoint.sh refuse to start at all.
    """
    if not user or not bcrypt_hash:
        return text, []
    quoted = bcrypt_hash if bcrypt_hash.startswith("'") and bcrypt_hash.endswith("'") else f"'{bcrypt_hash}'"
    results: list[KeyResult] = []
    pending: list[tuple[str, str]] = []
    for key, value in (("BASIC_AUTH_USER", user), ("BASIC_AUTH_HASH", quoted)):
        new_text, result, pend = _apply_simple_key(text, key, value)
        text = new_text
        if result is not None:
            results.append(result)
        if pend is not None:
            pending.append(pend)
    if pending:
        if text and not text.endswith("\n"):
            text += "\n"
        if MARKER not in text:
            text += f"\n{MARKER}\n"
        for key, value in pending:
            text += f"{key}={value}\n"
            results.append(KeyResult(key, "set", value))
    return text, [next(r for r in results if r.key == key) for key in _BASIC_AUTH_KEYS]


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


# ── Best-effort DNS check (warn-only, never fails the run) ───────────────────


def _default_resolve(domain: str, timeout: float = 3.0) -> list[str]:
    """Resolve `domain` to a sorted list of IP addresses, bounded by `timeout`.

    socket.getaddrinfo() does not honor socket timeouts (it isn't a socket
    operation), so a stuck resolver is bounded here with a daemon thread instead
    — the CLI can still return promptly even if resolution itself never comes back.
    """
    outcome: dict[str, object] = {}

    def _resolve() -> None:
        try:
            outcome["infos"] = socket.getaddrinfo(domain, None)
        except Exception as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=_resolve, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"resolving {domain} took longer than {timeout}s")
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    infos = outcome.get("infos", [])
    return sorted({info[4][0] for info in infos})  # type: ignore[union-attr]


def _default_fetch_public_ip(timeout: float = 3.0) -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as resp:
        return resp.read().decode("utf-8").strip()


def check_dns(domain: str, resolve=None, fetch_public_ip=None) -> str:
    """Best-effort DNS sanity check — never raises, never fails the run.

    Resolves `domain` and compares against this host's public IP. `resolve` and
    `fetch_public_ip` are injectable so tests never touch the network.
    """
    resolve = resolve or _default_resolve
    fetch_public_ip = fetch_public_ip or _default_fetch_public_ip
    try:
        addrs = resolve(domain)
        public_ip = fetch_public_ip()
    except Exception as exc:
        return f"INFO: DNS check skipped ({exc})"

    if not addrs:
        return f"INFO: DNS check skipped ({domain} did not resolve to any address)"
    if public_ip in addrs:
        return f"OK: {domain} resolves to this host's public IP ({public_ip})."
    return (
        f"WARN: {domain} resolves to {', '.join(addrs)}, not this host's public IP ({public_ip}). This can be fine behind a load balancer or CDN — otherwise check the DNS record."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enable the Caddy HTTPS reverse-proxy profile in .env")
    parser.add_argument("--domain", default=None, help="public domain name (or set the DOMAIN env var)")
    parser.add_argument("--acme-email", default=None, help="Let's Encrypt contact email (or set the ACME_EMAIL env var); PROXY_TLS=acme only")
    parser.add_argument(
        "--tls",
        default=None,
        choices=sorted(_TLS_MODES),
        help="how Caddy terminates TLS: acme (default, public domain), internal (Caddy's own CA — air-gapped), custom (your certificate), off (plain HTTP)",
    )
    parser.add_argument("--env", default=str(PROJECT_ROOT / ".env"), help="path to .env (default: ./.env)")
    parser.add_argument("--basic-auth-user", default=None, help="optional Caddy basic-auth username (or BASIC_AUTH_USER)")
    parser.add_argument("--basic-auth-hash", default=None, help="its bcrypt hash, never the plaintext (or BASIC_AUTH_HASH)")
    args = parser.parse_args(argv)

    domain = args.domain or os.environ.get("DOMAIN")
    tls = args.tls or os.environ.get("PROXY_TLS") or "acme"
    if tls not in _TLS_MODES:
        e = colors(stream=sys.stderr)
        print(f"{e['bold']}{e['red']}ERROR:{e['off']} PROXY_TLS={tls} is not one of: {', '.join(sorted(_TLS_MODES))}.", file=sys.stderr)
        return 1
    acme_email = args.acme_email or os.environ.get("ACME_EMAIL")
    if not domain:
        print(
            "ERROR: DOMAIN is required, e.g.:\n  DOMAIN=logs.example.com ACME_EMAIL=you@example.com ./logstotal proxy:enable",
            file=sys.stderr,
        )
        return 1
    # Only `acme` talks to a certificate authority, so only `acme` needs a contact address.
    # Demanding one for the other three would make an internal deployment invent an email
    # to get past this check.
    if tls == "acme" and not acme_email:
        print(
            "ERROR: DOMAIN and ACME_EMAIL are both required, e.g.:\n  DOMAIN=logs.example.com ACME_EMAIL=you@example.com ./logstotal proxy:enable\n"
            "  For an internal or air-gapped network, no email is needed:\n"
            "    DOMAIN=logs.internal ./logstotal proxy:enable -- --tls internal",
            file=sys.stderr,
        )
        return 1
    acme_email = acme_email or ""

    env_path = Path(args.env)
    if not env_path.exists():
        print(
            f"ERROR: {env_path} not found. Create it first: cp .env.example .env (or run: ./logstotal quickstart)",
            file=sys.stderr,
        )
        return 1

    text = env_path.read_text(encoding="utf-8")
    new_text, results = apply_proxy_settings(text, domain=domain, acme_email=acme_email, tls=tls)

    basic_user = args.basic_auth_user or os.environ.get("BASIC_AUTH_USER") or ""
    basic_hash = args.basic_auth_hash or os.environ.get("BASIC_AUTH_HASH") or ""
    if basic_user and not basic_hash:
        print(
            "ERROR: a basic-auth username needs its bcrypt hash. Generate one with:\n  docker run --rm -i caddy:2-alpine caddy hash-password",
            file=sys.stderr,
        )
        return 1
    new_text, basic_results = apply_basic_auth(new_text, basic_user, basic_hash)
    results = [*results, *basic_results]

    changed = any(r.status == "set" for r in results)
    if changed:
        _atomic_write(env_path, new_text)

    c = colors()
    print(f"{c['bold']}Proxy/HTTPS settings in {env_path}:{c['off']}")
    for r in results:
        label = "set" if r.status == "set" else "already correct"
        print(f"  {c['bold']}{r.key}={r.value}{c['off']}  {c['dim']}({label}){c['off']}")
    if not changed:
        print(f"  {c['green']}OK{c['off']}   nothing to change — all keys were already correct.")

    # Resolving the name against this host's public IP only means anything when a public CA
    # is about to validate it. On an internal network it is a guaranteed false alarm.
    if tls == "acme":
        print()
        print(check_dns(domain))

    print()
    print(f"{c['bold']}Next steps:{c['off']}")
    if tls == "acme":
        print("  1. Make sure ports 80 and 443 are reachable from the internet (Let's Encrypt validates over both).")
        print("  2. ./logstotal docker:up")
        print("     Caddy fetches a TLS certificate automatically on first start.")
    elif tls == "internal":
        print("  1. ./logstotal docker:up")
        print("     Caddy issues the certificate itself — no DNS, no port 80, no internet.")
        print("  2. Trust its root on the machines that will use LogsTotal:")
        print("       docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./logstotal-root.crt")
        print("     Until they do, every browser shows a certificate warning.")
    elif tls == "custom":
        print("  1. Put the certificate and key in ./certs (gitignored, never packaged).")
        print("  2. Point PROXY_TLS_CERT / PROXY_TLS_KEY at them by their in-container path,")
        print("     e.g. PROXY_TLS_CERT=/etc/caddy/certs/fullchain.pem")
        print("  3. ./logstotal docker:up")
    else:
        print("  1. ./logstotal docker:up")
        print("     Caddy serves plain HTTP on port 80 — nothing here terminates TLS.")
        print("  2. Make sure whatever sits in front of it does, and that it sets")
        print("     X-Forwarded-For (see TRUST_PROXY_HEADERS in docs/configuration.md).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
