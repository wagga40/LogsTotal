#!/usr/bin/env python3
"""What this fleet is configured to be, and where its settings disagree with each other.

Two things an operator needs before a deploy.

**What the fleet is.** A per-host check list and a version verdict name no setting, and
`deploy_network_plan.py` reads `DEPLOY_DOMAIN` only as a boolean, to move the app from port
8000 to 80+443 — so without this the one question a plan is asked most, *which site is
this about*, has no answer in its output. The settings block answers it, with a provenance
column: a value you cannot explain is a value you cannot fix, and "the domain is wrong"
and "the domain is right but `deploy.env` is being ignored" look identical without it.

**Where settings disagree.** The nine `GeneratorError`s in `deploy_fleet_env.py` run at
step 5 of 8 of `./logstotal deploy` — never under `deploy:plan` — so without this a plan could
report `3 fresh` and `Recommended: ./logstotal deploy` for a configuration `./logstotal deploy` refuses
two minutes later. Several other combinations are caught nowhere else and fail *after* a
green deploy: `DEPLOY_PROXY_TLS=custom` has no
`DEPLOY_*` knob for the certificate paths, so Caddy exits 1 at start
(`docker-caddy-entrypoint.sh`) on a fleet every check just passed.

**Findings are never fatal, deliberately.** They appear in `deploy:plan`, which always
exits 0, and in `./logstotal deploy`'s banner, which must not grow new ways to stop. Several of
these are legitimate on purpose — an MSP running `logs.client.com` from
`admin@their-own-domain` is not a mistake — and a warning that blocks would make the
honest answer "stop warning". Anything that genuinely must refuse already does, later,
where the refusal can be specific.

Pure and stdlib-only, the `deploy_network_plan.py` / `gen_secrets.py` constraint: it is
called from bash through `run_py`, on hosts with no venv, and its whole value is being
testable as data.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Sibling import, the scripts/deploy_fleet_env.py idiom: `python3 scripts/x.py` already
# puts scripts/ first on sys.path, but `run_py -c` and the tests import this by file, so
# make it explicit rather than depending on how it was invoked.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_color import colors as _colors

# ── Levels ───────────────────────────────────────────────────────────────────
#
# Two, not three. `warn` is "this will not do what you asked"; `note` is "this is unusual
# and you may have meant something else". There is deliberately no error level: see the
# module docstring.
WARN = "warn"
NOTE = "note"

#: The placeholder for the hash, shipped by both `deploy.env.example` and the template
#: `task deploy:init` writes. It starts with `$2a$`, so deploy-fleet.sh's bcrypt prefix
#: check and docker-caddy-entrypoint.sh both accept it — an operator who uncomments the
#: line gets a fleet that deploys green and rejects every login.
HASH_PLACEHOLDER = "$2a$14$..."

#: Emails the templates ship. Cheaper than importing gen_secrets just for its twin.
PLACEHOLDER_EMAILS = frozenset({"admin@example.com", "you@example.com", "ops@example.com"})

#: Suffixes no public CA will issue for.
PRIVATE_TLDS = (".local", ".internal", ".localdomain", ".home", ".lan", ".test", ".invalid", ".example")

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_CHARS = re.compile(r"^[A-Za-z0-9.-]+$")

_TLS_MODES = ("acme", "internal", "custom", "off")
_VPN_MODES = ("wireconf", "tailscale", "none")


@dataclass(frozen=True)
class Setting:
    """One row of the settings block."""

    label: str
    value: str
    source: str = ""
    #: Rendered after the value, parenthesised — "(derived)", "(2 workers)".
    note: str = ""


@dataclass(frozen=True)
class Finding:
    level: str
    #: The setting names this is about, so an operator knows what to open.
    keys: tuple[str, ...]
    message: str
    fix: str = ""


@dataclass(frozen=True)
class HostVerdict:
    """One host's row in the plan, as data rather than as a printed line."""

    host: str
    role: str
    verdict: str
    version: str = ""
    running: int = 0
    detail: str = ""


@dataclass
class Review:
    settings: list[Setting] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    control_plane: str = ""
    workers: list[str] = field(default_factory=list)

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.level == WARN)

    @property
    def notes(self) -> int:
        return sum(1 for f in self.findings if f.level == NOTE)


def _strip_user(entry: str) -> str:
    return entry.split("@", 1)[1] if "@" in entry else entry


def parse_hosts(raw: str) -> list[str]:
    return [h.strip() for h in raw.split(",") if h.strip()]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def email_domain(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def registrable(domain: str) -> str:
    """The last two labels — `logs.example.com` and `mail.example.com` both give
    `example.com`.

    Deliberately naive: this feeds a NOTE, and the alternative is shipping a public suffix
    list to tell `example.co.uk` from `example.com`. Over-reporting a hosted subdomain is
    an acceptable cost for a line that says "check this"; under-reporting is not, and a
    real PSL would still be wrong for an internal TLD.
    """
    labels = [label for label in domain.lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def _int_or_none(raw: str) -> int | None:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


# ── The settings block ───────────────────────────────────────────────────────


def build_settings(cfg: dict[str, str], sources: dict[str, str], hosts: list[str]) -> list[Setting]:
    def src(*keys: str) -> str:
        """The provenance of the first key that actually carries a value.

        Reporting the first key unconditionally would print `TLS  acme   deploy.env` for a
        fleet whose deploy.env says nothing about TLS.
        """
        for key in keys:
            if cfg.get(key):
                return sources.get(key, "a default")
        return "a default"

    def get(key: str, default: str = "") -> str:
        return (cfg.get(key) or default).strip()

    domain = get("DEPLOY_DOMAIN")
    tls = get("DEPLOY_PROXY_TLS", "acme")
    vpn = get("DEPLOY_VPN", "none")
    rows: list[Setting] = []

    if hosts:
        workers = len(hosts) - 1
        rows.append(
            Setting(
                "Fleet",
                hosts[0],
                sources.get("DEPLOY_HOSTS", "a default"),
                f"control plane, + {workers} worker(s)" if workers else "control plane, no workers",
            )
        )

    # Setting DEPLOY_DOMAIN is what turns the proxy on, so its absence is a statement
    # about the deployment rather than a missing row.
    if domain:
        rows.append(Setting("Domain", domain, src("DEPLOY_DOMAIN")))
        acme = get("DEPLOY_ACME_EMAIL")
        detail = ""
        if tls == "acme":
            # deploy_fleet_env.py invents admin@<domain> when none is given. Showing the
            # invented address is the point: it is what the CA will be told.
            detail = acme or f"admin@{domain}"
            detail += "" if acme else " (derived)"
        rows.append(Setting("TLS", tls, src("DEPLOY_PROXY_TLS"), detail))
    else:
        rows.append(Setting("Domain", "none", src("DEPLOY_DOMAIN"), f"app on http://{hosts[0]}:8000" if hosts else ""))

    user = get("DEPLOY_BASIC_AUTH_USER")
    rows.append(Setting("Basic auth", user or "off", src("DEPLOY_BASIC_AUTH_USER")))

    vpn_detail = ""
    if vpn == "wireconf":
        vpn_detail = f"{get('DEPLOY_VPN_NETWORK', '10.200.0.0/24')}, hub udp/{get('DEPLOY_VPN_PORT', '51820')}"
    rows.append(Setting("Private network", vpn, src("DEPLOY_VPN"), vpn_detail))

    cp_address = get("DEPLOY_CP_ADDRESS")
    if cp_address:
        rows.append(Setting("Workers reach CP at", cp_address, src("DEPLOY_CP_ADDRESS")))

    rows.append(Setting("Admin account", get("DEPLOY_ADMIN_EMAIL", "admin@example.com"), src("DEPLOY_ADMIN_EMAIL")))
    rows.append(Setting("Install dir", get("DEPLOY_REMOTE_DIR", "/opt/logstotal"), src("DEPLOY_REMOTE_DIR")))
    rows.append(Setting("Analysis workers", get("DEPLOY_HUEY_WORKERS", "4"), src("DEPLOY_HUEY_WORKERS"), "per host"))
    if get("DEPLOY_ONLY"):
        rows.append(Setting("Acting on", get("DEPLOY_ONLY"), src("DEPLOY_ONLY"), "other hosts untouched"))
    return rows


# ── The findings ─────────────────────────────────────────────────────────────


def _proxy_findings(g, hosts: list[str]) -> list[Finding]:
    out: list[Finding] = []
    domain, tls, acme = g("DEPLOY_DOMAIN"), g("DEPLOY_PROXY_TLS"), g("DEPLOY_ACME_EMAIL")

    if tls and tls not in _TLS_MODES:
        out.append(
            Finding(
                WARN,
                ("DEPLOY_PROXY_TLS",),
                f"DEPLOY_PROXY_TLS={tls} is not a mode. Caddy refuses to start on it.",
                f"Use one of: {', '.join(_TLS_MODES)}.",
            )
        )
    # Both are inert without a domain: deploy_fleet_env.py builds the proxy block from
    # `bool(domain)`, so these are configured and then dropped on the floor.
    if not domain:
        for key, val in (("DEPLOY_PROXY_TLS", tls), ("DEPLOY_ACME_EMAIL", acme)):
            if val:
                out.append(
                    Finding(
                        WARN,
                        (key, "DEPLOY_DOMAIN"),
                        f"{key} is set but DEPLOY_DOMAIN is not, so no proxy is configured and it is ignored.",
                        "Set DEPLOY_DOMAIN to put Caddy in front, or drop this setting.",
                    )
                )
    if domain and not _DOMAIN_CHARS.match(domain):
        out.append(
            Finding(
                WARN,
                ("DEPLOY_DOMAIN",),
                f"DEPLOY_DOMAIN={domain} has characters Caddy rejects at start-up (letters, digits, '.' and '-' only).",
                "",
            )
        )
    if tls == "custom":
        # There is no DEPLOY_* knob for PROXY_TLS_CERT/_KEY: proxy_enable.apply_proxy_settings
        # writes seven keys and neither is among them. The deploy is green and Caddy
        # crash-loops.
        out.append(
            Finding(
                WARN,
                ("DEPLOY_PROXY_TLS",),
                "DEPLOY_PROXY_TLS=custom needs PROXY_TLS_CERT and PROXY_TLS_KEY in the control plane's .env, and no DEPLOY_* setting writes them.",
                "Add both to the control plane's .env by hand and put the files in <remote dir>/certs, or Caddy will exit at start-up.",
            )
        )
    if tls == "acme" and domain:
        reason = ""
        if _is_ip(domain):
            reason = "an IP address"
        elif "." not in domain:
            reason = "a single-label name"
        elif domain.lower().endswith(PRIVATE_TLDS):
            reason = "a private suffix"
        if reason:
            out.append(
                Finding(
                    WARN,
                    ("DEPLOY_PROXY_TLS", "DEPLOY_DOMAIN"),
                    f"DEPLOY_PROXY_TLS=acme, but DEPLOY_DOMAIN={domain} is {reason} — no public CA will issue for it.",
                    "Use DEPLOY_PROXY_TLS=internal for a name only your network resolves.",
                )
            )
    if acme and tls and tls != "acme":
        out.append(
            Finding(
                NOTE,
                ("DEPLOY_ACME_EMAIL", "DEPLOY_PROXY_TLS"),
                f"DEPLOY_ACME_EMAIL is set but DEPLOY_PROXY_TLS={tls}, so no certificate is requested and the address is unused.",
                "",
            )
        )
    return out


def _identity_findings(g) -> list[Finding]:
    """The domain-vs-address family — the case this module was asked for."""
    out: list[Finding] = []
    domain = g("DEPLOY_DOMAIN")
    tls = g("DEPLOY_PROXY_TLS")
    admin = g("DEPLOY_ADMIN_EMAIL")
    acme = g("DEPLOY_ACME_EMAIL")

    for key, address in (("DEPLOY_ADMIN_EMAIL", admin), ("DEPLOY_ACME_EMAIL", acme)):
        if address and not _EMAIL.match(address):
            out.append(Finding(WARN, (key,), f"{key}={address} is not an email address.", ""))
            continue
        if address in PLACEHOLDER_EMAILS:
            out.append(
                Finding(
                    NOTE,
                    (key,),
                    f"{key} is still the template's {address}.",
                    "Set a real address — it is where this deployment's mail goes.",
                )
            )

    # The headline check. A NOTE, never a WARN: hosting logs.client.com from
    # admin@your-msp.com is ordinary, so this can only ever say "look at this", and the
    # honest response to a warning you are meant to ignore is to stop printing it.
    if domain and _DOMAIN_CHARS.match(domain):
        site = registrable(domain)
        for key, address in (("DEPLOY_ADMIN_EMAIL", admin), ("DEPLOY_ACME_EMAIL", acme)):
            if not address or not _EMAIL.match(address) or address in PLACEHOLDER_EMAILS:
                continue
            # An unset ACME address is derived as admin@<domain>, so it can never disagree.
            if key == "DEPLOY_ACME_EMAIL" and tls and tls != "acme":
                continue
            at = email_domain(address)
            if at and registrable(at) != site:
                out.append(
                    Finding(
                        NOTE,
                        (key, "DEPLOY_DOMAIN"),
                        f"{key} is at {at}, but this fleet serves {domain}.",
                        "Fine if that is the operator's own address; check it is not a leftover from another deployment.",
                    )
                )
    return out


def _basic_auth_findings(g) -> list[Finding]:
    out: list[Finding] = []
    user, password, bhash = g("DEPLOY_BASIC_AUTH_USER"), g("DEPLOY_BASIC_AUTH_PASSWORD"), g("DEPLOY_BASIC_AUTH_HASH")
    tls = g("DEPLOY_PROXY_TLS")

    if bhash == HASH_PLACEHOLDER or (bhash and bhash.endswith("...")):
        # `$2a$14$...` passes deploy-fleet.sh's bcrypt prefix check and the entrypoint's,
        # so it deploys clean and rejects every login.
        out.append(
            Finding(
                WARN,
                ("DEPLOY_BASIC_AUTH_HASH",),
                "DEPLOY_BASIC_AUTH_HASH is still the template placeholder — it looks like bcrypt, so nothing rejects it, and no password will ever match it.",
                "Generate one: docker run --rm -i caddy:2-alpine caddy hash-password",
            )
        )
    if password and bhash:
        out.append(
            Finding(
                NOTE,
                ("DEPLOY_BASIC_AUTH_PASSWORD", "DEPLOY_BASIC_AUTH_HASH"),
                "Both DEPLOY_BASIC_AUTH_PASSWORD and DEPLOY_BASIC_AUTH_HASH are set; the hash wins and the password is ignored.",
                "Drop one, so the credential in force is the one you can see.",
            )
        )
    if password and not user:
        # deploy-fleet.sh hashes on the control plane at step 5 — an SSH round trip and a
        # `docker run` — before deploy_fleet_env.py refuses for want of a username.
        out.append(
            Finding(
                WARN,
                ("DEPLOY_BASIC_AUTH_PASSWORD", "DEPLOY_BASIC_AUTH_USER"),
                "DEPLOY_BASIC_AUTH_PASSWORD is set but DEPLOY_BASIC_AUTH_USER is not; the deploy will refuse after hashing it on the control plane.",
                "Set DEPLOY_BASIC_AUTH_USER, or drop the password.",
            )
        )
    if user and (password or bhash) and tls == "off":
        out.append(
            Finding(
                WARN,
                ("DEPLOY_BASIC_AUTH_USER", "DEPLOY_PROXY_TLS"),
                "Basic auth with DEPLOY_PROXY_TLS=off sends the credentials in clear text on every request.",
                "Use acme or internal, or terminate TLS in front of Caddy.",
            )
        )
    return out


def _network_findings(g, hosts: list[str]) -> list[Finding]:
    out: list[Finding] = []
    vpn = g("DEPLOY_VPN")
    cp_address = g("DEPLOY_CP_ADDRESS")
    network = g("DEPLOY_VPN_NETWORK")

    if vpn and vpn not in _VPN_MODES:
        # vpn_mode passes an unknown value through verbatim and deploy-bootstrap.sh tests
        # `= "wireconf"`, so WireGuard is silently skipped until step 4 refuses.
        out.append(
            Finding(
                WARN,
                ("DEPLOY_VPN",),
                f"DEPLOY_VPN={vpn} is not a mode, so no tunnel is built and the relays stay on a routable interface until the deploy stops at the VPN step.",
                f"Use one of: {', '.join(_VPN_MODES)}.",
            )
        )
    if cp_address and vpn == "none":
        out.append(
            Finding(
                WARN,
                ("DEPLOY_CP_ADDRESS", "DEPLOY_VPN"),
                f"DEPLOY_CP_ADDRESS={cp_address} is set with DEPLOY_VPN=none — every worker will be pointed at it for Redis, PostgreSQL and S3 with no tunnel to carry it.",
                "Drop it if it is left over from a mesh, or set DEPLOY_VPN=wireconf.",
            )
        )
    if cp_address and vpn == "wireconf" and network:
        # An explicit --cp-address overrides the VPN address map unconditionally, so one
        # stale value takes every worker off a tunnel that is still built and reported up.
        try:
            net = ipaddress.ip_network(network, strict=False)
            addr = ipaddress.ip_address(cp_address)
        except ValueError:
            pass
        else:
            if addr not in net:
                out.append(
                    Finding(
                        WARN,
                        ("DEPLOY_CP_ADDRESS", "DEPLOY_VPN_NETWORK"),
                        f"DEPLOY_CP_ADDRESS={cp_address} is outside DEPLOY_VPN_NETWORK={network}, so workers will not reach the control plane over the tunnel that is being built for them.",
                        f"Use the hub's mesh address ({next(net.hosts(), addr)}), or unset it and let ./logstotal deploy:vpn supply it.",
                    )
                )
    only = g("DEPLOY_ONLY")
    if only and hosts:
        known = set(hosts) | {_strip_user(h) for h in hosts}
        unknown = [t for t in parse_hosts(only) if t not in known and _strip_user(t) not in known]
        if unknown:
            # deploy-multiserver.sh dies on this at step 7 of 8 — after bootstrap, the VPN
            # and the env push have all run against the full fleet.
            out.append(
                Finding(
                    WARN,
                    ("DEPLOY_ONLY", "DEPLOY_HOSTS"),
                    f"DEPLOY_ONLY names {', '.join(unknown)}, which is not in DEPLOY_HOSTS; the deploy stops on it at the last phase.",
                    "Spell it exactly as it appears in DEPLOY_HOSTS.",
                )
            )
    return out


def _numeric_findings(g) -> list[Finding]:
    """Values interpolated raw into remote shell or a compose file."""
    out: list[Finding] = []
    checks = (
        ("DEPLOY_HUEY_WORKERS", 1, 128, "analysis workers per host"),
        ("DEPLOY_KEEP_RELEASES", 1, 100, "rollback snapshots kept per host"),
        ("DEPLOY_VPN_PORT", 1, 65535, "the hub's WireGuard port"),
        ("DEPLOY_HEALTH_ATTEMPTS", 1, 10000, "control-plane health polls"),
        ("DEPLOY_HEALTH_DELAY", 1, 3600, "seconds between health polls"),
    )
    for key, low, high, what in checks:
        raw = g(key)
        if not raw:
            continue
        num = _int_or_none(raw)
        if num is None:
            out.append(Finding(WARN, (key,), f"{key}={raw} is not a number ({what}).", ""))
        elif not (low <= num <= high):
            extra = ""
            if key == "DEPLOY_KEEP_RELEASES" and num == 0:
                # The prune runs after the snapshot, so 0 deletes the rollback point the
                # upgrade just took.
                extra = " 0 deletes the snapshot the deploy just took, leaving nothing to roll back to."
            out.append(Finding(WARN, (key,), f"{key}={raw} is outside {low}-{high} ({what}).{extra}", ""))
    return out


def _file_findings(g) -> list[Finding]:
    out: list[Finding] = []
    domain, plain = g("DEPLOY_DOMAIN"), g("DOMAIN")
    if domain and plain and domain != plain:
        # task deploy:init writes both; deploy-smoke.sh reads DOMAIN first, so a stale one
        # silently retargets every probe.
        out.append(
            Finding(
                WARN,
                ("DOMAIN", "DEPLOY_DOMAIN"),
                f"DOMAIN={plain} and DEPLOY_DOMAIN={domain} disagree. ./logstotal deploy:init writes both, and ./logstotal deploy:smoke reads DOMAIN first — so it will test {plain}.",
                f"Set both to {domain}.",
            )
        )
    return out


def build_review(cfg: dict[str, str], sources: dict[str, str] | None = None, hosts: list[str] | None = None) -> Review:
    sources = sources or {}
    hosts = hosts if hosts is not None else parse_hosts(cfg.get("DEPLOY_HOSTS", ""))

    def g(key: str) -> str:
        return (cfg.get(key) or "").strip()

    findings: list[Finding] = []
    findings += _proxy_findings(g, hosts)
    findings += _identity_findings(g)
    findings += _basic_auth_findings(g)
    findings += _network_findings(g, hosts)
    findings += _numeric_findings(g)
    findings += _file_findings(g)
    # Warnings first: they are the ones that change an outcome.
    findings.sort(key=lambda f: 0 if f.level == WARN else 1)

    return Review(
        settings=build_settings(cfg, sources, hosts),
        findings=findings,
        control_plane=hosts[0] if hosts else "",
        workers=hosts[1:],
    )


# ── Rendering ────────────────────────────────────────────────────────────────

# The palette lives in scripts/cli_color.py, shared with doctor.py and the other helpers,
# so `task deploy:plan` and `task doctor` answer "is colour wanted" the same way.


def render_text(review: Review, color: str = "auto") -> str:
    c = _colors(color)
    lines: list[str] = []
    # The title belongs to the block, not to the render: --findings-only is folded into
    # the plan's own check output, where a second heading reads as a second section.
    if review.settings:
        # No verb in the heading, deliberately. tests/test_deploy_fleet.py asserts the
        # bare substring "apply" is absent from a run that declined the VPN, as its proxy
        # for `wireconf apply` never having run — so a heading that reads naturally here
        # would fail a test about something else entirely, three files away.
        lines += [f"{c['bold']}Fleet configuration{c['off']}", ""]

    width = max((len(s.label) for s in review.settings), default=10)
    value_width = max((len(s.value) for s in review.settings), default=10)
    for s in review.settings:
        shown = f"{c['bold']}{s.value}{c['off']}"
        # Padded on the plain length: the escapes are zero-width on screen and would
        # otherwise push the provenance column right by exactly their byte count.
        shown += " " * max(0, value_width - len(s.value))
        note = f"  {s.note}" if s.note else ""
        source = f"  {c['dim']}from {s.source}{c['off']}" if s.source else ""
        lines.append(f"  {s.label:<{width}}  {shown}{note}{source}".rstrip())

    if review.findings:
        if review.settings:
            lines.append("")
        for f in review.findings:
            tag = "WARN" if f.level == WARN else "NOTE"
            tint = c["yellow"] if f.level == WARN else c["cyan"]
            lines.append(f"  {tint}{tag}{c['off']}  {f.message}")
            if f.fix:
                lines.append(f"        {f.fix}")
        counts = []
        if review.warnings:
            counts.append(f"{review.warnings} warning(s)")
        if review.notes:
            counts.append(f"{review.notes} note(s)")
        # Said explicitly, every time there is anything to say: these do not gate a
        # deploy, and a reader who has to infer that will either ignore all of them or
        # stop on all of them.
        lines.append(f"  {', '.join(counts)} — none of them stops a deploy.")
    return "\n".join(lines)


def to_json(review: Review, plan: dict | None = None) -> str:
    """The whole run as one document.

    Serialised here rather than in the shell that collects it because a verdict carries a
    free-text reason and a host name is operator input: hand-rolled JSON in bash turns one
    stray quote into a parse error, and does it silently.
    """
    payload: dict = {
        "control_plane": review.control_plane,
        "workers": review.workers,
        "settings": [{"label": s.label, "value": s.value, "source": s.source, "note": s.note} for s in review.settings],
        "findings": [{"level": f.level, "keys": list(f.keys), "message": f.message, "fix": f.fix} for f in review.findings],
        "counts": {"warnings": review.warnings, "notes": review.notes},
    }
    if plan is not None:
        payload["plan"] = plan
    return json.dumps(payload, indent=2)


def parse_host_verdict(raw: str) -> HostVerdict:
    """`host<TAB>role<TAB>verdict<TAB>version<TAB>running<TAB>detail`, as the shell emits it.

    Tab-separated rather than `key=value`: every field but the first two is free text a
    human wrote into deploy.env or a remote host replied with, and a tab is the one
    character none of them can contain.
    """
    parts = (raw.split("\t") + [""] * 6)[:6]
    running = _int_or_none(parts[4])
    return HostVerdict(
        host=parts[0],
        role=parts[1],
        verdict=parts[2],
        version=parts[3],
        running=running if running is not None else 0,
        detail=parts[5],
    )


#: Every setting the review reads, and the flag that carries it. The shell shim builds its
#: argument list from this same list of names, so a key cannot be added here and forgotten
#: there.
REVIEWED_KEYS = (
    "DEPLOY_HOSTS",
    "DEPLOY_DOMAIN",
    "DOMAIN",
    "DEPLOY_PROXY_TLS",
    "DEPLOY_ACME_EMAIL",
    "DEPLOY_BASIC_AUTH_USER",
    "DEPLOY_BASIC_AUTH_PASSWORD",
    "DEPLOY_BASIC_AUTH_HASH",
    "DEPLOY_ADMIN_EMAIL",
    "DEPLOY_VPN",
    "DEPLOY_VPN_NETWORK",
    "DEPLOY_VPN_PORT",
    "DEPLOY_CP_ADDRESS",
    "DEPLOY_REMOTE_DIR",
    "DEPLOY_HUEY_WORKERS",
    "DEPLOY_KEEP_RELEASES",
    "DEPLOY_HEALTH_ATTEMPTS",
    "DEPLOY_HEALTH_DELAY",
    "DEPLOY_ONLY",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show a LogsTotal fleet's settings and where they disagree")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="a setting; repeatable. Values are passed rather than read from the environment so a test needs no env manipulation.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="KEY=WHERE",
        help="provenance for a setting, from deploy_env_source",
    )
    parser.add_argument("--format", default="text", choices=["text", "json"])
    # The plan's own results, passed in rather than recomputed: they come from probes only
    # the shell made, and a second opinion formed here could disagree with the printed one.
    parser.add_argument("--plan-host", action="append", default=[], metavar="TSV", help="one host verdict, tab-separated")
    parser.add_argument("--plan-count", action="append", default=[], metavar="NAME=N")
    parser.add_argument("--plan-version", default="")
    parser.add_argument("--plan-version-source", default="")
    parser.add_argument("--plan-dry-run", default="")
    parser.add_argument("--color", default=os.environ.get("LT_COLOR", "auto"), choices=["auto", "always", "never"])
    parser.add_argument("--settings-only", action="store_true", help="print the block, skip the findings")
    parser.add_argument("--findings-only", action="store_true", help="print the findings, skip the block")
    args = parser.parse_args(argv)

    def pairs(raw: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for item in raw:
            key, _, val = item.partition("=")
            if key:
                out[key] = val
        return out

    review = build_review(pairs(args.set), pairs(args.source))
    if args.format == "json":
        plan = None
        if args.plan_host or args.plan_count or args.plan_version:
            counts = {k: (_int_or_none(v) or 0) for k, v in pairs(args.plan_count).items()}
            plan = {
                "compared_against": args.plan_version,
                "compared_against_source": args.plan_version_source,
                "dry_run": args.plan_dry_run == "true",
                "counts": counts,
                "hosts": [vars(parse_host_verdict(h)) for h in args.plan_host],
            }
        print(to_json(review, plan))
        return 0
    if args.settings_only:
        review.findings = []
    if args.findings_only:
        review.settings = []
        if not review.findings:
            return 0
    print(render_text(review, color=args.color))
    return 0


if __name__ == "__main__":
    sys.exit(main())
