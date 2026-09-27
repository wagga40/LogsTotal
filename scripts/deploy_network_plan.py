#!/usr/bin/env python3
"""What must be able to reach what, for a LogsTotal fleet — and how to allow it.

The facts, in one place:

  * every worker opens TCP 6379 / 5432 / 3900 on the control plane — Redis, PostgreSQL and
    Garage. `deploy_fleet_env.py` binds them there and points every worker at them.
  * users reach the control plane on TCP 8000, or 80 + 443 when Caddy is in front
  * with `DEPLOY_VPN=wireconf` the hub accepts UDP 51820 from its spokes, and everything
    above moves onto the tunnel — which is the single most useful line here, because it is
    what the VPN actually buys
  * the machine running the deploy needs SSH to every host, always

Pure and stdlib-only, the scripts/gen_secrets.py constraint: it is called from bash through
`run_py`, on hosts with no venv, and its whole value is being testable as data.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

# The relay ports the control plane publishes for remote workers. Kept beside the strings
# that produce them in scripts/deploy_fleet_env.py::control_plane_keys — REDIS_EXPOSE,
# POSTGRES_EXPOSE and GARAGE_EXPOSE are `{bind}:{port}`, and these are those ports.
REDIS_PORT = 6379
POSTGRES_PORT = 5432
GARAGE_PORT = 3900
APP_PORT = 8000
HTTP_PORT = 80
HTTPS_PORT = 443
SSH_PORT = 22
DEFAULT_WG_PORT = 51820

# Reachability that a firewall on the LISTENER has to allow. `scope` says what kind of
# network it crosses, which is what the VPN changes.
PUBLIC = "public"  # crosses whatever network the hosts share
TUNNEL = "tunnel"  # crosses the WireGuard mesh only
ADMIN = "admin"  # from wherever the operator runs the deploy

# WHO enforces a rule, which decides whether a host firewall can do anything about it.
#
# This is not a detail. Docker publishes a port by writing nat and FORWARD rules, not
# INPUT ones, so ufw never sees the traffic: on a control plane with `ufw` active and only
# 22/tcp allowed, http://host:8000 still answers 200. Telling an operator to
# `ufw allow 8000/tcp` is therefore advice that does nothing — and implying the service is
# blocked when it is reachable is worse than saying nothing at all.
#
# It also sharpens the argument for the tunnel: a host firewall will NOT protect the three
# relays, because Docker published them. Binding them to a VPN address will.
HOST_FIREWALL = "host"  # a host service — ufw / firewalld governs it
DOCKER_PUBLISHED = "docker"  # published by Docker; it bypasses the host firewall


@dataclass(frozen=True)
class Rule:
    """One 'X must accept Y on port P' fact, with why and how."""

    listener: str
    sources: tuple[str, ...]
    proto: str
    port: int
    why: str
    scope: str
    enforced_by: str = DOCKER_PUBLISHED

    @property
    def source_label(self) -> str:
        return ", ".join(self.sources)


@dataclass
class Plan:
    hosts: list[str]
    control_plane: str
    workers: list[str] = field(default_factory=list)
    vpn: str = "none"
    vpn_port: int = DEFAULT_WG_PORT
    proxied: bool = False
    proxy_tls: str = "acme"
    rules: list[Rule] = field(default_factory=list)


def _strip_user(entry: str) -> str:
    """`user@host` → `host`. A DEPLOY_HOSTS entry is an SSH destination, not a hostname."""
    return entry.split("@", 1)[-1] if "@" in entry else entry


def parse_hosts(raw: str) -> list[str]:
    return [h.strip() for h in raw.split(",") if h.strip()]


def build_plan(
    *,
    hosts: list[str],
    vpn: str = "none",
    vpn_port: int = DEFAULT_WG_PORT,
    proxied: bool = False,
    proxy_tls: str = "acme",
) -> Plan:
    """The whole reachability matrix, as data.

    The first host is the control plane; the rest are workers — the same rule
    scripts/deploy-multiserver.sh deploys by, so there is one definition of "which host is
    which" and not two.
    """
    if not hosts:
        raise ValueError("no hosts: the plan needs at least a control plane")

    names = [_strip_user(h) for h in hosts]
    cp, workers = names[0], names[1:]
    tunnelled = vpn == "wireconf"
    scope = TUNNEL if tunnelled else PUBLIC
    plan = Plan(
        hosts=names,
        control_plane=cp,
        workers=workers,
        vpn=vpn,
        vpn_port=vpn_port,
        proxied=proxied,
        proxy_tls=proxy_tls,
    )

    # 1. The operator's own access. True on every host, in every topology, and the one that
    #    is never mentioned because it is already working by the time anyone looks.
    plan.rules.append(
        Rule(
            listener="every host",
            sources=("the machine running the deploy",),
            proto="tcp",
            port=SSH_PORT,
            why="the deploy, the preflight and every fleet command are SSH",
            scope=ADMIN,
            enforced_by=HOST_FIREWALL,
        )
    )

    # 2. Users reaching the app. Caddy replaces the app's own port rather than adding to it:
    #    proxy_enable and the fleet generator both set WEB_PORT to loopback.
    if proxied:
        plan.rules.append(
            Rule(
                listener=cp,
                sources=("users",),
                proto="tcp",
                port=HTTPS_PORT,
                why="the site itself" if proxy_tls != "off" else "unused while PROXY_TLS=off, but Caddy still binds it",
                scope=PUBLIC,
            )
        )
        plan.rules.append(
            Rule(
                listener=cp,
                sources=("users", "Let's Encrypt") if proxy_tls == "acme" else ("users",),
                proto="tcp",
                port=HTTP_PORT,
                why=("the site itself" if proxy_tls == "off" else "the ACME HTTP-01 challenge, and the redirect to HTTPS" if proxy_tls == "acme" else "the redirect to HTTPS"),
                scope=PUBLIC,
            )
        )
    else:
        plan.rules.append(
            Rule(
                listener=cp,
                sources=("users",),
                proto="tcp",
                port=APP_PORT,
                why="the app, served directly — there is no proxy in front",
                scope=PUBLIC,
            )
        )

    # 3. The three relays. Every worker dials all of them; without a tunnel they are on a
    #    routable interface protected only by their generated passwords, which is the whole
    #    argument for DEPLOY_VPN=wireconf.
    if workers:
        source_label = "every worker" if len(workers) > 1 else workers[0]
        for port, service in (
            (REDIS_PORT, "Redis — the job queue"),
            (POSTGRES_PORT, "PostgreSQL — every job and finding"),
            (GARAGE_PORT, "Garage S3 — uploaded logs, over plain HTTP"),
        ):
            plan.rules.append(
                Rule(
                    listener=cp,
                    sources=(source_label,),
                    proto="tcp",
                    port=port,
                    why=service,
                    scope=scope,
                )
            )

    # 4. The tunnel itself. Only the hub needs an inbound rule: spokes dial out from
    #    ephemeral ports and their return traffic rides conntrack. Measured on a real
    #    fleet — hub on 51820 with a rule, both spokes on ephemeral ports with none.
    if tunnelled and workers:
        plan.rules.append(
            Rule(
                listener=f"{cp} (hub)",
                sources=("every worker",),
                proto="udp",
                port=vpn_port,
                why="the WireGuard handshake — spokes need no inbound rule",
                scope=PUBLIC,
                enforced_by=HOST_FIREWALL,
            )
        )

    return plan


def allow_commands(rule: Rule, *, manager: str = "ufw") -> list[str]:
    """Copy-pasteable rules for the listener's firewall, or [] when there are none.

    Empty for a Docker-published port, deliberately: ufw does not see that traffic, so an
    `allow` line would change nothing while reading like the fix.

    Otherwise unrestricted by source address: the plan knows a host's *name*, and a
    firewall wants an address it may not have yet. Naming the port and letting the operator
    scope it beats printing a rule with a placeholder in it.
    """
    if rule.enforced_by != HOST_FIREWALL:
        return []
    if manager == "ufw":
        return [f"ufw allow {rule.port}/{rule.proto}"]
    if manager == "firewalld":
        return [
            f"firewall-cmd --permanent --add-port={rule.port}/{rule.proto}",
            "firewall-cmd --reload",
        ]
    raise ValueError(f"unknown firewall manager: {manager}")


def ports_for_host(plan: Plan, host: str) -> list[Rule]:
    """Every rule whose listener is `host` — what a per-host firewall probe should check."""
    name = _strip_user(host)
    out = []
    for rule in plan.rules:
        listener = rule.listener.split(" (", 1)[0]
        if listener in ("every host", name):
            out.append(rule)
    return out


def render_host_lines(plan: Plan, host: str) -> str:
    """One `proto port scope enforced_by why` line per rule this host must accept.

    A shell-readable shape on purpose: deploy-preflight.sh probes a firewall host by host
    and needs the port list without parsing JSON in bash. `scope` is what tells it which
    rules ride the tunnel and therefore need nothing on the public interface.
    """
    lines = []
    for rule in ports_for_host(plan, host):
        lines.append(f"{rule.proto} {rule.port} {rule.scope} {rule.enforced_by} {rule.why}")
    return "\n".join(lines)


def render_text(plan: Plan) -> str:
    lines: list[str] = []
    lines.append("Network plan — what must be reachable, and from where")
    lines.append("")

    role = f"control plane: {plan.control_plane}"
    if plan.workers:
        role += f"    workers: {', '.join(plan.workers)}"
    lines.append(f"  {role}")
    if plan.vpn == "wireconf":
        lines.append(f"  private network: WireGuard (hub {plan.control_plane}), so the relays are NOT on a routable interface")
    elif plan.workers:
        lines.append("  private network: none — the relays below are on a routable interface,")
        lines.append("                   protected only by their generated passwords")
    if plan.proxied:
        scheme = "http" if plan.proxy_tls == "off" else "https"
        lines.append(f"  users reach it over {scheme} (PROXY_TLS={plan.proxy_tls})")
    lines.append("")

    width = max((len(r.listener) for r in plan.rules), default=10)
    lines.append(f"  {'ACCEPTS ON':<{width}}  {'PORT':>9}  FROM")
    for rule in plan.rules:
        port = f"{rule.port}/{rule.proto}"
        tags = []
        if rule.scope == TUNNEL:
            tags.append("[tunnel]")
        if rule.enforced_by == DOCKER_PUBLISHED:
            tags.append("[docker]")
        tag = ("  " + " ".join(tags)) if tags else ""
        lines.append(f"  {rule.listener:<{width}}  {port:>9}  {rule.source_label}{tag}")
        lines.append(f"  {'':<{width}}  {'':>9}  └─ {rule.why}")

    if any(r.scope == TUNNEL for r in plan.rules):
        lines.append("")
        lines.append("  [tunnel] rides the WireGuard mesh — no rule needed on the public interface.")

    if any(r.enforced_by == DOCKER_PUBLISHED for r in plan.rules):
        lines.append("")
        lines.append("  [docker] published by Docker, which writes nat and FORWARD rules — NOT INPUT.")
        lines.append("           ufw and firewalld never see this traffic, so an `allow` line for one of")
        lines.append("           these changes nothing, and a host firewall will not close it either.")
        lines.append("           To restrict them: bind them to an address that is not routable (a VPN")
        lines.append("           does exactly that), or write DOCKER-USER rules.")

    host_rules = [r for r in plan.rules if r.enforced_by == HOST_FIREWALL]
    if host_rules:
        lines.append("")
        lines.append("  The host firewall governs only these:")
        for rule in host_rules:
            lines.append(f"    {rule.port}/{rule.proto:<4} {rule.why}")
        lines.append("    ufw allow <port>/<proto>        # or scope it: ufw allow from <peer-ip> to any port <port> proto <proto>")
        lines.append("    firewall-cmd --permanent --add-port=<port>/<proto> && firewall-cmd --reload")

    lines.append("")
    lines.append("  UDP reachability is never claimed here, or anywhere: a probe cannot tell an")
    lines.append("  open port from a black hole. A completed WireGuard handshake is the evidence.")
    return "\n".join(lines)


def to_json(plan: Plan) -> str:
    return json.dumps(
        {
            "control_plane": plan.control_plane,
            "workers": plan.workers,
            "vpn": plan.vpn,
            "proxied": plan.proxied,
            "proxy_tls": plan.proxy_tls,
            "rules": [
                {
                    "listener": r.listener,
                    "sources": list(r.sources),
                    "proto": r.proto,
                    "port": r.port,
                    "why": r.why,
                    "scope": r.scope,
                    "enforced_by": r.enforced_by,
                }
                for r in plan.rules
            ],
        },
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print what must be reachable for a LogsTotal fleet")
    parser.add_argument("--hosts", default="", help="comma-separated DEPLOY_HOSTS; the first is the control plane")
    parser.add_argument("--vpn", default="none", help="wireconf | tailscale | none")
    parser.add_argument("--vpn-port", type=int, default=DEFAULT_WG_PORT)
    parser.add_argument("--domain", default="", help="setting it means Caddy is in front")
    parser.add_argument("--proxy-tls", default="acme", help="acme | internal | custom | off")
    parser.add_argument("--format", default="text", choices=["text", "json", "host"])
    parser.add_argument("--for-host", default="", help="with --format host: whose accept-list to print")
    args = parser.parse_args(argv)

    hosts = parse_hosts(args.hosts)
    if not hosts:
        print("ERROR: --hosts is required (comma-separated; the first is the control plane).", file=sys.stderr)
        return 1

    plan = build_plan(
        hosts=hosts,
        vpn=args.vpn,
        vpn_port=args.vpn_port,
        proxied=bool(args.domain),
        proxy_tls=args.proxy_tls,
    )
    if args.format == "json":
        print(to_json(plan))
    elif args.format == "host":
        if not args.for_host:
            print("ERROR: --format host needs --for-host.", file=sys.stderr)
            return 1
        lines = render_host_lines(plan, args.for_host)
        if lines:
            print(lines)
    else:
        print(render_text(plan))
    return 0


if __name__ == "__main__":
    sys.exit(main())
