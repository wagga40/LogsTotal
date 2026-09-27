"""The reachability matrix, as data.

Tier 1: the module is pure and stdlib-only, so every claim the CLI prints is checkable
without a host.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def plan_mod():
    spec = importlib.util.spec_from_file_location("deploy_network_plan", REPO_ROOT / "scripts" / "deploy_network_plan.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_network_plan"] = module
    spec.loader.exec_module(module)
    return module


def _ports(plan, listener=None):
    return {(r.port, r.proto) for r in plan.rules if listener is None or r.listener.split(" (", 1)[0] == listener}


# ── the relays, which are the point of the whole thing ───────────────────────


def test_every_worker_reaches_the_three_relays_on_the_control_plane(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp", "w1", "w2"])
    assert {(6379, "tcp"), (5432, "tcp"), (3900, "tcp")} <= _ports(plan, "cp")


def test_a_single_host_fleet_needs_no_relay_ports_at_all(plan_mod):
    """Nothing dials them: the only worker is inside the same compose network."""
    plan = plan_mod.build_plan(hosts=["cp"])
    assert not {(6379, "tcp"), (5432, "tcp"), (3900, "tcp")} & _ports(plan)


def test_without_a_tunnel_the_relays_are_public(plan_mod):
    """This is the sentence the tooling could never say: those three ports are on a
    routable interface, protected only by their generated passwords."""
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="none")
    relays = [r for r in plan.rules if r.port in (6379, 5432, 3900)]
    assert relays and all(r.scope == plan_mod.PUBLIC for r in relays)


def test_with_a_tunnel_the_relays_move_onto_it(plan_mod):
    """The most useful line in the plan, because it is what the VPN actually buys."""
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf")
    relays = [r for r in plan.rules if r.port in (6379, 5432, 3900)]
    assert relays and all(r.scope == plan_mod.TUNNEL for r in relays)
    assert "[tunnel]" in plan_mod.render_text(plan)


# ── the tunnel itself ────────────────────────────────────────────────────────


def test_only_the_hub_accepts_the_wireguard_port(plan_mod):
    """Spokes dial out from ephemeral ports and ride conntrack. Measured on a real fleet;
    opening a port on the spokes would be cargo cult."""
    plan = plan_mod.build_plan(hosts=["cp", "w1", "w2"], vpn="wireconf")
    wg = [r for r in plan.rules if r.proto == "udp"]
    assert len(wg) == 1
    assert wg[0].listener.startswith("cp")
    assert wg[0].port == 51820
    assert not _ports(plan, "w1") and not _ports(plan, "w2")


def test_the_wireguard_port_follows_the_configured_one(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf", vpn_port=51999)
    assert (51999, "udp") in _ports(plan)


@pytest.mark.parametrize("vpn", ["none", "tailscale"])
def test_no_wireguard_rule_without_wireconf(plan_mod, vpn):
    """Tailscale is managed by the operator and dials out; it needs nothing inbound."""
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn=vpn)
    assert not [r for r in plan.rules if r.proto == "udp"]


def test_a_one_host_wireconf_fleet_has_no_tunnel_rule(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp"], vpn="wireconf")
    assert not [r for r in plan.rules if r.proto == "udp"]


# ── how users get in ─────────────────────────────────────────────────────────


def test_without_a_proxy_users_reach_the_app_port_directly(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp"])
    assert (8000, "tcp") in _ports(plan)
    assert not {(80, "tcp"), (443, "tcp")} & _ports(plan)


def test_a_proxy_replaces_the_app_port_rather_than_adding_to_it(plan_mod):
    """proxy_enable and the fleet generator both bind WEB_PORT to loopback, so 8000 stops
    being reachable at the moment Caddy starts."""
    plan = plan_mod.build_plan(hosts=["cp"], proxied=True)
    assert {(80, "tcp"), (443, "tcp")} <= _ports(plan)
    assert (8000, "tcp") not in _ports(plan)


def test_only_acme_needs_port_80_open_to_a_certificate_authority(plan_mod):
    """The distinction an air-gapped operator needs: `internal` issues its own certificate,
    so nothing outside has to reach port 80."""
    acme = plan_mod.build_plan(hosts=["cp"], proxied=True, proxy_tls="acme")
    internal = plan_mod.build_plan(hosts=["cp"], proxied=True, proxy_tls="internal")

    acme_80 = next(r for r in acme.rules if r.port == 80)
    internal_80 = next(r for r in internal.rules if r.port == 80)
    assert "Let's Encrypt" in acme_80.sources
    assert "Let's Encrypt" not in internal_80.sources


def test_plain_http_through_the_proxy_is_named_as_such(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp"], proxied=True, proxy_tls="off")
    assert "http (PROXY_TLS=off)" in plan_mod.render_text(plan)


# ── SSH, the one nobody writes down ──────────────────────────────────────────


def test_ssh_is_required_on_every_host_in_every_topology(plan_mod):
    for vpn in ("none", "wireconf"):
        plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn=vpn)
        ssh = [r for r in plan.rules if r.port == 22]
        assert len(ssh) == 1
        assert ssh[0].listener == "every host"
        assert ssh[0].scope == plan_mod.ADMIN


# ── shape and plumbing ───────────────────────────────────────────────────────


def test_a_user_at_host_entry_is_reduced_to_the_host(plan_mod):
    """A DEPLOY_HOSTS entry is an SSH destination; a firewall rule is about a machine."""
    plan = plan_mod.build_plan(hosts=["root@cp.example.com", "deploy@w1.example.com"])
    assert plan.control_plane == "cp.example.com"
    assert plan.workers == ["w1.example.com"]


def test_no_hosts_is_an_error_not_an_empty_plan(plan_mod):
    with pytest.raises(ValueError, match="at least a control plane"):
        plan_mod.build_plan(hosts=[])


def test_ports_for_host_is_what_a_per_host_probe_should_check(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf")
    cp = plan_mod.ports_for_host(plan, "root@cp")
    assert {r.port for r in cp} >= {22, 6379, 5432, 3900, 51820}
    worker = plan_mod.ports_for_host(plan, "w1")
    assert {r.port for r in worker} == {22}, "a worker accepts nothing but SSH"


@pytest.mark.parametrize(
    ("manager", "expected"),
    [
        ("ufw", ["ufw allow 51820/udp"]),
        ("firewalld", ["firewall-cmd --permanent --add-port=51820/udp", "firewall-cmd --reload"]),
    ],
)
def test_the_fix_command_matches_the_firewall_in_use(plan_mod, manager, expected):
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf")
    wg = next(r for r in plan.rules if r.port == 51820)
    assert plan_mod.allow_commands(wg, manager=manager) == expected


def test_no_firewall_command_is_offered_for_a_port_docker_published(plan_mod):
    """Measured on a real fleet: ufw active allowing only 22 and 51820, and http://cp:8000
    answered 200. Docker writes nat and FORWARD rules, never INPUT, so ufw never sees that
    traffic — an `allow` line changes nothing while reading like the fix."""
    plan = plan_mod.build_plan(hosts=["cp", "w1"])
    redis = next(r for r in plan.rules if r.port == 6379)
    assert redis.enforced_by == plan_mod.DOCKER_PUBLISHED
    assert plan_mod.allow_commands(redis) == []


@pytest.mark.parametrize(("port", "enforced"), [(22, "host"), (51820, "host"), (8000, "docker"), (6379, "docker"), (5432, "docker"), (3900, "docker")])
def test_only_ssh_and_wireguard_are_host_services(plan_mod, port, enforced):
    """The two that ufw governs are the two that are not containers. Everything else is a
    published container port, and a host firewall neither opens nor closes it."""
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf")
    rule = next(r for r in plan.rules if r.port == port)
    assert rule.enforced_by == enforced


def test_the_text_explains_why_a_host_firewall_will_not_protect_the_relays(plan_mod):
    """It is also the sharpest argument for the tunnel: without one, the three relays are
    published by Docker and ufw will not protect them. Binding them to a VPN address will."""
    text = plan_mod.render_text(plan_mod.build_plan(hosts=["cp", "w1"]))
    assert "[docker]" in text
    assert "not INPUT" in text.replace("NOT INPUT", "not INPUT")
    assert "The host firewall governs only these:" in text


def test_an_unknown_firewall_manager_raises_rather_than_inventing_a_command(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf")
    wg = next(r for r in plan.rules if r.port == 51820)
    with pytest.raises(ValueError, match="unknown firewall manager"):
        plan_mod.allow_commands(wg, manager="pf")


def test_json_carries_every_rule_for_the_preflight_to_probe(plan_mod):
    plan = plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf", proxied=True)
    payload = json.loads(plan_mod.to_json(plan))
    assert payload["control_plane"] == "cp"
    assert payload["workers"] == ["w1"]
    assert payload["vpn"] == "wireconf"
    assert len(payload["rules"]) == len(plan.rules)
    assert all({"listener", "sources", "proto", "port", "why", "scope"} <= set(r) for r in payload["rules"])


def test_the_text_never_claims_udp_reachability(plan_mod):
    """A UDP probe cannot tell an open port from a black hole — the rule the preflight has
    always followed, restated where an operator reads the port list."""
    text = plan_mod.render_text(plan_mod.build_plan(hosts=["cp", "w1"], vpn="wireconf"))
    assert "black hole" in text
    assert "reachable" not in text.replace("what must be reachable", "")


def test_every_rule_says_why(plan_mod):
    """A port number with no reason is what the operator cannot act on."""
    plan = plan_mod.build_plan(hosts=["cp", "w1", "w2"], vpn="wireconf", proxied=True)
    assert all(r.why.strip() for r in plan.rules)


def test_the_cli_refuses_without_hosts(plan_mod, capsys):
    assert plan_mod.main(["--hosts", ""]) == 1
    assert "--hosts is required" in capsys.readouterr().err
