#!/usr/bin/env python3
"""What the control plane knows about its own fleet.

Without a record, a host's role is only its INDEX in `DEPLOY_HOSTS`, and every other fact
about the deployment lives in the operator's working directory, in files
`scripts/package.sh` deliberately excludes from the archive — so a control plane could not
answer the first question an upgrade has to ask: *which machines am I responsible for?*

This is that answer, written to `<install>/fleet/manifest.json` on the control plane and
nowhere else. Three properties it has to have:

**No secrets, ever.** `deploy-envs/` (0600) keeps those, and it is excluded from snapshots
and from the archive. This file is 0644 on purpose: it should be safe to paste into a bug
report, which is exactly what makes it useful when something is broken.

**Intent and observation are separated and labelled.** `entry`, `role`, `address` and
`options` are configuration — what the operator asked for. `version`, `result`,
`containers` and `last_deploy` are measurements — what was found to be true. Collapsing
them into one shape reads fine right up to the moment they disagree, and disagreeing is
precisely when you need it: "the record names three workers and I can see two" is a
sentence `deploy:status` cannot form without the distinction.

**Written as it goes, never only at the end.** A run that dies in phase 5 is exactly when
the record matters, so the intended half lands before anything is mutated and each host's
result is merged in as that host finishes. `result` is one of ok / unverified / failed /
skipped / not-attempted, which is how the deploy's PASS/FAIL/UNKNOWN vocabulary survives
past the console.

Pure and stdlib-only, the scripts/gen_secrets.py and deploy_network_plan.py constraint: it
is called from bash through `run_py`, on hosts that have no venv, and its whole value is
being testable as data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import Any

SCHEMA = 1

#: What a host's `result` may say. Mirrors lib/verdict.sh's vocabulary: `unverified` is an
#: UNKNOWN that outlived the run, and it exists so a worker whose containers were never
#: confirmed is neither claimed as healthy nor reported as broken.
RESULTS = ("ok", "unverified", "failed", "skipped", "not-attempted")

CONTROL_PLANE = "control-plane"
WORKER = "worker"

#: Configuration keys the manifest carries forward, so a control plane can reproduce the
#: deployment it is part of without the operator's deploy.env. Every one of these is a
#: DECISION — several of them probed once and then impossible to re-derive correctly from
#: the control plane, where the CP's own entry is `local`.
OPTION_KEYS = (
    "vpn",
    "vpn_port",
    "vpn_network",
    "vpn_hub_endpoint",
    "cp_address",
    "cp_bind_address",
    "domain",
    "proxy_tls",
    "basic_auth_user",
    "huey_workers",
    "keep_releases",
    "remote_dir",
)


def _blank() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "written_by": "",
        "written_at": "",
        "install_dir": "",
        "control_plane": "",
        "release": {},
        "hosts": [],
        "options": {},
    }


def load(path: str) -> dict[str, Any]:
    """The manifest at `path`, or a blank one.

    Never raises on a damaged file. This is read by an upgrade that is about to run, and
    refusing to start because the record is unparseable would make a cosmetic file into a
    hard dependency — the fleet is still described by deploy.env and by positionals, both
    of which beat it.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return _blank()
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        return _blank()
    base = _blank()
    base.update({k: v for k, v in data.items() if k in base})
    return base


def save(path: str, manifest: dict[str, Any]) -> None:
    """Write atomically: a temp file in the same directory, then rename.

    The rename is the point. A manifest half-written when a deploy is interrupted is worse
    than none — `load` would fall back to blank and the fleet would appear to be one host.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".manifest.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# The "run it here" sentinel, shared with lib/common.sh::is_local_host. Named rather than
# repeated, because it means two opposite things depending on direction: read OUT of the
# record it is how a control plane addresses itself, written INTO it it is a mistake.
LOCAL_ENTRY = "local"


def host_entries(hosts_csv: str) -> list[str]:
    return [h.strip() for h in hosts_csv.split(",") if h.strip()]


def role_for(index: int) -> str:
    return CONTROL_PLANE if index == 0 else WORKER


def set_intent(
    manifest: dict[str, Any],
    *,
    hosts_csv: str,
    install_dir: str,
    written_by: str,
    written_at: str,
    options: dict[str, str],
    release: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Record what the operator asked for, before anything is mutated.

    Existing per-host MEASUREMENTS are preserved for hosts that are still in the fleet: a
    `DEPLOY_ONLY` run touches one machine, and the versions the others were last seen
    running are still the best answer anyone has for them. Hosts dropped from the list are
    dropped from the record — the manifest describes this fleet, not its history.

    Two things an incoming write must NOT be allowed to destroy:

    `local` is a runtime view, never a stored name. It is what hosts_line() hands a control
    plane so it stops trying to ssh to itself, and a run there passes that list straight back
    here. Storing it makes the record UNPORTABLE in the worst way: `./logstotal fleet:pull` onto a
    workstation would render `DEPLOY_HOSTS=local,…`, and that workstation would then deploy
    the control plane to ITSELF.

    An option absent from this run means "not specified now", never "unset it". An upgrade
    runs with DEPLOY_KEEPENV and carries almost none of the deploy-time knobs, so overwriting
    wholesale would erase vpn, vpn_port, domain and proxy_tls from a record that has them —
    the architecture the control plane is supposed to be able to follow, erased by the
    routine operation performed on it most often.
    """
    # Merged FIRST, because the control-plane address below is read out of it. Deriving that
    # from the incoming options alone would leave `hosts[0].address` empty on a run that does
    # not carry DEPLOY_CP_ADDRESS while `options.cp_address` in the same file holds it — the
    # record disagreeing with itself about one fact.
    merged_options = dict(manifest.get("options", {}))
    merged_options.update({k: v for k, v in options.items() if k in OPTION_KEYS and v != ""})

    entries = host_entries(hosts_csv)
    recorded_cp = manifest.get("control_plane", "")
    if recorded_cp and recorded_cp != LOCAL_ENTRY:
        entries = [recorded_cp if e == LOCAL_ENTRY else e for e in entries]
    previous = {h.get("entry"): h for h in manifest.get("hosts", [])}
    hosts = []
    for index, entry in enumerate(entries):
        before = previous.get(entry, {})
        hosts.append(
            {
                "entry": entry,
                "role": role_for(index),
                "address": merged_options.get("cp_address", "") if index == 0 else before.get("address", ""),
                "version": before.get("version", ""),
                "containers": before.get("containers", 0),
                "last_deploy": before.get("last_deploy", ""),
                "result": before.get("result", "not-attempted"),
            }
        )
    manifest["hosts"] = hosts
    manifest["install_dir"] = install_dir
    manifest["control_plane"] = entries[0] if entries else ""
    manifest["written_by"] = written_by
    manifest["written_at"] = written_at
    manifest["options"] = merged_options
    if release:
        merged_release = dict(manifest.get("release", {}))
        merged_release.update({k: v for k, v in release.items() if v != ""})
        manifest["release"] = merged_release
    return manifest


def set_result(
    manifest: dict[str, Any],
    *,
    entry: str,
    result: str,
    version: str = "",
    containers: int | None = None,
    when: str = "",
    address: str = "",
) -> dict[str, Any]:
    """Merge one host's observed outcome. Unknown hosts are ignored rather than invented —
    a result for a machine the fleet does not contain is a bug in the caller, and silently
    growing the record would hide it."""
    if result not in RESULTS:
        raise ValueError(f"result must be one of {RESULTS}, got {result!r}")
    for host in manifest.get("hosts", []):
        if host.get("entry") != entry:
            continue
        host["result"] = result
        if version:
            host["version"] = version
        if containers is not None:
            host["containers"] = containers
        if when:
            host["last_deploy"] = when
        if address:
            host["address"] = address
    return manifest


def hosts_line(manifest: dict[str, Any], *, as_control_plane: bool = False) -> str:
    """The host list, optionally with the control plane's own entry replaced by `local`.

    A fleet deployed from a workstation records its control plane by NAME, because a name is
    what the operator typed. Read that back ON the control plane and the name means "ssh to
    yourself" — which needs a key that machine has no reason to hold, so `./logstotal upgrade` on the
    control plane would fail its preflight on SSH to the one host already answering.

    `local` is the sentinel for "this machine, run it here". The substitution is EXACT rather
    than a guess: a manifest is only ever written to the control plane, so a process reading
    one out of its own install directory IS the control plane the record names.

    Matching hostnames or addresses is the obvious alternative and does not work: a fleet entry
    like `logstotal-cp.example.com` can belong to a host that calls itself `logstotal-cp` and
    resolve to an address the machine does not hold (NAT, a VM bridge).
    """
    entries = [h.get("entry", "") for h in manifest.get("hosts", [])]
    cp = manifest.get("control_plane", "")
    if as_control_plane and cp:
        entries = ["local" if e == cp else e for e in entries]
    return ",".join(entries)


def make_portable(manifest: dict[str, Any], fallback: str = "") -> tuple[dict[str, Any], str]:
    """Replace a stored `local` with an address another machine can reach.

    `local` means "this machine", so it is only ever correct where it was written. A record
    made by deploying FROM the control plane stores it, and a workstation that adopts that
    record and reads `DEPLOY_HOSTS=local,w1` will deploy the control plane to ITSELF — the
    same failure set_intent guards on the write path, arriving by the read path instead.

    Two substitutions, cheapest first: the address the record already holds for the control
    plane, then `fallback` — the entry the operator named to fetch it, which is reachable by
    construction, because it is the host we just copied the file off.

    Returns the manifest and the substitution used, or an empty string if none was needed.
    Never raises: a record it cannot make portable comes back unchanged, and the caller
    refuses rather than guessing.
    """
    entries = [h.get("entry", "") for h in manifest.get("hosts", [])]
    if LOCAL_ENTRY not in entries:
        return manifest, ""

    hosts = manifest.get("hosts", [])
    address = next((h.get("address", "") for h in hosts if h.get("entry") == LOCAL_ENTRY), "")
    replacement = address or fallback
    if not replacement:
        return manifest, ""

    for host in hosts:
        if host.get("entry") == LOCAL_ENTRY:
            host["entry"] = replacement
    if manifest.get("control_plane") == LOCAL_ENTRY:
        manifest["control_plane"] = replacement
    return manifest, replacement


def to_deploy_env(manifest: dict[str, Any]) -> str:
    """Render the manifest back as a deploy.env.

    This is what makes the record useful from somewhere else: a workstation that has never
    seen this fleet can pull the manifest off the control plane and drive every deploy task
    against it. Secrets are not here to be rendered, which is the point — the generated
    per-host env files stay on the machine that made them.
    """
    # `local` is portable nowhere: this file is FOR another machine. A record written by a
    # deploy run on the control plane itself has it, and the recorded address is the only
    # thing that machine can be reached by from somewhere else.
    entries = []
    unreachable = False
    for host in manifest.get("hosts", []):
        entry = host.get("entry", "")
        if entry == LOCAL_ENTRY:
            # The host's own address, else the recorded cp_address — the same fact, and the
            # only one of the two an older record may carry.
            entry = host.get("address", "") or manifest.get("options", {}).get("cp_address", "") or entry
            unreachable = entry == LOCAL_ENTRY
        entries.append(entry)
    options = manifest.get("options", {})
    lines = [
        "# Written by `./logstotal fleet:pull` from a control plane's fleet/manifest.json.",
        "# It carries the fleet's SHAPE and its settings — never its secrets.",
        "",
        f"DEPLOY_HOSTS={','.join(entries)}",
    ]
    if unreachable:
        lines.insert(
            2,
            "# WARNING: the control plane is recorded as `local` with no address — it was\n"
            "# deployed from itself, so nothing here names it. Replace `local` below with an\n"
            "# address this machine can reach, or every task will target THIS machine.",
        )
    mapping = {
        "remote_dir": "DEPLOY_REMOTE_DIR",
        "vpn": "DEPLOY_VPN",
        "vpn_port": "DEPLOY_VPN_PORT",
        "vpn_network": "DEPLOY_VPN_NETWORK",
        "vpn_hub_endpoint": "DEPLOY_VPN_HUB_ENDPOINT",
        "cp_address": "DEPLOY_CP_ADDRESS",
        "cp_bind_address": "DEPLOY_CP_BIND_ADDRESS",
        "domain": "DEPLOY_DOMAIN",
        "proxy_tls": "DEPLOY_PROXY_TLS",
        "basic_auth_user": "DEPLOY_BASIC_AUTH_USER",
        "huey_workers": "DEPLOY_HUEY_WORKERS",
        "keep_releases": "DEPLOY_KEEP_RELEASES",
    }
    for key, env_key in mapping.items():
        value = options.get(key, "")
        if value != "":
            lines.append(f"{env_key}={value}")
    release_server = manifest.get("release", {}).get("server", "")
    if release_server:
        lines.append(f"RELEASE_REPO_URL={release_server}")
    return "\n".join(lines) + "\n"


def summary(manifest: dict[str, Any]) -> str:
    """A human-readable rendering for `./logstotal fleet`."""
    if not manifest.get("hosts"):
        return "No fleet record. Run a deploy from this machine to write one."
    out = [
        f"install dir : {manifest.get('install_dir', '?')}",
        f"written by  : {manifest.get('written_by', '?')} at {manifest.get('written_at', '?')}",
    ]
    # WHERE releases come from, not which one is deployed. That question is answered by the
    # VERSION column below, per host, from measurement. A release version here would come
    # from the deploying machine's VERSION file, written BEFORE the overlay replaces it, and
    # a header that contradicts the table under it is worse than no header.
    release = manifest.get("release", {})
    if release.get("server"):
        out.append(f"releases from : {release['server']}")
    out.append("")
    # Width from the data, not a fixed guess: an entry like `root@logstotal-worker-1.example.com`
    # would otherwise push every following column out of line.
    width = max(len("HOST"), *(len(h.get("entry", "?")) for h in manifest["hosts"]))
    out.append(f"{'HOST':<{width}}  {'ROLE':<14} {'VERSION':<10} {'RESULT':<14} CONTAINERS")
    for host in manifest["hosts"]:
        version = host.get("version", "") or "?"
        out.append(f"{host.get('entry', '?'):<{width}}  {host.get('role', '?'):<14} {version:<10} {host.get('result', '?'):<14} {host.get('containers', 0)}")
    options = manifest.get("options", {})
    if options:
        out.append("")
        out.append("options     : " + "  ".join(f"{k}={v}" for k, v in sorted(options.items())))
    return "\n".join(out)


def _parse_options(pairs: list[str]) -> dict[str, str]:
    options = {}
    for pair in pairs:
        key, _, value = pair.partition("=")
        options[key.strip()] = value.strip()
    return options


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, help="path to fleet/manifest.json")
    sub = parser.add_subparsers(dest="command", required=True)

    p_intent = sub.add_parser("intent", help="record what the operator asked for")
    p_intent.add_argument("--hosts", required=True)
    p_intent.add_argument("--install-dir", required=True)
    p_intent.add_argument("--written-by", default="")
    p_intent.add_argument("--written-at", default="")
    p_intent.add_argument("--option", action="append", default=[], metavar="KEY=VALUE")
    p_intent.add_argument("--release", action="append", default=[], metavar="KEY=VALUE")

    p_result = sub.add_parser("result", help="merge one host's observed outcome")
    p_result.add_argument("--entry", required=True)
    p_result.add_argument("--result", required=True, choices=RESULTS)
    p_result.add_argument("--version", default="")
    p_result.add_argument("--containers", type=int, default=None)
    p_result.add_argument("--when", default="")
    p_result.add_argument("--address", default="")

    sub.add_parser("show", help="print the record for a human")
    p_hosts = sub.add_parser("hosts", help="print DEPLOY_HOSTS, or nothing")
    p_hosts.add_argument(
        "--as-control-plane",
        action="store_true",
        help="emit `local` for the control plane's own entry (see hosts_line)",
    )
    sub.add_parser("deploy-env", help="render the record as a deploy.env")
    sub.add_parser("options", help="print every recorded option as key=value lines")

    p_get = sub.add_parser("get", help="print one option value, or nothing")
    p_get.add_argument("key")

    # `get` reads options{} only; `release` is how bash reads manifest["release"], and so how
    # a control plane — which has no deploy.env — answers "where do my releases come from".
    p_release = sub.add_parser("release", help="print one release field, or nothing")
    p_release.add_argument("key")

    p_portable = sub.add_parser("portable", help="rewrite a fetched record so another machine can use it")
    p_portable.add_argument("--fallback", default="", help="address to use when the record holds none")

    args = parser.parse_args(argv)
    manifest = load(args.file)

    if args.command == "intent":
        set_intent(
            manifest,
            hosts_csv=args.hosts,
            install_dir=args.install_dir,
            written_by=args.written_by,
            written_at=args.written_at,
            options=_parse_options(args.option),
            release=_parse_options(args.release),
        )
        save(args.file, manifest)
    elif args.command == "result":
        set_result(
            manifest,
            entry=args.entry,
            result=args.result,
            version=args.version,
            containers=args.containers,
            when=args.when,
            address=args.address,
        )
        save(args.file, manifest)
    elif args.command == "show":
        print(summary(manifest))
    elif args.command == "hosts":
        line = hosts_line(manifest, as_control_plane=args.as_control_plane)
        if line:
            print(line)
    elif args.command == "options":
        for key, value in sorted(manifest.get("options", {}).items()):
            print(f"{key}={value}")
    elif args.command == "deploy-env":
        sys.stdout.write(to_deploy_env(manifest))
    elif args.command == "get":
        print(manifest.get("options", {}).get(args.key, ""))
    elif args.command == "release":
        print(manifest.get("release", {}).get(args.key, ""))
    elif args.command == "portable":
        manifest, used = make_portable(manifest, args.fallback)
        if not used and any(h.get("entry") == LOCAL_ENTRY for h in manifest.get("hosts", [])):
            print("no address recorded for the control plane", file=sys.stderr)
            return 1
        save(args.file, manifest)
        print(used)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
