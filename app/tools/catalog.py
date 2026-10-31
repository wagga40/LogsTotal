"""Detection-tool capabilities and release metadata. Standard library only.

The updater imports this before the application environment exists. Keep adapter
imports lazy in registry.py and tool-specific execution/parsing in the adapters.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReleaseAsset:
    target: str
    archive: str
    installed: str
    executable: str


@dataclass(frozen=True)
class RuntimeProfile:
    name: str
    rules_path: str | tuple[str, ...]
    options: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    adapter: str
    supported_types: frozenset[str]
    execution_modes: frozenset[str]
    output_suffix: str
    supports_threads: bool
    repo: str
    rule_repo: str
    assets: tuple[ReleaseAsset, ...] = ()
    version_args: tuple[str, ...] = ()
    # For a pre-1.0 engine a minor bump can change its CLI/output contract.
    minor_is_breaking: bool = False
    required_files: tuple[str, ...] = ()
    profiles: tuple[RuntimeProfile, ...] = ()
    docker_image: str | None = None


TOOLS = {
    "zircolite": ToolSpec(
        "zircolite",
        "app.tools.zircolite:ZircoliteAdapter",
        frozenset({"evtx", "json_evtx", "json_winlogbeat", "xml_evtx", "auditd", "sysmon_linux", "journald"}),
        frozenset({"local", "docker"}),
        "_zircolite.json",
        False,
        "wagga40/Zircolite",
        "wagga40/Zircolite",
        profiles=(
            RuntimeProfile("windows", "tools/zircolite/rules/rules_windows_merged.json"),
            RuntimeProfile("linux", "tools/zircolite/rules/rules_linux.json"),
            RuntimeProfile("journald", "tools/zircolite/rules/rules_linux.json", options=(("config", "zircolite_journald.yaml"),)),
        ),
        docker_image="wagga40/zircolite:4.7.0@sha256:6dba9ac590a699d6d622ad9a7ecd2c7b2e0874decff3bc310d452b33ad45a28f",
    ),
    "chainsaw": ToolSpec(
        "chainsaw",
        "app.tools.chainsaw:ChainsawAdapter",
        frozenset({"evtx"}),
        frozenset({"local"}),
        "_chainsaw.json",
        True,
        "WithSecureOpenSource/chainsaw",
        "SigmaHQ/sigma",
        (
            ReleaseAsset("x86_64-linux", "chainsaw_x86_64-unknown-linux-gnu.tar.gz", "chainsaw-intel-lin", "chainsaw"),
            ReleaseAsset("aarch64-linux", "chainsaw_aarch64-unknown-linux-gnu.tar.gz", "chainsaw-arm-lin", "chainsaw"),
            ReleaseAsset("aarch64-darwin", "chainsaw_aarch64-apple-darwin.zip", "chainsaw-mac", "chainsaw"),
        ),
        ("--version",),
        profiles=(RuntimeProfile("default", ("tools/chainsaw/sigma/rules", "tools/chainsaw/sigma/rules-emerging-threats", "tools/chainsaw/sigma/rules-threat-hunting")),),
    ),
    "hayabusa": ToolSpec(
        "hayabusa",
        "app.tools.hayabusa:HayabusaAdapter",
        frozenset({"evtx"}),
        frozenset({"local", "docker"}),
        "_hayabusa.json",
        True,
        "Yamato-Security/hayabusa",
        "Yamato-Security/hayabusa-rules",
        (
            ReleaseAsset("x86_64-linux", "hayabusa-{version}-lin-x64-gnu.zip", "hayabusa-intel-lin", "hayabusa-{version}-lin-x64-gnu"),
            ReleaseAsset("aarch64-linux", "hayabusa-{version}-lin-aarch64-gnu.zip", "hayabusa-arm-lin", "hayabusa-{version}-lin-aarch64-gnu"),
            ReleaseAsset("aarch64-darwin", "hayabusa-{version}-mac-aarch64.zip", "hayabusa-mac", "hayabusa-{version}-mac-aarch64"),
        ),
        ("help",),
        profiles=(RuntimeProfile("default", "tools/hayabusa/rules/"),),
    ),
    "chopchopgo": ToolSpec(
        "chopchopgo",
        "app.tools.chopchopgo:ChopChopGoAdapter",
        frozenset({"auditd", "syslog"}),
        frozenset({"local"}),
        "_chopchopgo.json",
        False,
        "M00NLIG7/ChopChopGo",
        "SigmaHQ/sigma",
        (
            ReleaseAsset("x86_64-linux", "ChopChopGo-{tag}-linux-amd64.zip", "chopchopgo-intel-lin", "ChopChopGo"),
            ReleaseAsset("aarch64-linux", "ChopChopGo-{tag}-linux-arm64.zip", "chopchopgo-arm-lin", "ChopChopGo"),
        ),
        profiles=(RuntimeProfile("default", "tools/chopchopgo/rules/builtin"),),
    ),
    "rsigma": ToolSpec(
        "rsigma",
        "app.tools.rsigma:RsigmaAdapter",
        frozenset({"evtx", "json_evtx", "json_winlogbeat"}),
        frozenset({"local"}),
        "_rsigma.json",
        False,
        "timescale/rsigma",
        "SigmaHQ/sigma",
        (
            ReleaseAsset("x86_64-linux", "rsigma-x86_64-unknown-linux-gnu.tar.gz", "rsigma-intel-lin", "rsigma"),
            ReleaseAsset("aarch64-linux", "rsigma-aarch64-unknown-linux-gnu.tar.gz", "rsigma-arm-lin", "rsigma"),
            ReleaseAsset("aarch64-darwin", "rsigma-aarch64-apple-darwin.tar.gz", "rsigma-mac", "rsigma"),
        ),
        ("--version",),
        minor_is_breaking=True,
        required_files=("config/rsigma.yml", "mappings/windows.yml", "LICENSE-SigmaHQ"),
        profiles=(RuntimeProfile("default", "tools/rsigma/rules/"),),
    ),
}


def output_tool(filename: str) -> ToolSpec | None:
    # A compressed output keeps its name plus `.zst` (app/tools/output_files.py).
    name = filename.lower()
    name = name[:-4] if name.endswith(".zst") else name
    return next((spec for spec in TOOLS.values() if name.endswith(spec.output_suffix)), None)
