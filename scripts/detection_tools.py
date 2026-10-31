"""Check and stage vendored detection engines and matching rule snapshots.

Standard library only: also runs before the application venv is installed.
Validate every download and architecture before replacing a tool directory.
Keep the previous directory under backups/. Container pins are changed separately.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from datetime import UTC, datetime
from pathlib import Path

# This script also runs before PDM is installed. The catalog has no app imports.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.tools.catalog import TOOLS
from app.tools.digests import file_digest as sha256
from app.tools.digests import tree_digest
from app.tools.runtime import resolve_task_config
from scripts.tool_runtime_inventory import workflow_task_scalars

REPOS = {name: spec.repo for name, spec in TOOLS.items()}
RULE_REPOS = {name: spec.rule_repo for name, spec in TOOLS.items()}
MANIFEST = "upstream.json"

# What Chainsaw keeps of a SigmaHQ snapshot: the curated rule directories and the licence
# they are redistributed under. The rest of that repository — regression_data/ alone is
# 34 MB, plus images, tests, documentation, and the deprecated/, unsupported/ and
# rules-placeholder/ sets upstream says must not run — is never loaded by any workflow.
CHAINSAW_SIGMA_KEEP = (
    "rules",
    "rules-emerging-threats",
    "rules-threat-hunting",
    "rules-dfir",
    "rules-compliance",
    "LICENSE",
    "README.md",
)


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def api(endpoint: str):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "LogsTotal-detection-tools"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"https://api.github.com/repos/{endpoint}", headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 — fixed HTTPS API
        return json.load(response)


def download(url: str, destination: Path, digest: str = "") -> None:
    if not url.startswith(("https://github.com/", "https://codeload.github.com/")):
        raise ValueError(f"unexpected download URL: {url}")
    with urllib.request.urlopen(url, timeout=120) as response, destination.open("wb") as stream:  # noqa: S310
        shutil.copyfileobj(response, stream)
    if digest and digest != "sha256:" + sha256(destination):
        raise ValueError(f"checksum mismatch: {destination.name}")


def extract(archive: Path, destination: Path) -> None:
    """Extract regular files only, excluding nested Git metadata."""
    destination.mkdir()

    def target(name: str) -> Path | None:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError(f"unsafe archive member: {name}")
        if ".git" in path.parts:
            return None
        out = destination / path
        out.parent.mkdir(parents=True, exist_ok=True)
        return out

    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                if member.is_dir():
                    continue
                if member.external_attr >> 16 & 0o170000 == 0o120000:
                    raise ValueError(f"archive contains symlink: {member.filename}")
                if out := target(member.filename):
                    with bundle.open(member) as source, out.open("wb") as stream:
                        shutil.copyfileobj(source, stream)
                    out.chmod(0o755 if member.external_attr >> 16 & 0o111 else 0o644)
    else:
        with tarfile.open(archive) as bundle:
            for member in bundle:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"archive contains non-regular file: {member.name}")
                if out := target(member.name):
                    with bundle.extractfile(member) as source, out.open("wb") as stream:
                        shutil.copyfileobj(source, stream)
                    out.chmod(0o755 if member.mode & 0o111 else 0o644)


def asset_map(tool: str, tag: str) -> list[tuple[str, str, str]]:
    values = {"tag": tag, "version": tag.removeprefix("v")}
    return [(asset.archive.format(**values), asset.installed, asset.executable.format(**values)) for asset in TOOLS[tool].assets]


def validate_binary(path: Path, name: str) -> None:
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) < 64:
        raise ValueError(f"not an executable: {name}")
    if name.endswith("-mac"):
        valid = header[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack_from("<I", header, 4)[0] == 0x100000C
    else:
        machine = 183 if name.endswith("-arm-lin") else 62
        valid = header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == machine
    if not valid:
        raise ValueError(f"wrong executable format/architecture: {name}")


def host_binary(directory: Path, tool: str) -> Path | None:
    suffix = {("Darwin", "arm64"): "mac", ("Darwin", "aarch64"): "mac", ("Linux", "x86_64"): "intel-lin", ("Linux", "aarch64"): "arm-lin", ("Linux", "arm64"): "arm-lin"}.get(
        (platform.system(), platform.machine().lower())
    )
    candidate = directory / f"{tool}-{suffix}"
    return candidate if suffix and candidate.is_file() else None


def local_version(root: Path, tool: str) -> str:
    directory = root / "tools" / tool
    if tool == "zircolite":
        versions = set()
        for workflow in (root / "workflows").glob("*.yml"):
            content = workflow.read_text()
            versions.update(re.findall(r"wagga40/zircolite:(\d+\.\d+\.\d+)", content))
            for task in workflow_task_scalars(content):
                if task.get("tool") == "zircolite" and "profile" in task:
                    image = resolve_task_config(task).get("docker_image", "")
                    versions.update(re.findall(r"wagga40/zircolite:(\d+\.\d+\.\d+)", image or ""))
        if len(versions) > 1:
            raise ValueError("inconsistent Zircolite versions in workflows")
        return next(iter(versions), "")
    manifest = directory / MANIFEST
    if manifest.exists():
        data = read_json(manifest)
        hashes = data.get("binaries", {})
        if hashes and all((directory / name).is_file() and sha256(directory / name) == digest for name, digest in hashes.items()):
            return data.get("version", "")
        raise ValueError(f"{tool}: installed binaries differ from {MANIFEST}")
    binary = host_binary(directory, tool)
    if binary and TOOLS[tool].version_args:
        proc = subprocess.run([str(binary.resolve()), *TOOLS[tool].version_args], capture_output=True, text=True, timeout=30, check=False)
        if match := re.search(r"\bv?(\d+\.\d+\.\d+)\b", proc.stdout):
            return match[1]
    return ""


def replace_tree(source: Path, destination: Path) -> None:
    if not source.is_dir() or not any(source.rglob("*")):
        raise ValueError(f"missing/empty upstream directory: {source}")
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def sigma_subset(source: Path, destination: Path) -> None:
    """Copy only CHAINSAW_SIGMA_KEEP out of a SigmaHQ snapshot."""
    if not (source / "rules").is_dir():
        raise ValueError(f"not a SigmaHQ snapshot (no rules/): {source}")
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name in CHAINSAW_SIGMA_KEEP:
        entry = source / name
        if entry.is_dir():
            shutil.copytree(entry, destination / name)
        elif entry.is_file():
            shutil.copy2(entry, destination / name)


def snapshot(repo: str, ref: str, work: Path, name: str) -> Path:
    archive = work / f"{name}.tar.gz"
    download(f"https://codeload.github.com/{repo}/tar.gz/{ref}", archive)
    unpacked = work / name
    extract(archive, unpacked)
    roots = list(unpacked.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError(f"unexpected source archive layout: {repo}")
    return roots[0]


def stage_binaries(tool: str, release: dict, stage: Path, work: Path) -> dict:
    assets = {asset["name"]: asset for asset in release["assets"]}
    hashes = {}
    for asset_name, installed_name, executable in asset_map(tool, release["tag_name"]):
        if asset_name not in assets:
            raise ValueError(f"missing release asset: {asset_name}")
        asset = assets[asset_name]
        if not str(asset.get("digest", "")).startswith("sha256:"):
            raise ValueError(f"release asset has no SHA-256 digest: {asset_name}")
        print(f"Downloading {asset_name}", flush=True)
        archive = work / asset_name
        download(asset["browser_download_url"], archive, asset["digest"])
        unpacked = work / installed_name
        extract(archive, unpacked)
        matches = [p for p in unpacked.rglob(executable) if p.is_file()]
        if len(matches) != 1:
            raise ValueError(f"expected one {executable} in {asset_name}; found {len(matches)}")
        validate_binary(matches[0], installed_name)
        shutil.copyfile(matches[0], stage / installed_name)
        (stage / installed_name).chmod(0o755)
        hashes[installed_name] = sha256(stage / installed_name)
        if tool == "hayabusa":
            replace_tree(matches[0].parent / "config", stage / "config")
        elif tool == "chopchopgo":
            replace_tree(matches[0].parent / "mappings", stage / "mappings")
    return hashes


def rsigma_rules(source: Path, stage: Path) -> None:
    """Vendor independent Windows rules and the LogsTotal-owned matching pipeline."""
    from app.tools.rsigma_windows import EXCLUDED_CATEGORIES, windows_pipeline

    rules = stage / "rules"
    if rules.exists():
        shutil.rmtree(rules)
    rules.mkdir()
    for name in ("rules", "rules-emerging-threats", "rules-threat-hunting"):
        directory = source / name / "windows"
        if directory.is_dir():
            shutil.copytree(directory, rules / name / "windows", ignore=lambda _path, names: [n for n in names if n in EXCLUDED_CATEGORIES or n == ".git"])
    if not any(rules.rglob("*.yml")):
        raise ValueError("RSigma Windows rule snapshot is empty")
    shutil.copyfile(source / "LICENSE", stage / "LICENSE-SigmaHQ")
    (stage / "mappings").mkdir(exist_ok=True)
    (stage / "config").mkdir(exist_ok=True)
    write_json(stage / "mappings" / "windows.yml", windows_pipeline())
    write_json(stage / "config" / "rsigma.yml", {"version": 1})


def stage_rules(tool: str, release: dict, stage: Path, work: Path, *, ref: str = "HEAD") -> dict:
    repo = RULE_REPOS[tool]
    commit = api(f"{repo}/commits/{urllib.parse.quote(ref, safe='')}")
    source = snapshot(repo, commit["sha"], work, "rule-source")
    if tool == "chainsaw":
        sigma_subset(source, stage / "sigma")
        native = snapshot(REPOS[tool], release["tag_name"], work, "native-source")
        for name in ("rules", "mappings"):
            replace_tree(native / name, stage / name)
    elif tool == "hayabusa":
        for name in ("config", "hayabusa", "sigma"):
            replace_tree(source / name, stage / "rules" / name)
    elif tool == "chopchopgo":
        replace_tree(source / "rules" / "linux", stage / "rules")
    elif tool == "rsigma":
        rsigma_rules(source, stage)
    else:
        for name in ("rules_windows_merged.json", "rules_linux.json"):
            rules = read_json(source / "rules" / name)
            if not isinstance(rules, list) or not rules or any(not isinstance(r, dict) or not r.get("rule") or not r.get("title") for r in rules):
                raise ValueError(f"empty/invalid compiled ruleset: {name}")
            shutil.copyfile(source / "rules" / name, stage / "rules" / name)
        # Preserve the LogsTotal journald aliases beside the compiled bundles.
    return {
        "repo": repo,
        "commit": commit["sha"],
        "committed_at": commit["commit"]["committer"]["date"],
        "trees": {name: tree_digest(stage / name) for name in ("rules", "sigma", "mappings", "config") if (stage / name).is_dir()},
    }


def install(root: Path, tool: str, stage: Path) -> Path:
    """Retain the previous tool and restore it if installation fails."""
    destination = root / "tools" / tool
    backup_root = root / "backups"
    backup_root.mkdir(exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix=f"tools-{tool}-", dir=backup_root)) / tool
    destination.rename(backup)
    try:
        stage.rename(destination)
    except BaseException:
        backup.rename(destination)
        raise
    return backup


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError(f"unsupported release version: {value}")
    return tuple(map(int, match.groups()))


def breaking_update(tool: str, have: str, want: str) -> bool:
    old, new = version_tuple(have), version_tuple(want)
    return old[0] != new[0] or (TOOLS[tool].minor_is_breaking and old[0] == 0 and old[:2] != new[:2])


def update(root: Path, tool: str, allow_major: bool, *, version: str | None = None, rules_ref: str | None = None) -> None:
    release_ref = "tags/" + urllib.parse.quote(version, safe="") if version else "latest"
    release = api(f"{REPOS[tool]}/releases/{release_ref}")
    have, want = local_version(root, tool), release["tag_name"]
    if have and version_tuple(have) > version_tuple(want):
        raise ValueError(f"refusing to downgrade {tool}: {have} -> {want}")
    if (not have or breaking_update(tool, have, want)) and not allow_major:
        raise ValueError(f"{tool}: {have or 'unknown'} -> {want}; validate the adapter, then pass --allow-major")
    print(f"{tool}: {have or '?'} -> {want}", flush=True)
    with tempfile.TemporaryDirectory(prefix=f".{tool}-", dir=root / "tools") as temporary:
        work = Path(temporary)
        stage = work / "staged"
        shutil.copytree(root / "tools" / tool, stage)
        hashes = stage_binaries(tool, release, stage, work)
        rules = stage_rules(tool, release, stage, work, **({"ref": rules_ref} if rules_ref else {}))
        write_json(stage / MANIFEST, {"repo": REPOS[tool], "version": want, "binaries": hashes, "rules": rules})
        backup = install(root, tool, stage)
    print(f"Installed {tool} rules" + (" and binaries" if hashes else "") + f"; previous files: {backup}")
    if tool == "zircolite":
        print(f"Container pin unchanged. Resolve and test wagga40/zircolite:{want.removeprefix('v')} before updating app/tools/catalog.py (or a workflow override).")
    print("Run the affected sample workflows and compare named findings before deploying.")


def check(root: Path, targets: list[str], strict: bool) -> int:
    pending = False
    commits = {}
    print(f"{'TOOL':12} {'VENDORED':12} {'LATEST':12} STATUS")
    for tool in targets:
        try:
            have = local_version(root, tool)
            want = api(f"{REPOS[tool]}/releases/latest")["tag_name"]
            if not have:
                status = "vendored version unknown"
            elif version_tuple(have) == version_tuple(want):
                status = "current"
            elif version_tuple(have) > version_tuple(want):
                status = "newer than latest release"
            elif breaking_update(tool, have, want):
                status = "BREAKING — incompatible version change; validate the adapter"
            else:
                status = "update available"
            print(f"{tool:12} {have or '?':12} {want:12} {status}")
            pending |= status not in {"current", "newer than latest release"}
            manifest = root / "tools" / tool / MANIFEST
            if not manifest.exists():
                print("  Rules: snapshot provenance unknown; refresh with tools:update")
                pending = True
                continue
            rules = read_json(manifest)["rules"]
            if not rules.get("trees"):
                raise ValueError(f"{tool}: rule checksums are missing; refresh the snapshot")
            for name, digest in rules.get("trees", {}).items():
                path = manifest.parent / name
                if not path.is_dir() or tree_digest(path) != digest:
                    raise ValueError(f"{tool}/{name}: rules/configuration differ from the recorded snapshot")
            repo = rules["repo"]
            if repo not in commits:
                commits[repo] = api(f"{repo}/commits/HEAD")["sha"]
            current = rules["commit"] == commits[repo]
            age = (datetime.now(UTC) - datetime.fromisoformat(rules["committed_at"].replace("Z", "+00:00"))).days
            print(f"  Rules: {rules['commit'][:12]}, {age} days old — {'current' if current else 'update available'}")
            pending |= not current
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            print(f"{tool}: unable to verify: {error}")
            pending = True
    return int(strict and pending)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "update", "artifacts"), nargs="?", default="check")
    parser.add_argument("tools", nargs="*")
    parser.add_argument("--strict", action="store_true", default=os.environ.get("TOOLS_STRICT") == "1")
    parser.add_argument("--allow-major", action="store_true", default=os.environ.get("TOOLS_ALLOW_MAJOR") == "1")
    parser.add_argument("--version", help="Exact upstream release tag (single-tool update only)")
    parser.add_argument("--rules-ref", help="Rules commit, tag or branch; resolved to an immutable commit (single-tool update only)")
    args = parser.parse_intermixed_args(argv)
    if (args.version or args.rules_ref) and (args.action != "update" or len(args.tools) != 1):
        parser.error("--version and --rules-ref require an update of exactly one tool")
    if unknown := set(args.tools) - REPOS.keys():
        parser.error(f"unknown tool(s): {', '.join(sorted(unknown))}")
    if args.action == "update" and not args.tools:
        parser.error("name at least one tool: ./logstotal tools:update -- chainsaw")
    root = Path.cwd()
    try:
        if args.action == "artifacts":
            for tool in args.tools or TOOLS:
                spec = TOOLS[tool]
                base = Path("tools") / tool
                manifest = read_json(root / base / MANIFEST)
                paths = [MANIFEST, "LICENSE", *spec.required_files, *(asset.installed for asset in spec.assets), *manifest["rules"]["trees"]]
                for path in dict.fromkeys(paths):
                    print((base / path).as_posix())
            return 0
        if args.action == "check":
            return check(root, args.tools or list(REPOS), args.strict)
        for tool in dict.fromkeys(args.tools):
            update(root, tool, args.allow_major, **({"version": args.version} if args.version else {}), **({"rules_ref": args.rules_ref} if args.rules_ref else {}))
        return 0
    except (OSError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
