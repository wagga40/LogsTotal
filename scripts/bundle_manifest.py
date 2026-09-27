"""Read and validate a local bundle without consulting a release server."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


def member(archive: Path, name: str) -> bytes:
    return subprocess.run(["7z", "x", "-so", str(archive), name], capture_output=True, check=True).stdout


def manifest(bundle: Path) -> dict:
    data = json.loads(member(bundle, "bundle-manifest.json"))
    if not re.fullmatch(r"\d+\.\d+\.\d+", data["version"]):
        raise ValueError("Invalid bundle version")
    if Path(data["archive"]).name != data["archive"] or not data["archive"].endswith(".7z"):
        raise ValueError("Invalid archive filename")
    return data


def verify(bundle: Path) -> None:
    data = manifest(bundle)
    with tempfile.TemporaryDirectory(prefix="logstotal-bundle-check-") as directory:
        root = Path(directory)
        archive = root / data["archive"]
        payload = member(bundle, data["archive"])
        if hashlib.sha256(payload).hexdigest() != data["archive_sha256"]:
            raise ValueError("Embedded archive checksum does not match the manifest")
        archive.write_bytes(payload)
        version = member(archive, "VERSION").decode().strip()
        if version != f"version: {data['version']}":
            raise ValueError("Embedded release version does not match the bundle")
        if data.get("schema", 1) < 2:
            return  # Legacy bundles did not record build provenance labels.
        for name, tag in (("logstotal", data["app_image"]), ("logstotal-garage", data["garage_image"])):
            image = root / f"{name}.tar"
            image.write_bytes(member(bundle, f"images/{name}.tar"))
            with tarfile.open(image) as tar:
                entries = json.load(tar.extractfile("manifest.json"))
                entry = next((item for item in entries if tag in (item.get("RepoTags") or [])), None)
                if entry is None:
                    raise ValueError(f"{name}: expected image tag is absent")
                labels = json.load(tar.extractfile(entry["Config"]))["config"].get("Labels") or {}
                if labels.get("org.logstotal.archive-sha256") != data["archive_sha256"] or labels.get("org.opencontainers.image.version") != data["version"]:
                    raise ValueError(f"{name}: image provenance differs from the selected release")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("version", "verify"))
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "version":
            print(manifest(args.bundle)["version"])
        else:
            verify(args.bundle)
    except (ValueError, TypeError, KeyError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        parser.exit(1, f"ERROR: invalid bundle: {exc}\n")


if __name__ == "__main__":
    main()
