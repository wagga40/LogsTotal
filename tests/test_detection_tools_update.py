"""A failed update must leave every installed architecture and rule intact."""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import detection_tools as updater


def elf(machine=62):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    tool = tmp_path / "tools" / "chainsaw"
    tool.mkdir(parents=True)
    (tool / "chainsaw-intel-lin").write_bytes(b"working binary")
    (tool / "rules").mkdir()
    (tool / "rules" / "custom.yml").write_text("existing rule")
    monkeypatch.setattr(updater, "local_version", lambda *_: "2.16.0")
    return tmp_path


def contents(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_missing_later_architecture_keeps_all_installed_files(installed, monkeypatch):
    release = {
        "tag_name": "v2.16.5",
        "assets": [{"name": "chainsaw_x86_64-unknown-linux-gnu.tar.gz", "browser_download_url": "https://github.com/example", "digest": "sha256:fake"}],
    }
    monkeypatch.setattr(updater, "api", lambda *_: release)

    def download(_url, path, _digest):
        with tarfile.open(path, "w:gz") as bundle:
            for name, payload in [("chainsaw/chainsaw", elf()), ("chainsaw/large-data", b"x" * 10000)]:
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))

    monkeypatch.setattr(updater, "download", download)
    before = contents(installed / "tools")
    with pytest.raises(ValueError, match="missing release asset"):
        updater.update(installed, "chainsaw", False)
    assert contents(installed / "tools") == before
    assert not (installed / "backups").exists()


def test_failed_rule_download_cannot_install_new_binaries(installed, monkeypatch):
    monkeypatch.setattr(updater, "api", lambda *_: {"tag_name": "v2.16.5", "assets": []})

    def stage_binary(_tool, _release, stage, _work):
        (stage / "chainsaw-intel-lin").write_bytes(b"replacement")
        return {}

    def fail(*_):
        raise OSError("upstream unavailable")

    monkeypatch.setattr(updater, "stage_binaries", stage_binary)
    monkeypatch.setattr(updater, "stage_rules", fail)
    before = contents(installed / "tools")
    with pytest.raises(OSError, match="unavailable"):
        updater.update(installed, "chainsaw", False)
    assert contents(installed / "tools") == before


def test_major_change_fails_before_staging(installed, monkeypatch):
    monkeypatch.setattr(updater, "api", lambda *_: {"tag_name": "v3.0.0"})
    before = contents(installed / "tools")
    with pytest.raises(ValueError, match="--allow-major"):
        updater.update(installed, "chainsaw", False)
    assert contents(installed / "tools") == before


def test_install_keeps_complete_backup(installed):
    before = contents(installed / "tools" / "chainsaw")
    stage = installed / "staged"
    stage.mkdir()
    (stage / "binary").write_bytes(b"replacement")
    backup = updater.install(installed, "chainsaw", stage)
    assert contents(backup) == before
    assert contents(installed / "tools" / "chainsaw") == {"binary": b"replacement"}


def test_failed_directory_swap_restores_original(installed, monkeypatch):
    stage = installed / "staged"
    stage.mkdir()
    original_rename = Path.rename

    def rename(path, target):
        if path == stage:
            raise OSError("disk error")
        return original_rename(path, target)

    monkeypatch.setattr(Path, "rename", rename)
    before = contents(installed / "tools")
    with pytest.raises(OSError, match="disk error"):
        updater.install(installed, "chainsaw", stage)
    assert contents(installed / "tools") == before


@pytest.mark.parametrize("name", ["../escape", "/absolute", "nested/../../escape", "nested\\escape"])
def test_unsafe_archive_paths_are_rejected(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(name, "payload")
    with pytest.raises(ValueError, match="unsafe archive"):
        updater.extract(archive, tmp_path / "unpacked")


def test_archive_git_metadata_is_excluded(tmp_path):
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("rules/.git/config", "repo metadata")
        bundle.writestr("rules/detection.yml", "rule")
    updater.extract(archive, tmp_path / "unpacked")
    assert contents(tmp_path / "unpacked") == {"rules/detection.yml": b"rule"}


def test_checksum_mismatch_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b"wrong download"))
    with pytest.raises(ValueError, match="checksum mismatch"):
        updater.download("https://github.com/release.zip", tmp_path / "release.zip", "sha256:expected")


def test_wrong_architecture_is_rejected(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(elf(62))
    updater.validate_binary(binary, "chainsaw-intel-lin")
    with pytest.raises(ValueError, match="architecture"):
        updater.validate_binary(binary, "chainsaw-arm-lin")


def test_linux_discovery_never_tries_the_mac_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(updater.platform, "system", lambda: "Linux")
    monkeypatch.setattr(updater.platform, "machine", lambda: "aarch64")
    for name in ("chainsaw-mac", "chainsaw-arm-lin", "chainsaw-intel-lin"):
        (tmp_path / name).touch()
    assert updater.host_binary(tmp_path, "chainsaw").name == "chainsaw-arm-lin"


def test_strict_check_fails_when_upstream_cannot_be_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "local_version", lambda *_: "2.16.5")

    def fail(*_):
        raise OSError("network down")

    monkeypatch.setattr(updater, "api", fail)
    assert updater.check(tmp_path, ["chainsaw"], strict=True) == 1
    assert updater.check(tmp_path, ["chainsaw"], strict=False) == 0


def test_unknown_target_fails_before_any_update(monkeypatch):
    monkeypatch.setattr(updater, "update", lambda *_: pytest.fail("must validate all names first"))
    with pytest.raises(SystemExit) as error:
        updater.main(["update", "chainsaw", "typo"])
    assert error.value.code == 2


def test_exact_binary_is_selected_instead_of_larger_data(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    stage.mkdir()
    monkeypatch.setattr(updater, "asset_map", lambda *_: [("release.zip", "chainsaw-intel-lin", "chainsaw")])

    def download(_url, path, _digest):
        with zipfile.ZipFile(path, "w") as bundle:
            bundle.writestr("chainsaw/chainsaw", elf())
            bundle.writestr("chainsaw/big-rules.json", b"x" * 10000)

    monkeypatch.setattr(updater, "download", download)
    release = {"tag_name": "v2.16.5", "assets": [{"name": "release.zip", "browser_download_url": "https://github.com/release.zip", "digest": "sha256:fixture"}]}
    hashes = updater.stage_binaries("chainsaw", release, stage, tmp_path)
    assert (stage / "chainsaw-intel-lin").read_bytes() == elf()
    assert hashes == {"chainsaw-intel-lin": updater.sha256(stage / "chainsaw-intel-lin")}


def test_zircolite_rule_refresh_preserves_journald_aliases(tmp_path, monkeypatch):
    stage = tmp_path / "stage"
    source = tmp_path / "source"
    for directory in (stage, source):
        (directory / "rules").mkdir(parents=True)
    aliases = stage / "rules/zircolite_journald.yaml"
    aliases.write_text("alias:\n  _EXE: Image\n")
    for name in ("rules_windows_merged.json", "rules_linux.json"):
        updater.write_json(source / "rules" / name, [{"title": "rule", "rule": ["SELECT * FROM logs"]}])
    monkeypatch.setattr(updater, "api", lambda *_: {"sha": "abc", "commit": {"committer": {"date": "2026-09-20T00:00:00Z"}}})
    monkeypatch.setattr(updater, "snapshot", lambda *_: source)
    manifest = updater.stage_rules("zircolite", {}, stage, tmp_path)
    assert aliases.read_text() == "alias:\n  _EXE: Image\n"
    assert manifest["trees"]["rules"] == updater.tree_digest(stage / "rules")


def test_chainsaw_keeps_only_the_rule_sets_and_their_licence(tmp_path, monkeypatch):
    """A SigmaHQ snapshot is mostly not rules: regression data, images, tests, and sets
    upstream says must not run. None of it is loaded, and all of it would ship."""
    source = tmp_path / "sigma-src"
    for name in (*updater.CHAINSAW_SIGMA_KEEP, "regression_data/x", "images/y", "deprecated/z", "rules-placeholder/p"):
        path = source / name
        if "." in Path(name).name or name in ("LICENSE",):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        else:
            path.mkdir(parents=True, exist_ok=True)
            (path / "rule.yml").write_text("title: t\n")
    native = tmp_path / "native"
    for name in ("rules", "mappings"):
        (native / name).mkdir(parents=True)
        (native / name / "a.yml").write_text("a")
    stage = tmp_path / "stage"
    stage.mkdir()
    monkeypatch.setattr(updater, "api", lambda *_: {"sha": "abc", "commit": {"committer": {"date": "2026-09-20T00:00:00Z"}}})
    monkeypatch.setattr(updater, "snapshot", lambda _repo, _ref, _work, name: source if name == "rule-source" else native)
    manifest = updater.stage_rules("chainsaw", {"tag_name": "v2.16.5"}, stage, tmp_path)
    assert sorted(p.name for p in (stage / "sigma").iterdir()) == sorted(updater.CHAINSAW_SIGMA_KEEP)
    assert manifest["trees"]["sigma"] == updater.tree_digest(stage / "sigma")


def test_the_vendored_chainsaw_sigma_tree_is_the_subset():
    shipped = Path(__file__).resolve().parents[1] / "tools" / "chainsaw" / "sigma"
    extra = sorted(p.name for p in shipped.iterdir() if p.name not in updater.CHAINSAW_SIGMA_KEEP)
    assert not extra, f"tools/chainsaw/sigma carries what no workflow loads: {extra}"


def test_strict_check_detects_deleted_rule_even_when_upstream_is_current(tmp_path, monkeypatch):
    directory = tmp_path / "tools/chainsaw"
    rules = directory / "rules"
    rules.mkdir(parents=True)
    (rules / "one.yml").write_text("rule one")
    (rules / "two.yml").write_text("rule two")
    updater.write_json(
        directory / updater.MANIFEST,
        {"rules": {"repo": "SigmaHQ/sigma", "commit": "current", "committed_at": "2026-09-20T00:00:00Z", "trees": {"rules": updater.tree_digest(rules)}}},
    )
    monkeypatch.setattr(updater, "local_version", lambda *_: "2.16.5")
    monkeypatch.setattr(updater, "api", lambda endpoint: {"tag_name": "v2.16.5"} if endpoint.endswith("latest") else {"sha": "current"})
    assert updater.check(tmp_path, ["chainsaw"], strict=True) == 0
    (rules / "one.yml").unlink()
    assert updater.check(tmp_path, ["chainsaw"], strict=True) == 1


def test_manifest_cannot_hide_a_modified_binary(tmp_path):
    directory = tmp_path / "tools/chopchopgo"
    directory.mkdir(parents=True)
    binary = directory / "chopchopgo-arm-lin"
    binary.write_bytes(b"original")
    updater.write_json(directory / updater.MANIFEST, {"version": "v1.1.0", "binaries": {binary.name: updater.sha256(binary)}})
    assert updater.local_version(tmp_path, "chopchopgo") == "v1.1.0"
    binary.write_bytes(b"replacement")
    with pytest.raises(ValueError, match="binaries differ"):
        updater.local_version(tmp_path, "chopchopgo")
