"""Tests for app.yaml_utils — the libyaml loader must build exactly what yaml.safe_load builds."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app import yaml_utils
from app.yaml_utils import safe_load

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every rule file under tools/ takes ~11 s through SafeLoader; an even stride keeps each
# tool's whole directory tree represented at a fraction of that.
_RULE_SAMPLE_PER_TOOL = 120


def _outcome(text: str, loader: type) -> tuple[str, object]:
    try:
        return "ok", yaml.load(text, Loader=loader)
    except yaml.YAMLError as exc:
        return "error", type(exc)


def _repo_yaml_files() -> list[Path]:
    files = [*sorted((REPO_ROOT / "workflows").glob("*.yml")), *sorted((REPO_ROOT / "rules").glob("*.yml")), *sorted((REPO_ROOT / "config").glob("*.yaml"))]
    for tool_dir in sorted(p for p in (REPO_ROOT / "tools").iterdir() if p.is_dir()):
        rules = sorted(tool_dir.rglob("*.yml"))
        files.extend(rules[:: max(1, len(rules) // _RULE_SAMPLE_PER_TOOL)])
    return files


class TestLoaderChoice:
    def test_uses_libyaml_when_pyyaml_has_it(self):
        expected = yaml.CSafeLoader if yaml.__with_libyaml__ else yaml.SafeLoader
        assert yaml_utils._LOADER is expected

    def test_refuses_python_object_tags(self):
        with pytest.raises(yaml.constructor.ConstructorError):
            safe_load('!!python/object/apply:os.system ["true"]')


class TestSafeLoadEquivalence:
    @pytest.mark.skipif(not yaml.__with_libyaml__, reason="PyYAML built without libyaml")
    def test_matches_pure_python_loader_on_repo_yaml(self):
        files = _repo_yaml_files()
        assert len(files) > 100, "the sample must cover workflows, shared rules, config and vendored rules"
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            assert _outcome(text, yaml.CSafeLoader) == _outcome(text, yaml.SafeLoader), path

    def test_accepts_str_bytes_and_streams(self, tmp_path):
        cfg = tmp_path / "rule.yml"
        cfg.write_text("id: abc\nlevel: high\ntags: [attack.t1059]\n", encoding="utf-8")
        expected = {"id": "abc", "level": "high", "tags": ["attack.t1059"]}
        assert safe_load(cfg.read_text(encoding="utf-8")) == expected
        assert safe_load(cfg.read_bytes()) == expected
        with open(cfg, encoding="utf-8") as f:
            assert safe_load(f) == expected

    def test_empty_document_is_none(self):
        assert safe_load("") is None

    @pytest.mark.parametrize("text", ["rules: [", "rules:\n\t- a: 1\n", "a: b\x00c\n"])
    def test_malformed_input_still_raises_yaml_error(self, text):
        with pytest.raises(yaml.YAMLError):
            safe_load(text)
