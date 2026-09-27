"""`rules_path` as a list, and the `--status` knob that sits on top of it.

Pointing Chainsaw's `--sigma` at the SigmaHQ repo *root* loads recursively — so
`deprecated/`, `unsupported/`, `rules-placeholder/` and `regression_data/` come along with
the curated rules. Naming the curated directories individually is the only way round it,
and that needs `rules_path` to hold more than one path.

Tier 1: no DB, no subprocess. The one thing these cannot prove is that `--sigma` is
genuinely repeatable — that was verified against the vendored binary by hand (repo root:
3,735 rules loaded / 1,014 rejected; three curated directories: 3,505 / 378).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.tools.base import ToolAdapter
from app.tools.chainsaw import ChainsawAdapter
from app.tools.zircolite import ZircoliteAdapter

THREE = [
    "tools/chainsaw/sigma/rules",
    "tools/chainsaw/sigma/rules-emerging-threats",
    "tools/chainsaw/sigma/rules-threat-hunting",
]


def _cmd(rules, **extra):
    adapter = ChainsawAdapter({"tool_path": "/fake", "rules_path": rules, **extra})
    # Bypass the executable check — this is about argument shape, not the binary.
    adapter._check_binary_executable = lambda _p: ""  # type: ignore[method-assign]
    cmd, err = adapter._build_local_cmd(Path("/fake"), Path("/in.evtx"), Path("/out.json"))
    assert err == "", err
    assert cmd is not None
    return cmd


def _sigma_values(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--sigma"]


# ── rules_path shape ─────────────────────────────────────────────────────────


def test_a_string_rules_path_emits_one_sigma_flag():
    assert _sigma_values(_cmd("tools/chainsaw/sigma/rules")) == ["tools/chainsaw/sigma/rules"]


def test_a_list_rules_path_emits_one_sigma_flag_each_in_order():
    """Order is preserved because Chainsaw reports the load list back verbatim."""
    assert _sigma_values(_cmd(THREE)) == THREE


def test_a_single_element_list_behaves_like_the_string():
    assert _sigma_values(_cmd(["a/b"])) == _sigma_values(_cmd("a/b"))


def test_rules_path_and_rules_paths_agree():
    """`rules_path` stays the first entry so existing consumers are untouched."""
    adapter = ChainsawAdapter({"tool_path": "/fake", "rules_path": THREE})
    assert adapter.rules_paths == THREE
    assert adapter.rules_path == THREE[0]


@pytest.mark.parametrize("bad", [[], "", None, ["ok", ""], ["ok", 3], 42, {"a": "b"}])
def test_an_invalid_rules_path_is_rejected_at_construction(bad):
    """Loudly, at construction — not as a silently empty hunt at run time."""
    with pytest.raises(ValueError, match="rules_path"):
        ChainsawAdapter({"tool_path": "/fake", "rules_path": bad})


def test_an_absent_rules_path_still_falls_back_to_the_default():
    assert ChainsawAdapter({"tool_path": "/fake"}).rules_paths == ["sigma_rules"]


# ── the Docker runner binds exactly one ──────────────────────────────────────


def test_a_multi_path_docker_task_fails_loudly_rather_than_running_on_the_first():
    """The base runner binds one host path at /rules.

    Running against only the first path would report a clean result from a fraction of the
    ruleset, which is the worst failure mode available to a detection platform — so this is
    an error, not a warning.
    """
    adapter = ZircoliteAdapter({"rules_path": THREE, "docker_image": "example:latest"})
    out = adapter._run_docker(Path("/in.evtx"), Path("/out.json"), Path("/outdir"))
    assert not out.success
    assert "rules paths" in (out.error or "")
    assert "Docker runner binds only one" in (out.error or "")


# ── options.status ───────────────────────────────────────────────────────────


def test_status_is_absent_by_default():
    """Unset means every status the rule files declare — the upstream default.

    Directory selection is the primary filter; adding a default here would silently drop
    rules an operator chose a directory to get.
    """
    assert "--status" not in _cmd(THREE)


def test_status_is_passed_through_when_set():
    cmd = _cmd(THREE, options={"status": "stable,experimental"})
    assert cmd[cmd.index("--status") + 1] == "stable,experimental"


def test_an_empty_status_is_treated_as_unset():
    assert "--status" not in _cmd(THREE, options={"status": ""})


def test_status_survives_an_absent_options_block():
    assert "--status" not in _cmd(THREE, options=None)


# ── the rule-content index spans every path ──────────────────────────────────


def test_the_rule_index_scans_every_path(tmp_path):
    """A finding from the second directory must still resolve its `rule_content`.

    Indexing only `rules_path` would leave every emerging-threats and threat-hunting
    finding with an empty rule body on the job page — present, but blank, which reads as
    the rule having no content rather than the index having missed it.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "one.yml").write_text("id: 11111111-1111-1111-1111-111111111111\ntitle: One\n", encoding="utf-8")
    (second / "two.yml").write_text("id: 22222222-2222-2222-2222-222222222222\ntitle: Two\n", encoding="utf-8")

    ToolAdapter._rule_index_cache.clear()
    adapter = ChainsawAdapter({"tool_path": "/fake", "rules_path": [str(first), str(second)]})
    assert "title: One" in adapter._lookup_rule_yaml("11111111-1111-1111-1111-111111111111")
    assert "title: Two" in adapter._lookup_rule_yaml("22222222-2222-2222-2222-222222222222")


def test_the_rule_index_cache_key_covers_every_path(tmp_path):
    """Two tasks sharing a first directory must not serve each other's index.

    A key that does not cover every path lets `[a]` and `[a, b]` collide — whichever runs
    first wins, and the other silently loses or gains rule bodies.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "one.yml").write_text("id: 33333333-3333-3333-3333-333333333333\ntitle: One\n", encoding="utf-8")
    (second / "two.yml").write_text("id: 44444444-4444-4444-4444-444444444444\ntitle: Two\n", encoding="utf-8")

    ToolAdapter._rule_index_cache.clear()
    narrow = ChainsawAdapter({"tool_path": "/fake", "rules_path": [str(first)]})
    assert narrow._lookup_rule_yaml("44444444-4444-4444-4444-444444444444") == ""

    wide = ChainsawAdapter({"tool_path": "/fake", "rules_path": [str(first), str(second)]})
    assert "title: Two" in wide._lookup_rule_yaml("44444444-4444-4444-4444-444444444444")
