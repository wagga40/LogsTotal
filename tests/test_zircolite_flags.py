"""Tests for log_type-driven Zircolite input flags (-AU / -S / -j)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.tools.base import ToolOutput
from app.tools.zircolite import ZircoliteAdapter


@pytest.fixture
def zircolite_env(tmp_path: Path):
    """A fake zircolite script + rules file + input log on disk."""
    script = tmp_path / "zircolite.py"
    script.write_text("# fake")
    rules = tmp_path / "rules_linux.json"
    rules.write_text("[]")
    log = tmp_path / "audit.log"
    log.write_text("type=SYSCALL msg=audit(1.0:1):\n")
    return script, rules, log


def _adapter(script: Path, rules: Path, **extra) -> ZircoliteAdapter:
    return ZircoliteAdapter({"tool_path": str(script), "rules_path": str(rules), **extra})


def _cmd_for(adapter: ZircoliteAdapter, log: Path, tmp_path: Path) -> list[str]:
    cmd, err = adapter._build_local_cmd(Path(adapter.config["tool_path"]), log, tmp_path / "out.json")
    assert err == ""
    return cmd


# ── run() records the log type on the adapter ───────────────────────────────


def test_run_populates_log_type(zircolite_env, tmp_path, monkeypatch):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    monkeypatch.setattr(
        adapter,
        "_execute_and_parse",
        lambda cmd, output_file: ToolOutput(success=True),
    )
    adapter.run(log, tmp_path / "out", log_type="auditd")
    assert adapter._log_type == "auditd"


# ── local command flags ─────────────────────────────────────────────────────


def test_auditd_adds_au_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = "auditd"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-AU" in cmd


def test_sysmon_linux_adds_s_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = "sysmon_linux"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-S" in cmd


def test_journald_adds_j_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = "journald"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-j" in cmd


def test_evtx_adds_no_input_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = "evtx"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert not {"-AU", "-S", "-j"} & set(cmd)


def test_no_log_type_adds_no_input_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    cmd = _cmd_for(adapter, log, tmp_path)
    assert not {"-AU", "-S", "-j"} & set(cmd)


def test_flag_not_duplicated_when_in_extra_args(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, extra_args=["-AU"])
    adapter._log_type = "auditd"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert cmd.count("-AU") == 1


def test_long_form_in_extra_args_suppresses_short_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, extra_args=["--auditd-input"])
    adapter._log_type = "auditd"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-AU" not in cmd
    assert cmd.count("--auditd-input") == 1


# ── docker args parity ──────────────────────────────────────────────────────


def test_docker_args_auditd_flag(zircolite_env):
    script, rules, _ = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = "auditd"
    args = adapter._docker_tool_args("/case/a.log", "/rules", "/out/a.json")
    assert "-AU" in args


def test_docker_args_evtx_no_flag(zircolite_env):
    script, rules, _ = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = "evtx"
    args = adapter._docker_tool_args("/case/a.evtx", "/rules", "/out/a.json")
    assert not {"-AU", "-S", "-j"} & set(args)


# ── supported types ─────────────────────────────────────────────────────────


def test_supported_types_include_linux_formats():
    assert {"auditd", "sysmon_linux", "journald"} <= ZircoliteAdapter.SUPPORTED_TYPES


def test_every_supported_type_but_evtx_declares_an_input_flag():
    """Every supported non-EVTX type states its input format explicitly.

    Current Zircolite auto-detects the format, so these flags are belt-and-braces rather
    than load-bearing (verified live against wagga40/zircolite:latest: identical event
    counts with and without them). They are still pinned because auto-detection is a
    heuristic with documented opt-outs (`--no-auto-mode`, `--no-auto-detect`) and its
    failure mode is silent — the wrong parser yields zero events, and the job then reads
    as *clean* rather than *not analysed*. Iterating the set here means a newly supported
    type cannot quietly rely on the heuristic.
    """
    missing = {t for t in ZircoliteAdapter.SUPPORTED_TYPES if t != ZircoliteAdapter._NATIVE_TYPE} - set(ZircoliteAdapter._INPUT_FLAGS)
    assert not missing, f"SUPPORTED_TYPES without an input flag: {sorted(missing)}"


@pytest.mark.parametrize("log_type", ["json_evtx", "json_winlogbeat"])
def test_json_types_add_the_json_input_flag(zircolite_env, tmp_path, log_type):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules)
    adapter._log_type = log_type
    assert "-j" in _cmd_for(adapter, log, tmp_path)
    assert "-j" in adapter._docker_tool_args("/case/a.json", "/rules", "/out/a.json")


# ── input-format flags are mutually exclusive in Zircolite ──────────────────


@pytest.mark.parametrize("configured", ["--json-array-input", "--jsonarray", "--json-array"])
def test_array_input_in_extra_args_suppresses_the_jsonl_flag(zircolite_env, tmp_path, configured):
    """`-j` and `--json-array-input` are different options in one argparse mutex group.

    Emitting both is a hard usage error, so a workflow that opts into JSON *array* input
    must not have `-j` bolted on beside it.
    """
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, extra_args=[configured])
    adapter._log_type = "json_evtx"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-j" not in cmd
    assert cmd.count(configured) == 1


def test_jsonline_alias_is_recognised_for_dedupe(zircolite_env, tmp_path):
    """`--jsonline` is a real alias of `-j` (per zircolite.py --help) and must dedupe."""
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, extra_args=["--jsonline"])
    adapter._log_type = "journald"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-j" not in cmd


def test_cross_format_flag_suppresses_our_own(zircolite_env, tmp_path):
    """An author forcing a different parser entirely wins over the log_type default."""
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, extra_args=["--csv-input"])
    adapter._log_type = "auditd"
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-AU" not in cmd


def test_declared_aliases_are_all_real_zircolite_flags():
    """Every alias we dedupe on must belong to Zircolite's input-format mutex group.

    Alias lists were transcribed from `zircolite.py --help` (wagga40/zircolite:latest);
    a typo here would silently stop dedupe from firing.
    """
    for log_type, aliases in ZircoliteAdapter._INPUT_FLAGS.items():
        unknown = set(aliases) - ZircoliteAdapter._ALL_INPUT_FORMAT_FLAGS
        assert not unknown, f"{log_type} declares non-existent flags: {sorted(unknown)}"


# ── options.config → -c, resolved beside the rules ──────────────────────────
#
# The compiled Linux ruleset keys on sysmon/auditd field names, so a journald export
# matched almost nothing (measured: 0 detections on an 8-event sample; 5 with the
# alias config). The config must resolve beside rules_path in BOTH execution modes:
# the runner bind-mounts the rules file's parent directory, so a sibling file is the
# only extra input reachable in Docker without a second mount.


def test_config_option_is_passed_locally_beside_the_rules(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, options={"config": "zircolite_journald.yaml"})
    cmd = _cmd_for(adapter, log, tmp_path)
    assert "-c" in cmd
    assert cmd[cmd.index("-c") + 1] == str(rules.parent / "zircolite_journald.yaml")


def test_config_option_uses_the_container_rules_dir_under_docker(zircolite_env):
    script, rules, _log = zircolite_env
    adapter = _adapter(script, rules, options={"config": "zircolite_journald.yaml"})
    args = adapter._docker_tool_args("/case/in.json", "/rules/rules_linux.json", "/out/out.json")
    assert args[args.index("-c") + 1] == "/rules/zircolite_journald.yaml", "config must resolve inside the mounted /rules"


def test_no_config_option_emits_no_flag(zircolite_env, tmp_path):
    script, rules, log = zircolite_env
    assert "-c" not in _cmd_for(_adapter(script, rules), log, tmp_path)


@pytest.mark.parametrize("bad", ["../escape.yaml", "sub/dir.yaml", "..", "", "   "])
def test_config_option_rejects_anything_but_a_bare_filename(zircolite_env, tmp_path, bad):
    """A path could point outside the one directory the runner mounts."""
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, options={"config": bad})
    assert "-c" not in _cmd_for(adapter, log, tmp_path)


@pytest.mark.parametrize("flag", ["-c", "--config"])
def test_explicit_config_in_extra_args_is_not_duplicated(zircolite_env, tmp_path, flag):
    """Zircolite's -c takes one value; emitting it twice would be a usage error."""
    script, rules, log = zircolite_env
    adapter = _adapter(script, rules, options={"config": "zircolite_journald.yaml"}, extra_args=[flag, "/custom.yaml"])
    cmd = _cmd_for(adapter, log, tmp_path)
    assert cmd.count("-c") + cmd.count("--config") == 1


# ── the shipped journald mapping ────────────────────────────────────────────


def test_shipped_journald_config_exists_beside_the_ruleset():
    """workflows/linux_journald.yml names it; it must sit in the mounted directory."""
    import yaml

    root = Path(__file__).resolve().parent.parent
    wf = yaml.safe_load((root / "workflows" / "linux_journald.yml").read_text(encoding="utf-8"))
    task = wf["tasks"][0]
    name = task["options"]["config"]
    cfg = (root / task["rules_path"]).parent / name
    assert cfg.is_file(), f"{cfg} is referenced by the workflow but missing"

    mapping = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    # These right-hand names are what rules_linux.json actually queries; the left-hand
    # ones are what journalctl -o json emits.
    assert mapping["alias"]["_EXE"] == "Image"
    assert mapping["alias"]["_CMDLINE"] == "CommandLine"


# ── Windows event XML: the flag depends on the file, not the log type ───────
#
# Measured against wagga40/zircolite:latest (4-event sample):
#            -x     --evtxtract-input
#   rootless 1/4          4/4
#   rooted   4/4          0/4
# Both flags are correct, each for the shape the other cannot read. A statically
# chosen flag would silently parse a fraction of every file of the other shape and
# report that as a complete analysis.

_NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
_ONE_EVENT = f"<Event {_NS}><System><EventID>4624</EventID></System></Event>"


def _xml_adapter(tmp_path: Path, body: str, name: str = "in.xml"):
    from app.tools.zircolite import ZircoliteAdapter

    src = tmp_path / name
    src.write_text(body, encoding="utf-8")
    adapter = ZircoliteAdapter({"rules_path": str(tmp_path / "rules.json"), "docker_image": "x"})
    adapter._log_type = "xml_evtx"
    adapter._input_path = src
    return adapter


def test_rootless_xml_selects_evtxtract(tmp_path):
    adapter = _xml_adapter(tmp_path, _ONE_EVENT + "\n" + _ONE_EVENT + "\n")
    assert adapter._input_flags() == ["--evtxtract-input"]


def test_rooted_xml_selects_xml_input(tmp_path):
    body = f'<?xml version="1.0" encoding="utf-8"?>\n<Events>\n{_ONE_EVENT}\n</Events>\n'
    assert _xml_adapter(tmp_path, body)._input_flags() == ["-x"]


def test_rootless_xml_with_declaration_still_selects_evtxtract(tmp_path):
    """An XML declaration on a rootless file must not be mistaken for a wrapper."""
    body = f'<?xml version="1.0" encoding="utf-8"?>\n{_ONE_EVENT}\n'
    assert _xml_adapter(tmp_path, body)._input_flags() == ["--evtxtract-input"]


def test_bom_prefixed_xml_is_handled(tmp_path):
    body = "﻿" + f"<Events>\n{_ONE_EVENT}\n</Events>\n"
    assert _xml_adapter(tmp_path, body)._input_flags() == ["-x"]


def test_unreadable_xml_falls_back_to_the_wevtutil_shape(tmp_path):
    """wevtutil qe /f:xml — the rootless form — is the common export."""
    adapter = _xml_adapter(tmp_path, _ONE_EVENT)
    adapter._input_path = tmp_path / "gone.xml"
    assert adapter._input_flags() == ["--evtxtract-input"]


def test_explicit_xml_flag_in_extra_args_suppresses_the_sniff(tmp_path):
    """Zircolite's input formats are one mutually exclusive group; two is a usage error."""
    adapter = _xml_adapter(tmp_path, _ONE_EVENT)
    adapter._extra_args = ["-x"]
    assert adapter._input_flags() == []


def test_shipped_xml_sample_is_the_rootless_shape(tmp_path):
    """Pins the pairing the sample manifest asserts: this file needs --evtxtract-input."""
    from app.tools.zircolite import ZircoliteAdapter

    sample = Path(__file__).resolve().parent.parent / "samples" / "windows" / "security_events.xml"
    adapter = ZircoliteAdapter({"rules_path": "r.json", "docker_image": "x"})
    adapter._log_type = "xml_evtx"
    adapter._input_path = sample
    assert adapter._input_flags() == ["--evtxtract-input"]


# ── options.config with a *directory* rules_path ─────────────────────────────
#
# Four of five shipped workflows point `rules_path` at a directory; only the journald one
# names a file. Taking the parent of whatever `_config_flags` is given would resolve a
# directory rules_path one level too high locally and to the filesystem root under Docker.


def test_config_option_resolves_inside_a_directory_rules_path(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules_linux.json").write_text("[]")
    script = tmp_path / "zircolite.py"
    script.write_text("# fake")
    log = tmp_path / "audit.log"
    log.write_text("type=SYSCALL msg=audit(1.0:1):\n")

    adapter = ZircoliteAdapter({"tool_path": str(script), "rules_path": str(rules_dir), "options": {"config": "aliases.yaml"}})
    cmd = _cmd_for(adapter, log, tmp_path)
    assert cmd[cmd.index("-c") + 1] == str(rules_dir / "aliases.yaml"), "a directory rules_path must not have its parent taken"


def test_docker_config_is_under_the_mount_point_for_a_directory_rules_path(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    adapter = ZircoliteAdapter({"docker_image": "x", "rules_path": str(rules_dir), "options": {"config": "aliases.yaml"}})
    # The runner passes container_rules="/rules" when rules_path is a directory.
    args = adapter._docker_tool_args("/case/in.json", "/rules", "/out/out.json")
    assert args[args.index("-c") + 1] == "/rules/aliases.yaml", "rsplit on '/rules' yielded '' and pointed at the filesystem root"
