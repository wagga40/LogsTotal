"""One malformed record must not discard a tool's entire findings set.

Every adapter's `normalize()` ran an unguarded `record.get(...)` loop, and
`ToolAdapter.run` catches around the whole call. So a single `null` line, a truncated
final NDJSON record, or a `"level": null` turned a file full of real detections into
`0 findings` — which on a detection platform reads as **clean**, not **broken**. That is
the worst available failure mode, and it is the ordinary shape of output from a tool that
was killed, hit a full disk, or wrote a partial line.

The malformed shapes here are the ones that actually occur: a killed process leaves a
truncated line (`_load_jsonl` yields whatever parsed), and tools legitimately emit nulls
for optional fields.
"""

from __future__ import annotations

import pytest

from app.tools.chainsaw import ChainsawAdapter
from app.tools.chopchopgo import ChopChopGoAdapter
from app.tools.hayabusa import HayabusaAdapter
from app.tools.zircolite import ZircoliteAdapter

GOOD_ZIRCOLITE = {"title": "Real detection", "id": "zr-1", "rule_level": "high", "count": 2, "matches": [{"a": 1}], "tags": ["attack.t1059"]}
GOOD_HAYABUSA = {"RuleTitle": "Real detection", "RuleID": "hb-1", "Level": "high", "Timestamp": "2026-01-01T00:00:00Z"}
GOOD_CHAINSAW = {"name": "Real detection", "id": "cs-1", "level": "high", "tags": ["t1"], "document": {"data": {"Event": {}}}}
GOOD_CHOPCHOPGO = {"Title": "Real detection", "ID": "cc-1", "Message": "m", "Tags": ["t1"]}

# Shapes a partially-written output actually produces. All non-dict: a dict with no
# recognised fields is a different case — it is a *record*, and every adapter has always
# folded it into "Unknown Rule" rather than dropping it, which stays correct.
JUNK = [None, "a truncated line", 42, []]


def _cfg(**kw):
    return {"tool_path": "/nonexistent", "rules_path": "/nonexistent", **kw}


ADAPTERS = [
    pytest.param(ZircoliteAdapter, GOOD_ZIRCOLITE, id="zircolite"),
    pytest.param(HayabusaAdapter, GOOD_HAYABUSA, id="hayabusa"),
    pytest.param(ChainsawAdapter, GOOD_CHAINSAW, id="chainsaw"),
    pytest.param(ChopChopGoAdapter, GOOD_CHOPCHOPGO, id="chopchopgo"),
]


@pytest.mark.parametrize(("adapter_cls", "good"), ADAPTERS)
def test_a_good_record_survives_junk_around_it(adapter_cls, good):
    adapter = adapter_cls(_cfg())
    findings = adapter.normalize([*JUNK, good, *JUNK])
    assert len(findings) == 1, "the real detection must survive"
    assert findings[0].rule_name == "Real detection"


@pytest.mark.parametrize(("adapter_cls", "good"), ADAPTERS)
def test_a_null_severity_does_not_take_the_file_with_it(adapter_cls, good):
    """`raw.lower()` on a null level raised AttributeError straight out of normalize()."""
    for key in ("rule_level", "level", "Level"):
        if key in good:
            record = {**good, key: None}
            break
    else:
        pytest.skip("adapter derives severity from the rule YAML, not the record")

    findings = adapter_cls(_cfg()).normalize([record])
    assert len(findings) == 1
    assert findings[0].severity == "informational"


@pytest.mark.parametrize(("adapter_cls", "good"), ADAPTERS)
def test_non_list_output_is_still_empty_not_an_exception(adapter_cls, good):
    for raw in (None, {}, "", 0):
        assert adapter_cls(_cfg()).normalize(raw) == []


def test_numeric_severity_is_coerced_rather_than_raising():
    """Some Sigma pipelines emit numeric levels."""
    findings = ZircoliteAdapter(_cfg()).normalize([{**GOOD_ZIRCOLITE, "rule_level": 3}])
    assert findings[0].severity == "informational"


def test_zircolite_survives_a_non_list_matches_field():
    findings = ZircoliteAdapter(_cfg()).normalize([{**GOOD_ZIRCOLITE, "matches": "unexpected"}])
    assert len(findings) == 1
    assert findings[0].details == []


def test_chainsaw_survives_a_non_dict_document():
    findings = ChainsawAdapter(_cfg()).normalize([{**GOOD_CHAINSAW, "document": "unexpected"}])
    assert len(findings) == 1
    assert findings[0].count == 1


@pytest.mark.parametrize(("adapter_cls", "good"), ADAPTERS)
def test_an_empty_dict_record_becomes_unknown_rule_not_a_lost_file(adapter_cls, good):
    """A dict with nothing recognisable in it is still a record, and always has been."""
    findings = adapter_cls(_cfg()).normalize([{}, good])
    names = {f.rule_name for f in findings}
    assert "Real detection" in names
    assert "Unknown Rule" in names
