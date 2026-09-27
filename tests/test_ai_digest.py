"""Tier-1 tests for app.ai.digest — pure, no DB, no network, no FastAPI.

The digest is the only thing the model ever sees, so this is where the two properties that
matter are pinned: it is **bounded** (every cap holds, and the true totals survive the
capping), and its truncation is **announced** — a brief that silently drops half a job's
detections produces an analysis that reads as complete and is not.

The third property is a security one: sample events go through the existing
``relationships.trim_evidence_event`` whitelist, so a field nobody vetted (a command line
full of encoded payload, say) never reaches a third-party API.
"""

from __future__ import annotations

import re

from app.ai.digest import (
    BRIEF_MARKER,
    DEFAULT_SYSTEM_PROMPT,
    ENTITY_SECTIONS,
    MAX_ENTITIES_PER_TYPE,
    MAX_FINDINGS,
    MAX_SAMPLE_EVENTS_PER_FINDING,
    MAX_TAGS_PER_FINDING,
    build_job_digest,
    render_prompt,
)
from app.constants import SEVERITY_ORDER
from app.intel.relationships import EVIDENCE_FIELDS

HUGE = 500_000  # a max_chars big enough that nothing is ever dropped for budget

# The end-of-function backstop in render_prompt. The slice leaves room for it, so it fits
# *inside* max_chars rather than extending past it.
HARD_CUT_NOTICE = "[truncated: brief exceeded the configured prompt size limit]"
HARD_CUT_TAIL = "\n\n" + HARD_CUT_NOTICE

_BLOCK_HEAD = re.compile(r"^\d+\. \[")


def _finding(name: str, severity: str = "high", count: int = 1, **kw) -> dict:
    f = {
        "rule_id": kw.pop("rule_id", f"id-{name}"),
        "rule_name": name,
        "severity": severity,
        "count": count,
        "tool": kw.pop("tool", "zircolite"),
        "tags": kw.pop("tags", []),
        "events": kw.pop("events", []),
    }
    f.update(kw)
    return f


def _job(**kw) -> dict:
    base = {
        "id": 7,
        "filename": "security.evtx",
        "log_type": "evtx",
        "workflow": "Windows quick scan",
        "status": "completed",
        "score_ratio": "2/3",
        "created_at": "2026-01-01T00:00:00",
        "severity_summary": {"critical": 1, "high": 2},
    }
    base.update(kw)
    return base


def _finding_blocks(prompt: str) -> list[str]:
    """The rendered finding records, as whole blocks.

    Blocks are joined with a blank line and every one starts ``N. [SEVERITY]``, so a split
    on the separator recovers exactly the records that were emitted — and a record cut in
    half would show up as a short block here rather than passing unnoticed.
    """
    _, marker, tail = prompt.partition("## Findings (most severe first)")
    assert marker, "prompt has no findings section"
    return [block for block in tail.split("\n\n") if _BLOCK_HEAD.match(block)]


# ── Caps and ordering ──────────────────────────────────────────────────────────


class TestFindingCapAndOrdering:
    def _mixed(self) -> list[dict]:
        """12 findings at each of the five severities, counts 1..12 within each."""
        out = []
        for severity in SEVERITY_ORDER:
            for n in range(1, 13):
                out.append(_finding(f"{severity}-{n}", severity=severity, count=n))
        return out

    def test_max_findings_caps_the_list_but_not_the_total(self):
        digest = build_job_digest(job=_job(), findings=self._mixed())
        assert len(digest["findings"]) == MAX_FINDINGS
        assert digest["findings_included"] == MAX_FINDINGS
        assert digest["findings_total"] == 60

    def test_most_severe_first_then_loudest_first(self):
        digest = build_job_digest(job=_job(), findings=self._mixed())
        ranks = [SEVERITY_ORDER.index(f["severity"]) for f in digest["findings"]]
        assert ranks == sorted(ranks), "findings are not ordered most-severe-first"

        by_severity: dict[str, list[int]] = {}
        for f in digest["findings"]:
            by_severity.setdefault(f["severity"], []).append(f["count"])
        for severity, counts in by_severity.items():
            assert counts == sorted(counts, reverse=True), f"{severity} counts are not descending"

    def test_the_kept_forty_are_the_most_severe_forty(self):
        digest = build_job_digest(job=_job(), findings=self._mixed())
        kept: dict[str, list[int]] = {}
        for f in digest["findings"]:
            kept.setdefault(f["severity"], []).append(f["count"])
        # 12 critical + 12 high + 12 medium = 36, leaving room for the four loudest lows.
        assert [len(kept.get(s, [])) for s in SEVERITY_ORDER] == [12, 12, 12, 4, 0]
        assert kept["low"] == [12, 11, 10, 9]

    def test_ordering_survives_unsorted_input(self):
        findings = [
            _finding("quiet crit", severity="critical", count=1),
            _finding("loud info", severity="informational", count=9999),
            _finding("loud crit", severity="critical", count=50),
            _finding("medium", severity="medium", count=3),
        ]
        digest = build_job_digest(job=_job(), findings=findings)
        assert [f["rule_name"] for f in digest["findings"]] == ["loud crit", "quiet crit", "medium", "loud info"]

    def test_unknown_severity_sorts_last_and_is_lowercased(self):
        findings = [
            _finding("weird", severity="SPICY", count=100),
            _finding("real", severity="LOW", count=1),
        ]
        digest = build_job_digest(job=_job(), findings=findings)
        assert [f["severity"] for f in digest["findings"]] == ["low", "spicy"]


class TestSampleEventCap:
    def test_events_per_finding_are_capped(self):
        events = [{"Computer": f"HOST{i}", "EventID": 1} for i in range(10)]
        digest = build_job_digest(job=_job(), findings=[_finding("noisy", events=events)])
        samples = digest["findings"][0]["sample_events"]
        assert len(samples) == MAX_SAMPLE_EVENTS_PER_FINDING
        # The first N, not an arbitrary N.
        assert [s["Computer"] for s in samples] == ["HOST0", "HOST1", "HOST2"]

    def test_prompt_carries_only_the_capped_events(self):
        events = [{"Computer": f"HOST{i}"} for i in range(10)]
        digest = build_job_digest(job=_job(), findings=[_finding("noisy", events=events)])
        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert prompt.count("   event: ") == MAX_SAMPLE_EVENTS_PER_FINDING
        assert "HOST9" not in prompt

    def test_tags_are_capped(self):
        tags = [f"attack.t{i:04d}" for i in range(30)]
        digest = build_job_digest(job=_job(), findings=[_finding("tagged", tags=tags)])
        assert len(digest["findings"][0]["tags"]) == MAX_TAGS_PER_FINDING


class TestEntityCaps:
    def test_each_entity_list_is_capped_but_the_total_is_true(self):
        analytics = {
            "users": [f"user{i}" for i in range(100)],
            "ip_addresses": [f"10.0.0.{i}" for i in range(3)],
        }
        digest = build_job_digest(job=_job(), findings=[], analytics=analytics)
        assert len(digest["entities"]["users"]) == MAX_ENTITIES_PER_TYPE
        assert digest["entity_totals"]["users"] == 100
        assert len(digest["entities"]["ip_addresses"]) == 3
        assert digest["entity_totals"]["ip_addresses"] == 3

    def test_prompt_announces_the_entity_cap(self):
        analytics = {"users": [f"user{i}" for i in range(100)]}
        digest = build_job_digest(job=_job(), findings=[], analytics=analytics)
        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert f"(showing {MAX_ENTITIES_PER_TYPE} of 100)" in prompt
        assert "user99" not in prompt

    def test_an_uncapped_entity_list_says_nothing_about_showing(self):
        digest = build_job_digest(job=_job(), findings=[], analytics={"users": ["alice", "bob"]})
        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert "Users: alice, bob" in prompt
        assert "showing" not in prompt

    def test_empty_and_non_list_entity_sections_are_skipped(self):
        analytics = {"users": [], "computers": "not-a-list", "domains": ["evil.test"]}
        digest = build_job_digest(job=_job(), findings=[], analytics=analytics)
        assert digest["entities"] == {"domains": ["evil.test"]}
        assert digest["entity_totals"] == {"domains": 1}


# ── Event field whitelist ──────────────────────────────────────────────────────


class TestSampleEventsGoThroughTheWhitelist:
    """Sample events are projected by ``relationships.trim_evidence_event``.

    Reusing that whitelist rather than writing a second trimmer keeps one answer to "which
    event fields are safe and useful to ship" — and it is the only thing standing between a
    raw matched event and a third-party API.
    """

    def test_a_non_whitelisted_field_is_dropped_and_a_whitelisted_one_survives(self):
        assert "Computer" in EVIDENCE_FIELDS
        assert "CommandLine" not in EVIDENCE_FIELDS

        event = {
            "Computer": "WORKSTATION1",
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "powershell -enc U0VDUkVUUEFZTE9BRA==",
            "SomeInternalField": "not-vetted",
        }
        digest = build_job_digest(job=_job(), findings=[_finding("r", events=[event])])
        sample = digest["findings"][0]["sample_events"][0]
        assert set(sample) == {"Computer", "Image"}
        assert sample["Computer"] == "WORKSTATION1"

        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert "WORKSTATION1" in prompt
        assert "CommandLine" not in prompt
        assert "U0VDUkVUUEFZTE9BRA==" not in prompt
        assert "SomeInternalField" not in prompt

    def test_nested_evtx_shape_is_flattened_by_the_shared_trimmer(self):
        event = {"Event": {"System": {"Computer": "DC1", "EventID": 4688}, "EventData": {"TargetUserName": "svc_backup", "Junk": "x"}}}
        digest = build_job_digest(job=_job(), findings=[_finding("r", events=[event])])
        sample = digest["findings"][0]["sample_events"][0]
        assert sample == {"Computer": "DC1", "EventID": 4688, "TargetUserName": "svc_backup"}

    def test_an_event_with_nothing_whitelisted_is_dropped_entirely(self):
        digest = build_job_digest(job=_job(), findings=[_finding("r", events=[{"CommandLine": "x"}, {"Computer": "H"}])])
        assert digest["findings"][0]["sample_events"] == [{"Computer": "H"}]


# ── Prompt budget ──────────────────────────────────────────────────────────────


def _bulky(n: int) -> list[dict]:
    """Findings big enough that a modest max_chars cannot hold them all."""
    return [
        _finding(
            f"Detection number {i:03d} " + "D" * 120,
            severity="high",
            count=1000 - i,
            tags=["attack.t1059", "attack.execution"],
            events=[{"Computer": f"HOST{i}", "Image": r"C:\Windows\System32\powershell.exe"}],
        )
        for i in range(n)
    ]


class TestPromptBudget:
    def test_prompt_is_bounded_by_max_chars(self):
        """Whatever the budget, the rendered prompt fits inside it — or says it was cut.

        Swept rather than spot-checked: the reserve is computed from the exact worst-case
        tail, and a reserve that is even a few bytes short only shows up at the budgets
        where the last block just fits. An earlier version guessed 240 and overshot by 62
        characters at roughly one budget in ten — always clipping the NOTE line that tells
        the model its view is partial, which is the worst sentence in the prompt to lose.

        ``max_chars`` is a hard ceiling: the sweep asserts the prompt never exceeds it, and
        that any cut is announced.
        """
        digest = build_job_digest(job=_job(), findings=_bulky(60), analytics={"users": [f"u{i}" for i in range(80)]})
        for max_chars in [*range(900, 6_000, 13), 8_000, 20_000, HUGE]:
            prompt, meta = render_prompt(digest, max_chars=max_chars)
            assert meta["chars"] == len(prompt)
            assert len(prompt) <= max_chars, f"prompt overflowed its ceiling at max_chars={max_chars}"
            if HARD_CUT_NOTICE in prompt:
                assert prompt.endswith(HARD_CUT_TAIL), f"silent cut at max_chars={max_chars}"
                assert meta["truncated"] is True

    def test_an_over_budget_prompt_is_never_a_silent_one(self):
        """The one property that must hold at every budget: a cut brief says it was cut."""
        digest = build_job_digest(job=_job(), findings=_bulky(60), analytics={"users": [f"u{i}" for i in range(80)]})
        for max_chars in range(300, 4_000, 7):
            prompt, meta = render_prompt(digest, max_chars=max_chars)
            if len(prompt) > max_chars:
                assert HARD_CUT_NOTICE in prompt
            assert meta["truncated"] is True  # every one of these budgets drops something

    def test_dropping_findings_for_budget_is_announced(self):
        digest = build_job_digest(job=_job(), findings=_bulky(60))
        prompt, meta = render_prompt(digest, max_chars=2_500)

        assert meta["truncated"] is True
        assert meta["findings_omitted"] > 0
        assert meta["findings_rendered"] < len(digest["findings"])
        # Truncation must never be silent: the model has to know its view is partial.
        assert "dropped to fit the prompt size limit" in prompt
        assert "Your view of this job is partial" in prompt

    def test_dropping_findings_for_the_cap_is_announced_even_with_unlimited_budget(self):
        digest = build_job_digest(job=_job(), findings=_bulky(60))
        prompt, meta = render_prompt(digest, max_chars=HUGE)

        assert meta["findings_rendered"] == MAX_FINDINGS
        assert meta["truncated"] is True
        assert meta["findings_omitted"] == 60 - MAX_FINDINGS
        assert "further finding(s) were not included in this brief" in prompt
        assert "Your view of this job is partial" in prompt

    def test_both_omission_reasons_are_reported_together(self):
        digest = build_job_digest(job=_job(), findings=_bulky(60))
        prompt, meta = render_prompt(digest, max_chars=2_500)
        omitted_by_cap = 60 - MAX_FINDINGS
        assert f"{omitted_by_cap} further finding(s) were not included" in prompt
        assert "finding(s) were dropped to fit the prompt size limit" in prompt
        assert meta["findings_omitted"] == omitted_by_cap + (MAX_FINDINGS - meta["findings_rendered"])

    def test_the_hard_cut_backstop_announces_itself(self):
        """When the context sections alone blow the budget, the cut is still stated.

        ``_small_sections`` is never dropped, so a job with nine full entity lists and a
        long heuristics section can exceed the budget before a single finding is
        considered. The prompt is cut and the cut is announced — which is the property that
        matters, since the model must not read a severed entity list as a complete one.

        The notice fits *inside* the ceiling: the slice leaves room for it rather than
        appending past it, so ``max_chars`` means what it says.
        """
        analytics = {key: ["X" * 200 + str(i) for i in range(60)] for key, _label in ENTITY_SECTIONS}
        digest = build_job_digest(job=_job(), findings=_bulky(5), analytics=analytics)

        for max_chars in (2_000, 20_000, 45_000):
            prompt, meta = render_prompt(digest, max_chars=max_chars)
            assert HARD_CUT_NOTICE in prompt, "the brief was cut without saying so"
            assert meta["truncated"] is True
            assert len(prompt) == max_chars, "the hard cut must land exactly on the ceiling, notice included"

    def test_a_complete_brief_is_not_flagged_as_truncated(self):
        digest = build_job_digest(job=_job(), findings=_bulky(3))
        prompt, meta = render_prompt(digest, max_chars=HUGE)
        assert meta == {"chars": len(prompt), "findings_rendered": 3, "findings_omitted": 0, "truncated": False}
        assert "partial" not in prompt


class TestFindingsAreNeverHalfSerialised:
    """The budget loop stops at a whole record.

    A half-serialised finding is worse than an absent one: the model reads a truncated rule
    name or a cut-off event as fact, and there is nothing in the text to warn it.
    """

    def test_every_rendered_block_is_a_complete_record(self):
        digest = build_job_digest(job=_job(), findings=_bulky(40))
        full, _full_meta = render_prompt(digest, max_chars=HUGE)
        full_blocks = _finding_blocks(full)
        assert len(full_blocks) == MAX_FINDINGS

        small, meta = render_prompt(digest, max_chars=1_800)
        small_blocks = _finding_blocks(small)

        assert 0 < len(small_blocks) < len(full_blocks), "budget did not actually truncate"
        assert len(small_blocks) == meta["findings_rendered"]
        # Byte-identical to the untruncated rendering of the same records: nothing was cut
        # mid-record, and nothing was reordered.
        assert small_blocks == full_blocks[: len(small_blocks)]

    def test_a_partial_block_never_appears_at_any_budget(self):
        """Swept densely, including the budgets where the hard-cut backstop fires.

        The backstop slices from the end, and the omission notice sits there — so what it
        eats is the tail of that sentence, never the last finding record. Which is the
        right order to lose things in, and worth pinning: the reverse would hand the model
        a severed rule name with nothing marking it as severed.
        """
        digest = build_job_digest(job=_job(), findings=_bulky(40))
        full_blocks = _finding_blocks(render_prompt(digest, max_chars=HUGE)[0])
        for max_chars in range(900, 4_000, 7):
            prompt, meta = render_prompt(digest, max_chars=max_chars)
            blocks = _finding_blocks(prompt)
            assert blocks == full_blocks[: len(blocks)], f"a record was cut at max_chars={max_chars}"
            assert len(blocks) == meta["findings_rendered"]

    def test_a_budget_too_small_for_any_finding_renders_none_rather_than_a_fragment(self):
        digest = build_job_digest(job=_job(), findings=_bulky(10))
        prompt, meta = render_prompt(digest, max_chars=700)
        assert meta["findings_rendered"] == 0
        assert _finding_blocks(prompt) == []
        assert "(none)" in prompt
        assert meta["truncated"] is True
        assert "dropped to fit the prompt size limit" in prompt


# ── Junk tolerance ─────────────────────────────────────────────────────────────


class TestBuildJobDigestToleratesJunk:
    """It runs in a worker whose only job is to record an outcome — it must not raise.

    Everything it reads came out of the database as free-form JSON, so every one of these
    shapes is reachable from a tool that changed its output format.
    """

    def test_missing_keys_everywhere(self):
        digest = build_job_digest(job={}, findings=[{}])
        assert digest["findings_total"] == 1
        assert digest["findings"][0] == {
            "rule_id": None,
            "rule_name": "",
            "severity": "informational",
            "count": 0,
            "tool": "",
            "tags": [],
            "sample_events": [],
        }
        render_prompt(digest, max_chars=HUGE)

    def test_none_values_throughout(self):
        job = {"id": None, "filename": None, "log_type": None, "workflow": None, "status": None, "score_ratio": None, "created_at": None, "severity_summary": None}
        findings = [{"rule_id": None, "rule_name": None, "severity": None, "count": None, "tool": None, "tags": None, "events": None}]
        digest = build_job_digest(job=job, findings=findings, analytics=None)
        assert digest["severity_summary"] == {}
        assert digest["findings"][0]["severity"] == "informational"
        assert digest["findings"][0]["count"] == 0
        assert digest["findings"][0]["tags"] == []
        assert digest["findings"][0]["sample_events"] == []
        prompt, meta = render_prompt(digest, max_chars=HUGE)
        assert "file: unknown" in prompt
        assert meta["truncated"] is False

    def test_non_dict_entries_in_the_findings_list_are_skipped(self):
        findings = [None, "junk", 42, ["nope"], _finding("real")]
        digest = build_job_digest(job=_job(), findings=findings)
        assert digest["findings_total"] == 1
        assert digest["findings"][0]["rule_name"] == "real"

    def test_a_non_list_findings_container_is_tolerated(self):
        for junk in ("a string", {"a": "dict"}, ()):
            digest = build_job_digest(job=_job(), findings=junk)  # type: ignore[arg-type]
            assert digest["findings"] == []
            assert digest["findings_total"] == 0
            render_prompt(digest, max_chars=HUGE)

    def test_non_dict_analytics_is_tolerated(self):
        for junk in (None, "analytics", ["a"], 17):
            digest = build_job_digest(job=_job(), findings=[], analytics=junk)  # type: ignore[arg-type]
            assert digest["entities"] == {}
            assert digest["entity_totals"] == {}
            assert digest["mitre_tactics"] == {}
            assert digest["threat_detection"] == {}
            render_prompt(digest, max_chars=HUGE)

    def test_junk_inside_analytics_sections(self):
        analytics = {
            "users": "not-a-list",
            "mitre_tactics": "not-a-dict",
            "threat_detection": ["not-a-dict"],
            "computers": [None, 42, "REAL-HOST"],
        }
        digest = build_job_digest(job=_job(), findings=[], analytics=analytics)
        assert digest["mitre_tactics"] == {}
        assert digest["threat_detection"] == {}
        assert digest["entities"]["computers"] == ["", "42", "REAL-HOST"]
        render_prompt(digest, max_chars=HUGE)

    def test_junk_inside_threat_detection_categories(self):
        analytics = {
            "threat_detection": {
                "categories": {"a": "not-a-dict", "b": {"label": "LOLBIN", "severity": "high", "total": 2, "indicators": ["junk", {"value": "certutil.exe", "count": 2}]}}
            }
        }
        digest = build_job_digest(job=_job(), findings=[], analytics=analytics)
        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert "LOLBIN" in prompt
        assert "certutil.exe (x2)" in prompt

    def test_junk_counts_and_tags_do_not_raise(self):
        findings = [
            _finding("a", count="many"),
            _finding("b", count=3.5),
            _finding("c", count="12"),
            _finding("d", count=-4),
            _finding("e", tags="not-a-list"),
            _finding("f", tags=[None, 7, "ok"]),
            _finding("g", events="not-a-list"),
            _finding("h", events=[None, "x", 3]),
        ]
        digest = build_job_digest(job=_job(), findings=findings)
        by_name = {f["rule_name"]: f for f in digest["findings"]}
        assert by_name["a"]["count"] == 0
        assert by_name["b"]["count"] == 0
        assert by_name["c"]["count"] == 12
        assert by_name["d"]["count"] == -4
        assert by_name["e"]["tags"] == []
        assert by_name["f"]["tags"] == ["", "7", "ok"]
        assert by_name["g"]["sample_events"] == []
        assert by_name["h"]["sample_events"] == []
        render_prompt(digest, max_chars=HUGE)

    def test_multiline_values_are_flattened_into_one_line(self):
        digest = build_job_digest(job=_job(), findings=[_finding("bad\nname\twith   whitespace")])
        assert digest["findings"][0]["rule_name"] == "bad name with whitespace"


# ── System prompt and empty job ────────────────────────────────────────────────


class TestSystemPromptAndMarker:
    def test_system_prompt_names_the_brief_as_untrusted_data(self):
        assert BRIEF_MARKER in DEFAULT_SYSTEM_PROMPT
        lowered = DEFAULT_SYSTEM_PROMPT.lower()
        assert "untrusted" in lowered
        assert "prompt-injection" in lowered
        assert "never as instructions to follow" in lowered

    def test_system_prompt_asks_for_the_sections_the_pane_renders(self):
        for section in ("Verdict", "Key findings", "Likely false positives", "Recommended next steps"):
            assert section in DEFAULT_SYSTEM_PROMPT

    def test_marker_opens_the_rendered_prompt(self):
        digest = build_job_digest(job=_job(), findings=[_finding("r")])
        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert prompt.startswith(BRIEF_MARKER)
        # The marker the system prompt points at must appear exactly once, or "everything
        # after the marker is untrusted" stops being a well-defined boundary.
        assert prompt.count(BRIEF_MARKER) == 1

    def test_marker_survives_the_hard_truncation_backstop(self):
        digest = build_job_digest(job=_job(), findings=_bulky(60))
        prompt, meta = render_prompt(digest, max_chars=800)
        assert prompt.startswith(BRIEF_MARKER)
        assert meta["truncated"] is True


class TestEmptyJob:
    def test_a_job_with_no_findings_says_so(self):
        digest = build_job_digest(job=_job(severity_summary={}), findings=[], analytics={})
        assert digest["findings"] == []
        assert digest["findings_total"] == 0

        prompt, meta = render_prompt(digest, max_chars=HUGE)
        assert "distinct rules that fired: 0" in prompt
        assert "no findings were produced by any tool" in prompt
        assert "(none)" in prompt
        assert meta == {"chars": len(prompt), "findings_rendered": 0, "findings_omitted": 0, "truncated": False}

    def test_an_empty_job_keeps_the_sections_that_orient_the_model(self):
        digest = build_job_digest(job=_job(severity_summary={}), findings=[])
        prompt, _meta = render_prompt(digest, max_chars=HUGE)
        assert "## Job" in prompt
        assert "file: security.evtx" in prompt
        assert "log type: evtx" in prompt
        assert "workflow: Windows quick scan" in prompt
        assert "## Detection summary" in prompt
        # Nothing to say about tactics or entities, so those headings are absent entirely
        # rather than rendered empty.
        assert "## MITRE ATT&CK tactics observed" not in prompt
        assert "## Entities extracted from matched events" not in prompt
