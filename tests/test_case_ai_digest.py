"""Bounded case prompts preserve whole evidence records and signal missing context."""

import pytest

from app.ai.case_digest import BRIEF_MARKER, build_case_digest, render_case_prompt


@pytest.mark.parametrize("budget", [0, 1, 30, 100, 500, 2000, 60000])
def test_budget_is_a_hard_limit(budget):
    digest = build_case_digest(case={"name": "Case", "notes": "x" * 8000}, jobs=[], entities=[], findings=[], findings_total=0)
    prompt, meta = render_case_prompt(digest, max_chars=budget)
    assert len(prompt) <= budget
    assert meta["chars"] == len(prompt)
    if budget >= 500:
        assert prompt.startswith(BRIEF_MARKER)
    if 500 <= budget < 60000:
        assert "truncated" in prompt


def test_notes_cannot_crowd_out_findings():
    digest = build_case_digest(
        case={"summary": "s" * 8000, "notes": "n" * 8000},
        jobs=[],
        entities=[],
        findings=[{"id": 1, "job_id": 2, "rule_name": "Suspicious powershell", "severity": "high"}],
        findings_total=1,
    )
    prompt, meta = render_case_prompt(digest, max_chars=60000)
    assert '"notes":"' in prompt and '"summary":"' in prompt
    assert "Suspicious powershell" in prompt
    assert meta["findings_rendered"] == 1
