"""Who wrote the rule behind a finding.

The SigmaHQ rules, and the rule sets built from them, are redistributed under the Detection
Rule License 1.1. It asks anyone who shares *match output* to keep the rule author's
identification with it, and a finding is match output — on the job page and in the
findings.json export — so both name the author wherever they name the rule.

Pure: no FastAPI, no database. Chainsaw, Hayabusa and ChopChopGo keep the rule's own YAML in
`Finding.rule_content`, `author:` line included. Zircolite keeps only the SQL it compiled the
rule to, so its author comes from the ruleset that rule was compiled into, by rule id.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from app.json_utils import load_file

_ZIRCOLITE_RULES = Path(__file__).resolve().parent.parent / "tools" / "zircolite" / "rules"
# Anchored to a line start so a SQL rule body or a description that mentions "author:" in
# passing is not taken for the field.
_AUTHOR_LINE = re.compile(r"^author:[ \t]*(.+?)[ \t]*$", re.M)


def authors_from_rule_text(text: str | None) -> str:
    """The `author:` of a rule's YAML — every distinct one, for a multi-document finding."""
    authors: list[str] = []
    for match in _AUTHOR_LINE.finditer(text or ""):
        value = match.group(1).strip().strip("'\"").strip()
        if value and value not in authors:
            authors.append(value)
    return "; ".join(authors)


@lru_cache(maxsize=1)
def _zircolite_authors() -> dict[str, str]:
    """Rule id → author, across the compiled rulesets the Zircolite workflows load."""
    index: dict[str, str] = {}
    for path in sorted(_ZIRCOLITE_RULES.glob("*.json")):
        try:
            rules = load_file(path)
        except (OSError, ValueError):
            continue
        for rule in rules if isinstance(rules, list) else []:
            if isinstance(rule, dict) and rule.get("id") and rule.get("author"):
                index.setdefault(str(rule["id"]), str(rule["author"]).strip())
    return index


def rule_author(tool_name: str | None, rule_id: str | None, rule_content: str | None) -> str:
    """The author to show beside a finding's rule, or "" when nothing records one."""
    from_text = authors_from_rule_text(rule_content)
    if from_text:
        return from_text
    if tool_name == "zircolite" and rule_id:
        return _zircolite_authors().get(str(rule_id), "")
    return ""
