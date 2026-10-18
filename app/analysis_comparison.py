"""Compare persisted rule matches without loading event samples or raw outputs."""

from collections import defaultdict

from app.constants import is_post_processing_task
from app.models import enum_val


def _group(job):
    groups, available = {}, defaultdict(list)
    for task in job.task_results:
        if is_post_processing_task(task.tool_name):
            continue
        available[task.tool_name].append(enum_val(task.status) == "completed")
        for finding in task.findings:
            identity = ("id", finding.rule_id) if finding.rule_id else ("title", finding.rule_name)
            key = (task.tool_name, *identity)
            group = groups.setdefault(key, {"title": finding.rule_name, "rule_id": finding.rule_id, "count": 0, "severities": defaultdict(int)})
            group["count"] += finding.count
            group["severities"][enum_val(finding.severity)] += finding.count
    return groups, {tool: all(states) for tool, states in available.items()}


def compare_findings(baseline, current) -> list[dict]:
    old, old_available = _group(baseline)
    new, new_available = _group(current)
    rows = []
    for key in sorted(old.keys() | new.keys()):
        before, after = old.get(key), new.get(key)
        comparable = old_available.get(key[0], False) and new_available.get(key[0], False)
        if not comparable:
            change = "Not comparable"
        elif before is None:
            change = "Added"
        elif after is None:
            change = "No longer observed"
        elif any(before[k] != after[k] for k in ("title", "count", "severities")):
            change = "Changed"
        else:
            change = "Unchanged"
        rows.append({"tool": key[0], "title": (after or before)["title"], "rule_id": (after or before)["rule_id"], "change": change, "before": before, "after": after})
    return rows
