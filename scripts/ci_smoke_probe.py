"""Small reads that `scripts/ci-deploy-smoke.sh` makes against a running stack.

A file rather than `python3 -c` inside the shell script: an inline snippet loses its stdin
to a heredoc, and a double quote inside a single-quoted bash string cannot be escaped —
failures invisible until the snippet runs. Here they are ordinary Python — ruff lints
them, and they can be exercised directly.

Standard library only: this runs against the *host* interpreter during CI, before and
outside any virtualenv, exactly like scripts/gen_secrets.py.

Usage (each reads the document on stdin):
    curl .../                     | python3 scripts/ci_smoke_probe.py workflow-id --log-type syslog
    curl .../jobs/1/status-partial | python3 scripts/ci_smoke_probe.py job-status
    curl .../jobs/1/findings.json  | python3 scripts/ci_smoke_probe.py findings-count
"""

from __future__ import annotations

import argparse
import json
import re
import sys

# Mirrors app.constants.TERMINAL_JOB_STATUSES. Duplicated rather than imported: this file
# must run with no venv and no app on sys.path, and a probe that needs the application
# importable cannot check whether the application is importable.
TERMINAL_JOB_STATUSES = ("completed", "failed", "partial", "cancelled")

# The upload form ships its workflow list as a JSON island so Alpine can filter it by the
# detected log type. That makes it the stable way to learn an id from outside — ids come
# from init_db.py's insertion order and are not fixed.
_WORKFLOWS_ISLAND = re.compile(r'id="workflows-data"[^>]*>(.*?)</script>', re.S)


def workflow_id(html: str, log_type: str) -> int:
    """The id of the first workflow accepting *log_type*."""
    match = _WORKFLOWS_ISLAND.search(html)
    if not match:
        raise SystemExit("the homepage carries no #workflows-data block — is this the upload page?")
    try:
        workflows = json.loads(match.group(1))
    except ValueError as exc:
        raise SystemExit(f"#workflows-data is not JSON: {exc}") from exc
    for workflow in workflows:
        if log_type in (workflow.get("log_types") or []):
            return int(workflow["id"])
    raise SystemExit(f"no workflow accepts {log_type!r} — did init_db.py load workflows/?")


# `/jobs/{id}/findings.json` is a bare list of findings and carries no status, so the
# status comes from the poll partial the job page itself uses. Two markers there are load-
# bearing and both are pinned by existing tests: the region carries `hx-trigger="every 3s"`
# only while the job is *not* terminal (tests/test_integration_routes.py), and it includes
# `partials/_status_badge.html` exactly once, which renders `badge-<status>`.
_STILL_POLLING = re.compile(r'hx-trigger="every 3s"')
_STATUS_BADGE = re.compile(r"badge-(completed|running|pending|failed|partial|cancelled)\b")


def job_status(html: str) -> str:
    """The job's status from a status-partial, or "pending" while it is still polling."""
    if _STILL_POLLING.search(html):
        return "pending"
    match = _STATUS_BADGE.search(html)
    if not match:
        # No poll trigger and no badge means this is not a status partial at all.
        raise SystemExit("the status partial carries neither a poll trigger nor a status badge")
    status = match.group(1)
    return status if status in TERMINAL_JOB_STATUSES else "pending"


def findings_count(body: str) -> int:
    """How many findings `/jobs/{id}/findings.json` reports. An unreadable body is zero."""
    try:
        findings = json.loads(body)
    except ValueError:
        return 0
    return len(findings) if isinstance(findings, list) else 0


def health_version(document: str) -> str:
    """The `version` field of a /health body.

    Its own reader rather than a grep in the shell: the upgrade rehearsal asserts on this
    exact string, and `grep -o '"version":"[^"]*"'` gets the answer wrong the moment the
    server pretty-prints or reorders the document.
    """
    try:
        return str(json.loads(document).get("version", ""))
    except (ValueError, AttributeError):
        return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    pick = sub.add_parser("workflow-id", help="print the id of a workflow accepting --log-type")
    pick.add_argument("--log-type", default="syslog")

    sub.add_parser("job-status", help="print a job's status from its status-partial HTML")
    sub.add_parser("findings-count", help="print how many findings a findings.json body holds")
    sub.add_parser("health-version", help="print the version field of a /health body")

    args = parser.parse_args()
    document = sys.stdin.read()

    if args.command == "workflow-id":
        print(workflow_id(document, args.log_type))
    elif args.command == "job-status":
        print(job_status(document))
    elif args.command == "health-version":
        print(health_version(document))
    else:
        print(findings_count(document))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
