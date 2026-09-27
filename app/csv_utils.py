"""CSV cell defusing, shared by every export that a spreadsheet opens.

It lives here rather than in the router that first needed it because the second caller is
`routers/intel.py`, and a router importing a router is how this codebase gets an import
cycle. Pure — the same reason `json_utils.py` is.
"""

from __future__ import annotations

#: Spreadsheets evaluate a cell beginning with any of these. Exported cells are attacker-
#: influenced — the activity log's `summary` can hold a submitted filename or an attempted
#: username, and an `Entity.value` of type user/computer/service/task comes off an upload
#: with no charset constraint at all — so an export opened in Excel is a code-execution
#: path unless the leading character is defused.
CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """Neutralise a spreadsheet formula without changing what the text says."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(CSV_FORMULA_LEADERS) else text
