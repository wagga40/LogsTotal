"""Pure-text utility functions for Huey workers — no Huey/Redis/DB imports."""

from __future__ import annotations

import re

# Strip ANSI escape sequences (colors, cursor movement, etc.) from tool output
_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


def _combine_logs(stdout: str, stderr: str, max_bytes: int = 0) -> str:
    stdout = _strip_ansi(stdout)
    stderr = _strip_ansi(stderr)
    parts = []
    if stdout.strip():
        parts.append(f"=== stdout ===\n{stdout.rstrip()}")
    if stderr.strip():
        parts.append(f"=== stderr ===\n{stderr.rstrip()}")
    combined = "\n\n".join(parts) if parts else ""
    if max_bytes and len(combined) > max_bytes:
        combined = "...[truncated]...\n" + combined[-max_bytes:]
    return combined


def humanbytes(value) -> str:
    """`524288` -> `512.0 KB`. The worker's copy of the Jinja filter.

    Duplicated rather than imported from `templates_config`, deliberately: that module
    builds a Jinja environment and pulls in the whole web tier, which a Huey task must not
    do. Two small implementations beat one import that drags a template engine into the
    worker — the same reasoning behind `app/workers/utils.py` existing at all.
    """
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    if size < 1024:
        return f"{int(size)} B"
    for unit in ("KB", "MB", "GB", "TB"):
        size /= 1024
        if size < 1024:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} PB"


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    """`1 directory` / `2 directories`. Reporting "1 directories" reads as a bug."""
    word = singular if count == 1 else (plural_form or singular + "s")
    return f"{count} {word}"
