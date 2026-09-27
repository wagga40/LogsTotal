"""The one colour decision, on the Python side of the tooling.

`scripts/lib/common.sh` resolves a palette once at source time — a TTY, no `NO_COLOR`,
`TERM` not `dumb` — and **exports the answer as `LT_COLOR`** precisely so a subprocess
does not get to form a second opinion. An `isatty()` inside a helper cannot see the
caller's redirection: `./logstotal deploy:plan > plan.txt` reaches `deploy_config_review.py` on
a pipe either way, but `./logstotal doctor | less` reaches `doctor.py` on a pipe too, and only
the shell knows which of those the operator meant.

Stdlib only, and importable as a sibling — `python3 scripts/doctor.py` puts `scripts/`
first on `sys.path`, and `deploy_fleet_env.py` already imports `gen_secrets` and
`proxy_enable` this way. Nothing here imports the application: several of these helpers
run inside the container with no venv, and one of them (`doctor.py`) is the thing you
run *because* the application will not start.

Usage:

    from cli_color import colors

    c = colors()                      # honours LT_COLOR, then NO_COLOR/TERM, then isatty
    print(f"{c['bold']}Fleet configuration{c['off']}")

The keys are fixed and every one of them always exists, so a call site never guards:
switched off, they are all the empty string and the same f-string renders plain.
"""

from __future__ import annotations

import os
import sys

# The shell palette's five colours plus `dim`, which only the Python side uses (the
# provenance column). Deliberately the same escapes as scripts/lib/common.sh — a review
# rendered by a helper sits directly under lines printed by its caller.
PALETTE = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "off": "\033[0m",
}

OFF = dict.fromkeys(PALETTE, "")


def supports_color(mode: str | None = None, stream=None) -> bool:
    """Resolve `always` / `never` / `auto` (the default) to a yes or a no.

    `auto` asks, in order: `LT_COLOR` from the shell, then this process's own reading of
    `NO_COLOR` / `TERM=dumb` / `isatty()`. The environment variable comes FIRST because
    it is the more informed answer — the shell saw the redirection.
    """
    if mode is None or mode == "auto":
        mode = os.environ.get("LT_COLOR", "auto")
    if mode == "always":
        return True
    if mode == "never":
        return False
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    # A stream with no isatty() at all (a StringIO in a test, a captured buffer) is not a
    # terminal. getattr rather than a try/except so the answer is the same either way.
    return bool(getattr(stream, "isatty", lambda: False)())


def colors(mode: str | None = None, stream=None) -> dict[str, str]:
    """The palette, or an all-empty one with the same keys. Never raises, never None."""
    return PALETTE if supports_color(mode, stream) else OFF
