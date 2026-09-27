#!/usr/bin/env python3
"""Consistent SQLite snapshot: ``python3 scripts/sqlite_snapshot.py SRC DST``.

Used by ``scripts/backup.sh`` on hosts without the ``sqlite3`` CLI, where the snapshot
is taken inside the web container (which always has Python). Stdlib only — the image
runs this before any application dependency is guaranteed importable.

This lives in a file rather than inline in a shell heredoc so that it is directly
testable, because the call is easy to get backwards. Python's contract is
``source.backup(target)`` — it copies *from* the connection the method is called on. The
reversed form

    sqlite3.connect(dst).backup(sqlite3.connect(src))

writes the newly created, empty destination into the live database, destroying the data
it was asked to protect and leaving an empty artifact that still passes
``PRAGMA integrity_check``.
"""

from __future__ import annotations

import sqlite3
import sys


def snapshot(src: str, dst: str) -> int:
    """Copy the database at *src* to *dst*. Returns the artifact's schema-object count."""
    with sqlite3.connect(f"file:{src}?mode=ro", uri=True) as source, sqlite3.connect(dst) as target:
        source.backup(target)
    with sqlite3.connect(f"file:{dst}?mode=ro", uri=True) as check:
        return int(check.execute("SELECT count(*) FROM sqlite_master").fetchone()[0])


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} SRC DST", file=sys.stderr)
        return 2
    src, dst = argv[1], argv[2]
    try:
        objects = snapshot(src, dst)
    except sqlite3.Error as exc:
        print(f"ERROR: could not snapshot {src}: {exc}", file=sys.stderr)
        return 1
    print(f"Backup written to {dst} ({objects} schema objects)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
