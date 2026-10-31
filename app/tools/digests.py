"""Content digests and cheap change detection for vendored engine assets.

Stdlib only: `scripts/detection_tools.py` imports this before PDM is installed.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


def file_digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_digest(path: Path) -> str:
    """Include filenames as well as content, so missing/renamed rules are detected."""
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(file.relative_to(path)).encode())
        digest.update(b"\0")
        digest.update(file_digest(file).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def stat_fingerprint(path: Path) -> tuple | None:
    """Names, sizes and timestamps, read without opening a file; None when unreadable.

    Names are relative to *path*, so `tools/x/rules` and its absolute spelling agree.
    `st_ctime_ns` is in it because only the kernel sets it: a copy that preserves
    mtimes (`rsync -a`, an archive extract) still changes it. `os.scandir`, not
    pathlib: over ~5,000 rule files `Path.relative_to` alone cost half a second.
    """
    try:
        if not path.is_dir():
            st = path.stat()
            return (("", st.st_size, st.st_mtime_ns, st.st_ctime_ns),)
        found: list[tuple] = []
        _scan(str(path), "", found)
        return tuple(sorted(found))
    except OSError:
        return None


def _scan(directory: str, prefix: str, found: list[tuple]) -> None:
    with os.scandir(directory) as entries:
        for entry in entries:
            name = prefix + entry.name
            if entry.is_dir(follow_symlinks=False):
                _scan(entry.path, name + "/", found)
            elif entry.is_file():
                st = entry.stat()
                found.append((name, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
