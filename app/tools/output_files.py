"""Raw tool outputs at rest: zstd-compressed once the job is done, read the same either way.

The outputs were 1.51 GiB in development, 2.7x the uploads, and zstd level 3 took one job's
from 276 MB to 7 MB (Hayabusa 37x, Chainsaw 52x, Zircolite 31x, rsigma 57x). A compressed
file keeps its name plus `.zst` (`x_hayabusa.json.zst`), so every suffix match goes through
`logical_name` and every read through `open_output`, which sniffs the frame magic rather
than trusting the name. Pure: no app imports beyond the zstd shim and the tool catalog.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import BinaryIO

from app.compression_utils import DEFAULT_LEVEL, open_read, open_write

logger = logging.getLogger(__name__)

ZST_SUFFIX = ".zst"
_PART_SUFFIX = ".zst.part"
_COPY_BUFFER = 1 << 20


def logical_name(name: str) -> str:
    """The name a tool wrote, without the `.zst` the compression step adds."""
    return name[: -len(ZST_SUFFIX)] if name.lower().endswith(ZST_SUFFIX) else name


def is_tool_output(name: str) -> bool:
    from app.tools.catalog import output_tool

    return output_tool(name) is not None


def open_output(path: Path) -> BinaryIO:
    """The output's content, decompressed if it is a zstd frame, whatever its name says."""
    return open_read(path)


def compress_output_file(path: Path, *, level: int = DEFAULT_LEVEL) -> int:
    """Replace *path* by `<path>.zst`; return the bytes saved (0 when left as it was).

    Written to a `.zst.part` sibling, fsynced, then renamed over, so a crash leaves either the
    plain file or the finished frame and never a truncated one under the final name. The
    plaintext is removed only after the rename.
    """
    if path.name.lower().endswith(ZST_SUFFIX) or not path.is_file():
        return 0
    target = path.with_name(path.name + ZST_SUFFIX)
    part = path.with_name(path.name + _PART_SUFFIX)
    try:
        with path.open("rb") as source, open_write(part, level=level) as sink:
            while chunk := source.read(_COPY_BUFFER):
                sink.write(chunk)
        with part.open("rb") as written:
            os.fsync(written.fileno())
        os.replace(part, target)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    before, after = path.stat().st_size, target.stat().st_size
    path.unlink()
    return max(0, before - after)


def compress_job_outputs(job_dir: Path) -> tuple[int, int]:
    """Compress every plain tool output under *job_dir*. Never raises; returns (files, bytes saved).

    A failure on one file leaves that file plain and readable and moves on: an output that
    stays uncompressed costs disk, while one lost would cost the job's analytics and export.
    """
    files, saved = 0, 0
    if not job_dir.is_dir():
        return files, saved
    for path in sorted(job_dir.rglob("*")):
        if not path.is_file() or path.name.lower().endswith((ZST_SUFFIX, _PART_SUFFIX)) or not is_tool_output(path.name):
            continue
        try:
            saved += compress_output_file(path)
            files += 1
        except Exception:
            logger.warning("Could not compress %s; left as it was", path, exc_info=True)
    return files, saved
