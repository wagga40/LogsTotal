"""zstd for data at rest: the stdlib `compression.zstd` on Python 3.14, its backport before.

Pure, with no app imports, so the worker, the web tier and the tool adapters can all use it.
Every reader sniffs the 4-byte zstd frame magic instead of trusting a file name, so a
plaintext file and a compressed one read the same way during a migration in either direction.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import BinaryIO

try:
    from compression import zstd
except ImportError:  # Python < 3.14: the same API from the backport
    from backports import zstd  # type: ignore[no-redef]

#: The zstd frame magic number, little-endian 0xFD2FB528.
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
#: Measured on real tool output (job 12): level 3 took a 203 MB Hayabusa file to 5.5 MB in
#: 0.26 s; higher levels cost time for a few percent.
DEFAULT_LEVEL = 3
_READ_BUFFER = 1 << 20


def compress(data: bytes, level: int = DEFAULT_LEVEL) -> bytes:
    return zstd.compress(data, level=level)


def decompress(data: bytes) -> bytes:
    return zstd.decompress(data)


def is_zstd(prefix: bytes) -> bool:
    return prefix[:4] == ZSTD_MAGIC


def is_zstd_file(path: str | Path) -> bool:
    with open(path, "rb") as stream:
        return is_zstd(stream.read(4))


def open_read(path: str | Path) -> BinaryIO:
    """A binary stream of the file's content, decompressed when it is a zstd frame."""
    if is_zstd_file(path):
        return io.BufferedReader(zstd.ZstdFile(path, "rb"), _READ_BUFFER)  # type: ignore[arg-type]
    return open(path, "rb")


def open_write(path: str | Path, *, level: int = DEFAULT_LEVEL, threads: int = 0) -> BinaryIO:
    """A binary stream that writes a zstd frame. `threads` > 0 compresses on worker threads."""
    options = {zstd.CompressionParameter.compression_level: level}
    if threads > 0:
        options[zstd.CompressionParameter.nb_workers] = threads
    return zstd.ZstdFile(path, "wb", options=options)  # type: ignore[return-value]
