"""Event stores at a local path for the web tier's engine. Blocking; call from a threadpool.

On local storage a store is already on disk and is used where it lies. On S3 it is
downloaded once into `.events_cache/stores/{sha256}/{gen}/` and kept, least recently opened
out first past `EVENTS_CACHE_MAX_MB`. A download lands in a `.part` directory and is moved
into place only after `validate_manifest` passes, so a half-fetched store is never read.

A store is immutable for its generation, so a cached copy never goes stale. A job's overlay
is not — it is rebuilt when the job is re-analysed — so cached overlays are keyed by the
overlay's own tag (its links digest) and a rebuilt overlay is simply a new directory.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

from app.events.manifest import MANIFEST, ManifestError, validate_manifest

logger = logging.getLogger(__name__)

OVERLAY_FILES = ("hits.parquet", "levels.parquet", "overlay.json")
#: A store touched this recently is assumed in use by another request and never trimmed.
_IN_USE_GRACE_SECONDS = 300
_TAG = re.compile(r"^[0-9a-f]{1,64}$")
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()
_in_use: Counter[str] = Counter()


def cache_root() -> Path:
    from app.config import settings

    return Path(settings.upload_dir).resolve() / ".events_cache"


def _lock(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _touch(path: Path) -> None:
    with contextlib.suppress(OSError):
        os.utime(path)


@contextlib.contextmanager
def store_dir(sha256: str, gen: str):
    """The store's local directory for the duration of the block."""
    from app.storage import event_store_prefix, get_storage

    prefix = event_store_prefix(sha256, gen)  # validates both parts before any path is built
    direct = get_storage().event_store_dir_sync(sha256, gen)
    if direct is not None:
        yield direct.resolve()
        return
    target = cache_root() / "stores" / sha256 / gen
    with _locks_guard:
        _in_use[prefix] += 1
    try:
        with _lock(prefix):
            if not (target / MANIFEST).is_file():
                _download_store(sha256, gen, target)
        _touch(target / MANIFEST)
        yield target
    finally:
        with _locks_guard:
            _in_use[prefix] -= 1
            if _in_use[prefix] <= 0:
                del _in_use[prefix]
    trim()


def is_local_or_cached(sha256: str, gen: str) -> bool:
    """Whether opening the store now would be quick: on this disk, or already fetched."""
    from app.storage import get_storage

    if get_storage().event_store_dir_sync(sha256, gen) is not None:
        return True
    return (cache_root() / "stores" / sha256 / gen / MANIFEST).is_file()


_prefetching: set[str] = set()


def prefetch(sha256: str, gen: str) -> None:
    """Start fetching a store in the background (at most once at a time); the page polls."""
    from app.storage import event_store_prefix

    key = event_store_prefix(sha256, gen)
    with _locks_guard:
        if key in _prefetching:
            return
        _prefetching.add(key)

    def run() -> None:
        try:
            with store_dir(sha256, gen):
                pass
        except Exception:
            logger.warning("Event store %s/%s: background fetch failed", sha256, gen, exc_info=True)
        finally:
            with _locks_guard:
                _prefetching.discard(key)

    threading.Thread(target=run, name=f"events-prefetch-{gen}", daemon=True).start()


def _download_store(sha256: str, gen: str, target: Path) -> None:
    from app.json_utils import load_file
    from app.storage import get_storage

    st = get_storage()
    part = target.parent / f".{gen}.{uuid.uuid4().hex}.part"
    part.mkdir(parents=True, exist_ok=True)
    try:
        st.fetch_event_store_file_sync(sha256, gen, MANIFEST, part)
        manifest = load_file(part / MANIFEST)
        for entry in manifest.get("files") or []:
            name = entry.get("name")
            if isinstance(name, str) and "/" not in name and not name.startswith(".") and name != MANIFEST:
                st.fetch_event_store_file_sync(sha256, gen, name, part)
        validate_manifest(part)
        shutil.rmtree(target, ignore_errors=True)
        os.replace(part, target)
    except (ManifestError, OSError):
        logger.warning("Event store %s/%s could not be fetched intact", sha256, gen, exc_info=True)
        raise
    finally:
        shutil.rmtree(part, ignore_errors=True)


def overlay_dir(sha256: str, gen: str, job_id: int, tag: str) -> Path | None:
    """A job's overlay at a local path, or None when it has not been built."""
    from app.storage import event_store_prefix, get_storage

    prefix = event_store_prefix(sha256, gen)
    st = get_storage()
    direct = st.event_store_dir_sync(sha256, gen)
    if direct is not None:
        path = direct / "overlays" / f"job_{int(job_id)}"
        return path.resolve() if (path / "levels.parquet").is_file() else None
    if not _TAG.match(tag or ""):
        return None
    target = cache_root() / "stores" / sha256 / gen / "overlays" / f"job_{int(job_id)}-{tag}"
    with _lock(f"{prefix}/job_{int(job_id)}"):
        if (target / "levels.parquet").is_file():
            return target
        part = target.parent / f".{target.name}.{uuid.uuid4().hex}.part"
        try:
            for name in OVERLAY_FILES:
                if st.fetch_overlay_file_sync(sha256, gen, job_id, name, part) is None:
                    return None
            for stale in target.parent.glob(f"job_{int(job_id)}-*"):
                shutil.rmtree(stale, ignore_errors=True)
            os.replace(part, target)
        finally:
            shutil.rmtree(part, ignore_errors=True)
    return target


def trim(max_bytes: int | None = None) -> int:
    """Delete cached stores, least recently opened first, until under the cap. Returns bytes freed."""
    if max_bytes is None:
        from app.config import settings

        max_bytes = int(settings.events_cache_max_mb) << 20
    root = cache_root() / "stores"
    if not root.is_dir():
        return 0
    stores = []
    for sha_dir in root.iterdir():
        for gen_dir in sha_dir.iterdir() if sha_dir.is_dir() else ():
            if gen_dir.name.startswith(".") or not (gen_dir / MANIFEST).is_file():
                continue
            size = sum(f.stat().st_size for f in gen_dir.rglob("*") if f.is_file())
            stores.append(((gen_dir / MANIFEST).stat().st_mtime, size, sha_dir.name, gen_dir))
    total = sum(size for _m, size, _s, _d in stores)
    freed = 0
    now = time.time()
    for mtime, size, sha, gen_dir in sorted(stores):
        if total <= max_bytes:
            break
        if _in_use.get(f"events/{sha}/{gen_dir.name}") or now - mtime < _IN_USE_GRACE_SECONDS:
            continue
        shutil.rmtree(gen_dir, ignore_errors=True)
        total -= size
        freed += size
    return freed
