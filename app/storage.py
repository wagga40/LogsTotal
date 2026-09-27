"""Storage backends for uploaded log files.

LocalStorage: reads/writes directly to settings.upload_dir (default).
S3Storage: uses boto3 to PUT/GET from any S3-compatible endpoint (Garage, SeaweedFS, AWS S3, etc.).
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import tempfile
import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from starlette.concurrency import run_in_threadpool

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredObject:
    """One stored object: its key relative to the backend root, its size, its mtime.

    `mtime` is a float epoch rather than a datetime because it comes straight from
    `os.stat` on one side and `LastModified` on the other, and the only consumer compares
    it against an age threshold.
    """

    key: str
    size: int
    mtime: float


class StorageBackend(ABC):
    @abstractmethod
    async def save(self, filename: str, data: AsyncIterator[bytes]) -> str:
        """Save file content and return the stored filename."""

    @abstractmethod
    async def load(self, filename: str) -> Path:
        """Return a local Path to the file (downloads to temp if remote)."""

    @abstractmethod
    def load_sync(self, filename: str) -> Path:
        """Sync version of load() for Huey workers."""

    def release_sync(self, path: Path) -> None:
        """Drop a local copy produced by :meth:`load_sync`, if it was a temporary one.

        No-op on local disk, where the path *is* the stored file. On S3 it reclaims the
        download cache entry: without this a worker keeps a permanent copy of every log
        it has ever analysed, which defeats the point of the object store and fills the
        worker's disk with nothing to prune it.
        """

    @abstractmethod
    async def save_path(self, filename: str, local_path: Path) -> str:
        """Store an already-materialised local file under *filename*, consuming it.

        The upload route spools the request body to a temp file to hash and type-detect it
        before deciding anything. Feeding that file back through ``save()`` as an async
        iterator would read and write every byte a second time, on the event loop — a
        500 MB upload blocking the 3s job-status polls and /health for the duration.
        Backends can do far better with a path: local disk renames it, S3 hands the path
        straight to boto3 in a threadpool.

        ``local_path`` must not be used by the caller afterwards.
        """

    @abstractmethod
    async def delete(self, filename: str) -> None:
        """Delete a stored file."""

    @abstractmethod
    def delete_sync(self, filename: str) -> None:
        """Sync version of delete() for Huey workers."""

    @abstractmethod
    def exists_sync(self, filename: str) -> bool:
        """Check if a file exists (sync, for workers)."""

    def sync_job_outputs_from_worker(self, job_id: int, local_root: Path) -> None:
        """After analysis, mirror tool output files to remote storage (S3 only). No-op on local disk."""

    @abstractmethod
    async def resolve_job_outputs_dir(self, job_id: int) -> tuple[Path, bool] | None:
        """Directory tree of raw tool outputs for ZIP export, or None.

        Returns ``(root_path, cleanup)`` — if ``cleanup`` is True, delete ``root_path`` after use.
        """

    @abstractmethod
    def resolve_job_outputs_dir_sync(self, job_id: int) -> tuple[Path, bool] | None:
        """Blocking twin of :meth:`resolve_job_outputs_dir` — the ``load``/``load_sync`` pair.

        Every consumer of a job's raw output must come through here rather than reaching
        into ``settings.upload_dir`` itself. On the S3 backend the worker uploads the tree
        and then **removes its local copy**, and in a multi-server layout the worker is a
        different machine from the web tier anyway — so a direct filesystem read finds
        nothing, silently, and the surface renders its own empty state — a process tree
        blank on every S3 deployment while working perfectly on local disk.

        Blocking on both backends (S3 lists and downloads every output file), so web-tier
        callers must go through ``run_in_threadpool``.
        """

    @abstractmethod
    def delete_job_outputs_sync(self, job_id: int) -> bool:
        """Remove stored tool outputs for a job. Returns True if anything was removed."""

    @abstractmethod
    def iter_objects_sync(self, prefix: str | None = None) -> Iterator[StoredObject]:
        """Every stored object, as ``(key, size_bytes, mtime_epoch)``.

        The *only* enumeration method on this interface, deliberately. Totals, per-job
        usage and orphan detection all derive from it in `app/storage_usage.py`, so a new
        backend implements one method rather than four — and no general "delete this
        prefix" primitive exists here, because a prefix delete on a bucket that also holds
        every uploaded log is a footgun. Removal stays `delete_job_outputs_sync` (narrow,
        by job id) and `delete_sync` (one known filename).

        Blocking on both backends: a local walk, and one S3 round trip per 1,000 keys.
        Callers in the web tier must go through `run_in_threadpool`.
        """


class LocalStorage(StorageBackend):
    def __init__(self) -> None:
        self._dir = settings.upload_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    async def save(self, filename: str, data: AsyncIterator[bytes]) -> str:
        # The write itself is blocking, but the awaits between chunks yield the loop, so
        # this streams rather than stalling. `save_path` is the better entry point when
        # the caller already has the bytes on disk.
        path = self._dir / filename
        with open(path, "wb") as f:
            async for chunk in data:
                await run_in_threadpool(f.write, chunk)
        return filename

    async def save_path(self, filename: str, local_path: Path) -> str:
        return await run_in_threadpool(self._move_into_place, filename, local_path)

    def _move_into_place(self, filename: str, local_path: Path) -> str:
        target = self._dir / filename
        try:
            # Same filesystem: a rename, so a 500 MB upload costs no I/O at all.
            os.replace(local_path, target)
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                # Only a cross-device rename is worth a second attempt. ENAMETOOLONG or
                # ENOSPC fail identically through `copyfile`, one whole file later, with the
                # copy's error hiding the rename's.
                raise
            # Different filesystem (a /tmp on tmpfs is the usual case). Copy, then drop
            # the source — `shutil.move` would do both but hides which half failed.
            shutil.copyfile(local_path, target)
            Path(local_path).unlink(missing_ok=True)
        return filename

    async def load(self, filename: str) -> Path:
        return self._dir / filename

    def load_sync(self, filename: str) -> Path:
        return self._dir / filename

    async def delete(self, filename: str) -> None:
        (self._dir / filename).unlink(missing_ok=True)

    def delete_sync(self, filename: str) -> None:
        (self._dir / filename).unlink(missing_ok=True)

    def exists_sync(self, filename: str) -> bool:
        return (self._dir / filename).exists()

    async def resolve_job_outputs_dir(self, job_id: int) -> tuple[Path, bool] | None:
        return self.resolve_job_outputs_dir_sync(job_id)

    def resolve_job_outputs_dir_sync(self, job_id: int) -> tuple[Path, bool] | None:
        # Cheap enough to share with the async form: two stats and a walk over a directory
        # the caller is about to read anyway. `cleanup` is False — this *is* the live tree,
        # not a copy, and removing it would delete the job's output.
        root = self._dir / f"job_{job_id}"
        if not root.is_dir():
            return None
        if not any(p.is_file() for p in root.rglob("*")):
            return None
        return (root, False)

    def delete_job_outputs_sync(self, job_id: int) -> bool:
        target = self._dir / f"job_{job_id}"
        existed = target.is_dir()
        shutil.rmtree(target, ignore_errors=True)
        return existed

    def iter_objects_sync(self, prefix: str | None = None) -> Iterator[StoredObject]:
        root = self._dir / prefix if prefix else self._dir
        if not root.exists():
            return
        # `os.walk` over `rglob` because it gives directory names for free, which is what
        # lets the caller skip `.s3_cache` without stat-ing everything inside it.
        for dirpath, _dirnames, filenames in os.walk(root):
            base = Path(dirpath)
            for name in filenames:
                path = base / name
                try:
                    stat = path.stat()
                except OSError:
                    # A file removed between the walk and the stat — a cleanup running
                    # concurrently is normal, not an error.
                    continue
                yield StoredObject(key=str(path.relative_to(self._dir)), size=stat.st_size, mtime=stat.st_mtime)


class S3Storage(StorageBackend):
    def __init__(self) -> None:
        import boto3
        from botocore.config import Config as BotoConfig

        self._bucket = settings.s3_bucket
        session = boto3.session.Session()
        self._s3 = session.client(
            "s3",
            endpoint_url=settings.s3_endpoint,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name=settings.s3_region,
            config=BotoConfig(
                signature_version="s3v4",
                connect_timeout=10,
                read_timeout=60,
                retries={"max_attempts": 3, "mode": "adaptive"},
            ),
        )
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            self._s3.head_bucket(Bucket=self._bucket)
        except Exception:
            logger.warning("S3 bucket '%s' not found, attempting to create it", self._bucket)
            try:
                self._s3.create_bucket(Bucket=self._bucket)
            except Exception:
                logger.warning("Failed to create S3 bucket '%s' — uploads will fail if it doesn't exist", self._bucket, exc_info=True)

    async def save(self, filename: str, data: AsyncIterator[bytes]) -> str:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".upload")  # noqa: SIM115  # path handed to caller; closed below in try/finally
        tmp_path = Path(tmp.name)
        try:
            async for chunk in data:
                await run_in_threadpool(tmp.write, chunk)
            tmp.close()
            # boto3 blocks for the whole network upload — on the event loop that is the
            # single longest stall the web tier can take. `load()` below threadpools for the
            # same reason.
            await run_in_threadpool(self._s3.upload_file, str(tmp_path), self._bucket, filename)
        finally:
            tmp_path.unlink(missing_ok=True)
        return filename

    async def save_path(self, filename: str, local_path: Path) -> str:
        try:
            await run_in_threadpool(self._s3.upload_file, str(local_path), self._bucket, filename)
        finally:
            Path(local_path).unlink(missing_ok=True)
        return filename

    async def load(self, filename: str) -> Path:
        # boto3 is blocking, and this runs inside request handlers (job download, raw
        # export). Left on the event loop it stalls every other request — including the
        # 3s job-status polls and /health — for the length of the download.
        return await run_in_threadpool(self._download, filename)

    def load_sync(self, filename: str) -> Path:
        return self._download(filename)

    def _cache_dir(self) -> Path:
        return settings.upload_dir / ".s3_cache"

    def _download(self, filename: str) -> Path:
        """Download to a caller-private directory under the cache.

        The per-download prefix matters: every caller pairs `load_sync` with
        `release_sync`, which unlinks the path unconditionally. With one fixed path per
        filename, two jobs analysing the *same* upload — routine, since `/upload`
        deduplicates by sha256 across workflows, users and force-resubmit, and
        `/jobs/{id}/resubmit` reuses the row — would share it, and whichever finished first
        would delete the input out from under the other mid-run. Isolating the copies is
        cheaper than reference-counting and cannot go wrong under a crash.
        """
        cache_dir = self._cache_dir() / f"{os.getpid()}-{uuid.uuid4().hex}"
        local_path = cache_dir / filename
        local_path.parent.mkdir(parents=True, exist_ok=True)
        self._s3.download_file(self._bucket, filename, str(local_path))
        return local_path

    def release_sync(self, path: Path) -> None:
        """Delete a `.s3_cache` download once the caller is done with it.

        Removes the per-download directory `_download` created, not just the file, so the
        prefix directories do not accumulate forever. Guarded to paths inside the cache
        directory so a mistaken call can never remove a real upload (the local backend
        hands back the stored file itself).
        """
        try:
            cache_dir = self._cache_dir().resolve()
            resolved = Path(path).resolve()
            if not resolved.is_relative_to(cache_dir):
                return
            resolved.unlink(missing_ok=True)
            # Walk back up to (but never including) the cache root, removing the now-empty
            # per-download directories. rmdir only succeeds on an empty directory, so this
            # cannot take anything else with it.
            parent = resolved.parent
            while parent != cache_dir and parent.is_relative_to(cache_dir):
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent
        except OSError:
            logger.warning("Could not reclaim S3 cache entry %s", path, exc_info=True)

    async def delete(self, filename: str) -> None:
        self._s3.delete_object(Bucket=self._bucket, Key=filename)

    def delete_sync(self, filename: str) -> None:
        self._s3.delete_object(Bucket=self._bucket, Key=filename)

    def exists_sync(self, filename: str) -> bool:
        try:
            self._s3.head_object(Bucket=self._bucket, Key=filename)
            return True
        except Exception:
            return False

    def sync_job_outputs_from_worker(self, job_id: int, local_root: Path) -> None:
        """Upload a job's tool outputs to S3, then reclaim the worker's local copy.

        With an object-store backend the worker's copy is a staging area, not the system
        of record, and left in place every job permanently grows the worker's disk.
        ``cleanup_old_job_outputs`` does not help: it runs on the web tier against
        ``upload_dir``, not on each worker. The tree is kept when any file failed to upload,
        so a transient S3 error cannot silently destroy the only copy.
        """
        if not local_root.is_dir():
            return
        prefix = f"job_{job_id}/"
        failed = 0
        for path in local_root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(local_root)
            key = prefix + str(rel).replace("\\", "/")
            try:
                self._s3.upload_file(str(path), self._bucket, key)
            except Exception as exc:
                failed += 1
                logger.warning("Failed to upload job output %s: %s", key, exc)

        if failed:
            logger.warning("Job %s: keeping local outputs at %s — %d file(s) did not reach S3", job_id, local_root, failed)
            return
        try:
            shutil.rmtree(local_root)
        except OSError as exc:
            logger.warning("Job %s: uploaded to S3 but could not remove %s: %s", job_id, local_root, exc)

    async def resolve_job_outputs_dir(self, job_id: int) -> tuple[Path, bool] | None:
        # Listing plus one blocking download per output file. The caller (the raw-export
        # route) already offloads the ZIP build for exactly this reason; leaving the
        # downloads on the loop would stall the whole web process for far longer.
        return await run_in_threadpool(self.resolve_job_outputs_dir_sync, job_id)

    def resolve_job_outputs_dir_sync(self, job_id: int) -> tuple[Path, bool] | None:
        prefix = f"job_{job_id}/"
        paginator = self._s3.get_paginator("list_objects_v2")
        keys: list[str] = []
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                k = obj["Key"]
                if k.endswith("/") or not k.startswith(prefix):
                    continue
                rel = k[len(prefix) :]
                if rel:
                    keys.append(k)
        if not keys:
            return None
        tmp_root = Path(tempfile.mkdtemp(prefix=f"job_{job_id}_raw_"))
        try:
            for key in keys:
                rel = key[len(prefix) :]
                local_path = tmp_root / rel
                local_path.parent.mkdir(parents=True, exist_ok=True)
                self._s3.download_file(self._bucket, key, str(local_path))
            return (tmp_root, True)
        except Exception:
            shutil.rmtree(tmp_root, ignore_errors=True)
            raise

    def delete_job_outputs_sync(self, job_id: int) -> bool:
        prefix = f"job_{job_id}/"
        paginator = self._s3.get_paginator("list_objects_v2")
        removed = False
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if not objs:
                continue
            removed = True
            self._s3.delete_objects(Bucket=self._bucket, Delete={"Objects": objs})
        return removed

    def iter_objects_sync(self, prefix: str | None = None) -> Iterator[StoredObject]:
        """Every object in the bucket, with the size the listing already carries.

        `list_objects_v2` returns `Size` and `LastModified` on every entry — the same
        paginator used two methods above. One network round trip per 1,000 keys, so callers
        must cache and cap.
        """
        paginator = self._s3.get_paginator("list_objects_v2")
        kwargs = {"Bucket": self._bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                last_modified = obj.get("LastModified")
                yield StoredObject(
                    key=obj["Key"],
                    size=int(obj.get("Size") or 0),
                    mtime=last_modified.timestamp() if last_modified else 0.0,
                )


def free_bytes_for_uploads() -> int | None:
    """Free space on the filesystem that accepts an upload, or None if unmeasurable.

    Always the local upload directory, even on the S3 backend: the request body is spooled
    to a temp file there before anything is decided, so the local volume is what an upload
    can exhaust either way.
    """
    try:
        target = settings.upload_dir
        target.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(target).free
    except OSError:
        return None


_storage: StorageBackend | None = None


def get_storage() -> StorageBackend:
    """Return the configured storage backend (lazy singleton)."""
    global _storage
    if _storage is None:
        if settings.storage_backend == "s3":
            missing = [
                name
                for name, val in [
                    ("S3_ENDPOINT", settings.s3_endpoint),
                    ("S3_ACCESS_KEY", settings.s3_access_key),
                    ("S3_SECRET_KEY", settings.s3_secret_key),
                ]
                if not val
            ]
            if missing:
                raise ValueError(f"STORAGE_BACKEND=s3 but required env vars are missing: {', '.join(missing)}")
            _storage = S3Storage()
        else:
            _storage = LocalStorage()
    return _storage


@contextmanager
def job_outputs_dir(job_id: int):
    """A job's raw-output directory, wherever the backend keeps it, cleaned up after.

    The one way to read a job's tool output. Yields ``None`` when there is none, which the
    readers in ``app/intel/event_timeline.py`` already treat as "nothing to parse", so a
    caller needs no special case.

    It lives here rather than beside its first caller because it is a storage question, and
    skipping it fails quietly: a reader that builds ``settings.upload_dir / f"job_{id}"``
    itself finds nothing on S3, where the worker uploads the tree and removes its local copy
    — or in a multi-server layout, where the worker is a different machine — so it reports
    "no raw output" and the surface renders its own empty state. It looks like missing
    data, not a bug.

    The cleanup is a ``finally``: the S3 backend hands back a temp copy of a whole job's
    output, and a parse that raises would otherwise leave it in the container until restart.

    Blocking on both backends. Web-tier callers must already be inside ``run_in_threadpool``.
    """
    resolved = None
    try:
        resolved = get_storage().resolve_job_outputs_dir_sync(job_id)
    except Exception:  # a storage outage degrades to the empty state, never a 500
        logger.warning("Job %s: could not resolve its raw output directory", job_id, exc_info=True)
    if resolved is None:
        yield None
        return
    root, cleanup = resolved
    try:
        yield root
    finally:
        if cleanup:
            shutil.rmtree(root, ignore_errors=True)
