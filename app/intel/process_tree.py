"""Loading a job's process forest — the one place the cache and the threadpool hop live.

`app/intel/lineage.py` stays pure (no I/O at all). This module is the thin impure layer
around it: read the cache, otherwise parse the job's raw tool output off disk and build,
then write the cache back. `live_enrichment.py` and `rules.py` set the same precedent —
an `app/intel/` module may do I/O as long as it does not drag FastAPI or Huey in.

Three surfaces want a job's forest — the job page, the entity
Processes tab, and the case Processes tab — and the invariant they must all keep is easy
to break in a copy: **the closure handed to the threadpool must touch no ORM objects.**
`event_timeline.extract_all_from_raw_output` is blocking disk I/O plus a JSON parse over
every tool output file, so it cannot run on the event loop; and an ORM instance read inside
a worker thread raises `MissingGreenlet` under async SQLAlchemy. Keeping the closure in one
place makes that auditable instead of a rule three call sites have to remember.
"""

from __future__ import annotations

from app.intel.lineage import build_process_forest, prune_to_entity
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.storage import job_outputs_dir

# Bounded because the underlying parse is expensive and a job's raw output does not change
# once it is terminal — five minutes is long enough to cover a page's worth of tab
# switching without pinning a stale tree after a recalculation.
CACHE_TTL_SECONDS = 300

# Bumped whenever the cached shape changes, because on a rolling deploy the old key would
# otherwise serve old-shaped blobs to new code for a whole TTL: a missing node field is a
# KeyError (a 500 for every viewer in the window), a wrong banner, or an entity that
# silently fails to anchor. The TTL is five minutes, so a bump costs at most one extra cold
# build per job.
_CACHE_PREFIX = "logstotal:proctree:v4:"


def _cache_key(job_id: int) -> str:
    return f"{_CACHE_PREFIX}{job_id}"


def _read_cache(job_id: int) -> dict | None:
    """Best-effort; Redis being down must degrade to a rebuild, never to an error."""
    try:
        from app.redis_client import get_redis

        cached = get_redis().get(_cache_key(job_id))
        return json_loads(cached) if cached else None
    except Exception:
        return None


def _write_cache(job_id: int, forest: dict) -> None:
    try:
        from app.redis_client import get_redis

        get_redis().set(_cache_key(job_id), json_dumps(forest), ex=CACHE_TTL_SECONDS)
    except Exception:
        pass


def invalidate(job_id: int) -> None:
    """Drop a job's cached forest — for when its raw output or analytics are rebuilt."""
    try:
        from app.redis_client import get_redis

        get_redis().delete(_cache_key(job_id))
    except Exception:
        pass


def build_job_forest_sync(job_id: int, *, entity_type: str = "", entity_value: str = "") -> dict:
    """The whole blocking path: cache read, parse, build, cache write, optional prune.

    Takes plain values only — an `int` and two `str`s — because this runs in a worker
    thread. Resolve `entity.entity_type` / `entity.value` off the ORM instance *before*
    handing them here.

    The **unfiltered** forest is what gets cached, and the prune runs after. Caching per
    `(job, entity)` would multiply entries without bound for no gain: the prune is pure CPU
    over a dict that is already in memory.
    """
    forest = _read_cache(job_id)
    if forest is None:
        from app.intel.event_timeline import extract_all_from_raw_output

        # Through the storage backend, never straight off `upload_dir`. On S3 the worker
        # uploads the output tree and then deletes its local copy — and in a multi-server
        # layout it is not this machine's disk at all — so a direct read finds nothing and
        # the page renders "no process tree" instead of failing. Blocking (S3 downloads
        # every output file), which is fine: this whole
        # function already runs in a threadpool, and the result is cached for CACHE_TTL_SECONDS,
        # so the download happens once per job per five minutes rather than per request.
        with job_outputs_dir(job_id) as job_dir:
            _buckets, events = extract_all_from_raw_output(job_id, job_dir=job_dir)
        forest = build_process_forest(events)
        _write_cache(job_id, forest)

    if entity_type and entity_value:
        return prune_to_entity(forest, entity_type, entity_value)
    return forest


async def load_job_forest(job_id: int, *, entity_type: str = "", entity_value: str = "") -> dict:
    """Async wrapper — one `run_in_threadpool` hop around `build_job_forest_sync`."""
    from fastapi.concurrency import run_in_threadpool

    return await run_in_threadpool(build_job_forest_sync, job_id, entity_type=entity_type, entity_value=entity_value)
