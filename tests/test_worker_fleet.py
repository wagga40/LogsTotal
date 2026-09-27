"""Tests for multi-server worker validation, fleet visibility, and concurrency slots."""

from __future__ import annotations


def test_multi_server_config_warnings_flag_local_storage_and_sqlite():
    """Multi-worker mode should warn when shared DB/storage are not configured."""
    from app.system_checks import multi_server_config_warnings

    warnings = multi_server_config_warnings(
        compose_profiles="postgres,s3,workers",
        database_url="sqlite+aiosqlite:////data/logstotal.db",
        storage_backend="local",
        redis_expose="10.0.123.1:6379",
        postgres_expose=None,
        garage_expose=None,
    )

    assert any("STORAGE_BACKEND=s3" in warning for warning in warnings)
    assert any("PostgreSQL" in warning for warning in warnings)
    assert any("POSTGRES_EXPOSE" in warning for warning in warnings)
    assert any("GARAGE_EXPOSE" in warning for warning in warnings)


async def test_fetch_worker_data_reads_worker_info(async_db, fake_redis, monkeypatch):
    """Worker fleet data should include process metadata for idle workers."""
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    worker_id = "remote-worker:4242"
    fake_redis.set(f"{WORKER_ALIVE_PREFIX}{worker_id}", "1", ex=180)
    fake_redis.hset(
        f"{WORKER_INFO_PREFIX}{worker_id}",
        mapping={
            "worker_name": "remote-eu-west",
            "hostname": "remote-host",
            "ip_address": "10.0.123.2",
            "jobs_completed": "7",
        },
    )
    fake_redis.expire(f"{WORKER_INFO_PREFIX}{worker_id}", 180)

    data = await _fetch_worker_data(async_db)

    assert len(data["active_workers"]) == 1
    worker = data["active_workers"][0]
    assert worker["worker_id"] == worker_id
    assert worker["worker_name"] == "remote-eu-west"
    assert worker["ip_address"] == "10.0.123.2"
    assert worker["jobs_completed"] == 7
    assert worker["status"] == "idle"
    assert worker["current_job_ids"] == []


async def test_fetch_worker_data_merges_busy_heartbeat(async_db, fake_redis, monkeypatch):
    """A busy worker should merge job heartbeat state onto process metadata."""
    from app.redis_client import HEARTBEAT_PREFIX, WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    worker_id = "remote-worker:4242"
    fake_redis.set(f"{WORKER_ALIVE_PREFIX}{worker_id}", "1", ex=180)
    fake_redis.hset(
        f"{WORKER_INFO_PREFIX}{worker_id}",
        mapping={
            "worker_name": "remote-eu-west",
            "hostname": "remote-host",
            "ip_address": "10.0.123.2",
            "jobs_completed": "3",
        },
    )
    fake_redis.expire(f"{WORKER_INFO_PREFIX}{worker_id}", 180)
    fake_redis.set(f"{HEARTBEAT_PREFIX}42", f"{worker_id}:Worker-1", ex=55)

    data = await _fetch_worker_data(async_db)

    worker = data["active_workers"][0]
    assert worker["status"] == "busy"
    assert "42" in worker["current_job_ids"]
    assert worker["heartbeat_ttl"] > 0
    assert worker["jobs_completed"] == 3


async def test_fetch_worker_data_multi_job_heartbeats(async_db, fake_redis, monkeypatch):
    """Multiple heartbeats for the same process should all appear in current_job_ids."""
    from app.redis_client import HEARTBEAT_PREFIX, WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    worker_id = "multi-worker:5555"
    fake_redis.set(f"{WORKER_ALIVE_PREFIX}{worker_id}", "1", ex=180)
    fake_redis.hset(
        f"{WORKER_INFO_PREFIX}{worker_id}",
        mapping={
            "worker_name": "multi-worker",
            "hostname": "multi-host",
            "ip_address": "10.0.0.5",
            "jobs_completed": "10",
        },
    )
    fake_redis.expire(f"{WORKER_INFO_PREFIX}{worker_id}", 180)

    fake_redis.set(f"{HEARTBEAT_PREFIX}100", f"{worker_id}:Worker-1", ex=50)
    fake_redis.set(f"{HEARTBEAT_PREFIX}101", f"{worker_id}:Worker-2", ex=40)
    fake_redis.set(f"{HEARTBEAT_PREFIX}102", f"{worker_id}:Worker-3", ex=30)

    data = await _fetch_worker_data(async_db)

    assert len(data["active_workers"]) == 1
    worker = data["active_workers"][0]
    assert worker["status"] == "busy"
    assert len(worker["current_job_ids"]) == 3
    assert set(worker["current_job_ids"]) == {"100", "101", "102"}
    assert worker["heartbeat_ttl"] <= 50

    assert "100" in data["heartbeat_map"]
    assert "101" in data["heartbeat_map"]
    assert "102" in data["heartbeat_map"]


async def test_fetch_worker_data_includes_pending_and_running_jobs(async_db, fake_redis, monkeypatch):
    """Worker data should include pending and running job lists."""
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    data = await _fetch_worker_data(async_db)

    assert "pending_jobs" in data
    assert "running_jobs" in data
    assert "heartbeat_map" in data
    assert "huey_queue_size" in data
    assert isinstance(data["pending_jobs"], list)
    assert isinstance(data["running_jobs"], list)


async def test_workers_page_renders_worker_ip(admin_client, fake_redis):
    """The workers page should render the worker name and IP address."""
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX

    worker_id = "remote-worker:4242"
    fake_redis.set(f"{WORKER_ALIVE_PREFIX}{worker_id}", "1", ex=180)
    fake_redis.hset(
        f"{WORKER_INFO_PREFIX}{worker_id}",
        mapping={
            "worker_name": "remote-eu-west",
            "hostname": "remote-host",
            "ip_address": "10.0.123.2",
            "jobs_completed": "7",
        },
    )
    fake_redis.expire(f"{WORKER_INFO_PREFIX}{worker_id}", 180)

    resp = await admin_client.get("/admin/workers")

    assert resp.status_code == 200
    assert "remote-eu-west" in resp.text
    assert "10.0.123.2" in resp.text


async def test_workers_page_pauses_polling_when_priority_dirty(admin_client):
    """Workers page polling should be gated by unsaved priority state."""
    resp = await admin_client.get("/admin/workers")
    assert resp.status_code == 200
    assert 'hx-trigger="every 5s[!window.__workersPriorityDirty]"' in resp.text


# ── Concurrency Slot Tests ────────────────────────────────────────────────────


async def test_fetch_worker_data_includes_max_concurrent_jobs_default(async_db, fake_redis, monkeypatch):
    """Workers with no policy row should have max_concurrent_jobs=0 (unlimited)."""
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-a:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-a:1234", mapping={"hostname": "host-a", "worker_name": "host-a"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-a:1234", 180)

    data = await _fetch_worker_data(async_db)
    assert data["active_workers"][0]["max_concurrent_jobs"] == 0
    assert data["active_workers"][0]["active_slots"] == 0


async def test_fetch_worker_data_reflects_saved_policy(async_db, fake_redis, monkeypatch):
    """Workers with a saved policy should reflect their max_concurrent_jobs."""
    from app.models import WorkerPolicy
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    async_db.add(WorkerPolicy(hostname="host-a", max_concurrent_jobs=4))
    await async_db.commit()

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-a:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-a:1234", mapping={"hostname": "host-a", "worker_name": "host-a"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-a:1234", 180)

    data = await _fetch_worker_data(async_db)
    assert data["active_workers"][0]["max_concurrent_jobs"] == 4


async def test_workers_priority_save_slots(admin_client, async_db, fake_redis):
    """POST /admin/workers/priority should create/update WorkerPolicy with max_concurrent_jobs."""
    from sqlalchemy import select

    from app.models import WorkerPolicy

    resp = await admin_client.post(
        "/admin/workers/priority",
        data={"slots_host-a": "4", "slots_host-b": "-1"},
    )
    assert resp.status_code in (200, 303)

    result = await async_db.execute(select(WorkerPolicy).where(WorkerPolicy.hostname == "host-a"))
    policy = result.scalar_one_or_none()
    assert policy is not None
    assert policy.max_concurrent_jobs == 4

    result_b = await async_db.execute(select(WorkerPolicy).where(WorkerPolicy.hostname == "host-b"))
    policy_b = result_b.scalar_one_or_none()
    assert policy_b is not None
    assert policy_b.max_concurrent_jobs == -1


async def test_workers_priority_clamps_minimum(admin_client, async_db, fake_redis):
    """Slot values below -1 should be clamped to -1."""
    from sqlalchemy import select

    from app.models import WorkerPolicy

    await admin_client.post(
        "/admin/workers/priority",
        data={"slots_host-x": "-5"},
    )

    result_x = await async_db.execute(select(WorkerPolicy).where(WorkerPolicy.hostname == "host-x"))
    assert result_x.scalar_one().max_concurrent_jobs == -1


def test_acquire_slot_unlimited_always_accepts(monkeypatch, fake_redis):
    """max_concurrent_jobs=0 (unlimited) should always accept."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_get_max_concurrent_jobs", lambda: 0)
    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    assert tasks._acquire_job_slot(1) is True
    assert int(fake_redis.get("logstotal:worker_slots:test-host") or "0") == 1


def test_acquire_slot_under_capacity(monkeypatch, fake_redis):
    """Should accept when current slots are below the cap."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_get_max_concurrent_jobs", lambda: 4)
    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    fake_redis.set("logstotal:worker_slots:test-host", "0")

    assert tasks._acquire_job_slot(1) is True
    assert int(fake_redis.get("logstotal:worker_slots:test-host")) == 1


def test_acquire_slot_at_capacity_rejects(monkeypatch, fake_redis):
    """Should reject when at capacity."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_get_max_concurrent_jobs", lambda: 2)
    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    fake_redis.set("logstotal:worker_slots:test-host", "2")

    assert tasks._acquire_job_slot(10) is False


def test_release_slot_decrements(monkeypatch, fake_redis):
    """_release_job_slot should decrement the slot counter."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    fake_redis.set("logstotal:worker_slots:test-host", "3")

    tasks._release_job_slot()
    assert int(fake_redis.get("logstotal:worker_slots:test-host")) == 2


def test_release_slot_floors_at_zero(monkeypatch, fake_redis):
    """_release_job_slot should not go below zero."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    fake_redis.set("logstotal:worker_slots:test-host", "0")

    tasks._release_job_slot()
    assert int(fake_redis.get("logstotal:worker_slots:test-host")) == 0


def test_bounded_deferral_force_accepts(monkeypatch, fake_redis):
    """After _MAX_DEFERRALS rejections, should force-accept the job."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_get_max_concurrent_jobs", lambda: 1)
    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    monkeypatch.setattr(tasks, "_MAX_DEFERRALS", 3)
    fake_redis.set("logstotal:worker_slots:test-host", "1")
    fake_redis.set("logstotal:job_defer:99", "2")

    assert tasks._acquire_job_slot(99) is True


def test_paused_rejects_with_other_workers(monkeypatch, fake_redis):
    """Paused worker (-1) with other live workers should reject."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_get_max_concurrent_jobs", lambda: -1)
    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    fake_redis.set("logstotal:worker:alive:other-host:1", "1", ex=60)
    fake_redis.set("logstotal:worker:alive:other-host:2", "1", ex=60)

    assert tasks._acquire_job_slot(1) is False


def test_paused_accepts_if_only_worker(monkeypatch, fake_redis):
    """Paused worker (-1) should accept if it's the only live worker (deadlock safety)."""
    from app.workers import tasks

    monkeypatch.setattr(tasks, "_get_max_concurrent_jobs", lambda: -1)
    monkeypatch.setattr(tasks, "_hostname", lambda: "test-host")
    fake_redis.set("logstotal:worker:alive:test-host:1", "1", ex=60)

    assert tasks._acquire_job_slot(1) is True


async def test_fetch_worker_data_shows_active_slots(async_db, fake_redis, monkeypatch):
    """Fleet data should show the active slot count from Redis."""
    from app.models import WorkerPolicy
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX, WORKER_SLOTS_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    async_db.add(WorkerPolicy(hostname="host-a", max_concurrent_jobs=8))
    await async_db.commit()

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-a:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-a:1234", mapping={"hostname": "host-a", "worker_name": "host-a"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-a:1234", 180)
    fake_redis.set(f"{WORKER_SLOTS_PREFIX}host-a", "3")

    data = await _fetch_worker_data(async_db)
    worker = data["active_workers"][0]
    assert worker["max_concurrent_jobs"] == 8
    assert worker["active_slots"] == 3


# ── Capacity & Available Slots Tests ─────────────────────────────────────────


async def test_worker_effective_capacity_with_cap_under_threads(async_db, fake_redis, monkeypatch):
    """Cap below thread count: effective_capacity = cap."""
    from app.models import WorkerPolicy
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX, WORKER_SLOTS_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    async_db.add(WorkerPolicy(hostname="host-a", max_concurrent_jobs=2))
    await async_db.commit()

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-a:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-a:1234", mapping={"hostname": "host-a", "worker_name": "host-a", "huey_workers": "4"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-a:1234", 180)
    fake_redis.set(f"{WORKER_SLOTS_PREFIX}host-a", "1")

    data = await _fetch_worker_data(async_db)
    w = data["active_workers"][0]
    assert w["effective_capacity"] == 2
    assert w["available_slots"] == 1


async def test_worker_effective_capacity_cap_bounded_by_threads(async_db, fake_redis, monkeypatch):
    """Cap above thread count: effective_capacity = thread count (can't exceed it)."""
    from app.models import WorkerPolicy
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    async_db.add(WorkerPolicy(hostname="host-a", max_concurrent_jobs=8))
    await async_db.commit()

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-a:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-a:1234", mapping={"hostname": "host-a", "worker_name": "host-a", "huey_workers": "2"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-a:1234", 180)

    data = await _fetch_worker_data(async_db)
    w = data["active_workers"][0]
    assert w["effective_capacity"] == 2
    assert w["available_slots"] == 2


async def test_worker_effective_capacity_unlimited_uses_threads(async_db, fake_redis, monkeypatch):
    """Worker with max_concurrent_jobs=0 (unlimited) should use huey_workers as effective capacity."""
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-b:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-b:1234", mapping={"hostname": "host-b", "worker_name": "host-b", "huey_workers": "4"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-b:1234", 180)

    data = await _fetch_worker_data(async_db)
    w = data["active_workers"][0]
    assert w["max_concurrent_jobs"] == 0
    assert w["effective_capacity"] == 4
    assert w["available_slots"] == 4


async def test_worker_effective_capacity_paused_is_zero(async_db, fake_redis, monkeypatch):
    """Paused worker (-1) should have effective_capacity=0, available_slots=0."""
    from app.models import WorkerPolicy
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    async_db.add(WorkerPolicy(hostname="host-c", max_concurrent_jobs=-1))
    await async_db.commit()

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-c:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-c:1234", mapping={"hostname": "host-c", "worker_name": "host-c"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-c:1234", 180)

    data = await _fetch_worker_data(async_db)
    w = data["active_workers"][0]
    assert w["effective_capacity"] == 0
    assert w["available_slots"] == 0


async def test_fleet_capacity_summary(async_db, fake_redis, monkeypatch):
    """Fleet summary should aggregate capacity across hostnames, bounded by threads."""
    from app.models import WorkerPolicy
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX, WORKER_SLOTS_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    async_db.add(WorkerPolicy(hostname="host-a", max_concurrent_jobs=8))
    async_db.add(WorkerPolicy(hostname="host-b", max_concurrent_jobs=2))
    await async_db.commit()

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-a:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-a:1234", mapping={"hostname": "host-a", "worker_name": "host-a", "huey_workers": "4"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-a:1234", 180)
    fake_redis.set(f"{WORKER_SLOTS_PREFIX}host-a", "3")

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-b:5678", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-b:5678", mapping={"hostname": "host-b", "worker_name": "host-b", "huey_workers": "2"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-b:5678", 180)
    fake_redis.set(f"{WORKER_SLOTS_PREFIX}host-b", "1")

    data = await _fetch_worker_data(async_db)
    # host-a: cap=8 but only 4 threads → effective=4; host-b: cap=2, threads=2 → effective=2
    assert data["fleet_total_capacity"] == 6  # min(8,4) + min(2,2)
    assert data["fleet_total_active"] == 4  # 3 + 1
    assert data["fleet_total_available"] == 2  # 6 - 4
    assert data["fleet_has_unlimited"] is False


async def test_fleet_capacity_with_unlimited_worker(async_db, fake_redis, monkeypatch):
    """Fleet with an unlimited worker should flag fleet_has_unlimited and use threads as capacity."""
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-d:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-d:1234", mapping={"hostname": "host-d", "worker_name": "host-d", "huey_workers": "4"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-d:1234", 180)

    data = await _fetch_worker_data(async_db)
    assert data["fleet_has_unlimited"] is True
    assert data["fleet_total_capacity"] == 4
    assert data["fleet_total_available"] == 4


async def test_worker_huey_threads_in_metadata(async_db, fake_redis, monkeypatch):
    """Worker metadata should include the huey_workers thread count."""
    from app.redis_client import WORKER_ALIVE_PREFIX, WORKER_INFO_PREFIX
    from app.routers.admin import _fetch_worker_data

    monkeypatch.setattr("app.huey_inspect.get_queue_snapshot", lambda limit=20: {"queue_size": 0, "items": [], "error": None})

    fake_redis.set(f"{WORKER_ALIVE_PREFIX}host-e:1234", "1", ex=180)
    fake_redis.hset(f"{WORKER_INFO_PREFIX}host-e:1234", mapping={"hostname": "host-e", "worker_name": "host-e", "huey_workers": "8"})
    fake_redis.expire(f"{WORKER_INFO_PREFIX}host-e:1234", 180)

    data = await _fetch_worker_data(async_db)
    assert data["active_workers"][0]["huey_workers"] == 8


# ── Registration refresher ────────────────────────────────────────────────────
#
# Registration is refreshed by a per-process thread, never by a Huey periodic task on the
# SHARED queue. Every consumer's scheduler enqueues its own copy
# (huey/consumer.py::Scheduler.enqueue_periodic_tasks — no lock, no leader election) and
# whichever idle thread in the fleet wins the BRPOP refreshes only *its* pid, so a
# process's refresh rate would be C x (threads_here / threads_fleet) per minute against a
# 180s TTL — near one refresh per 100 seconds for a `-w 2` control plane, and none at all
# for a process whose every thread is inside a long backfill or AI run. Three lost draws
# and the row vanishes from /admin/workers until the next win.
#
# None of this is reachable from a route test: the process is alive, healthy, logs
# nothing, and the page is correct about every worker it can still see.


def test_liveness_never_rides_the_shared_queue():
    """A refresh any other consumer can win is not a refresh this process can rely on."""
    from app.workers.huey_app import huey

    periodic = {type(task).__name__ for task in huey._registry.periodic_tasks}
    assert "worker_heartbeat_periodic" not in periodic, "worker liveness is back on the shared queue"


def test_worker_startup_leaves_a_refresher_thread_running(monkeypatch):
    """`@huey.on_startup()` is the only hook that runs in every consumer process."""
    import threading

    from app.workers import tasks

    monkeypatch.setattr(tasks, "_register_worker", lambda *a, **k: None)
    try:
        tasks._on_worker_startup()
        assert tasks._REGISTRATION_THREAD_NAME in {t.name for t in threading.enumerate()}
    finally:
        tasks._stop_registration_refresher()


def test_a_multi_thread_consumer_starts_exactly_one_refresher(monkeypatch):
    """`Worker.initialize` (huey/consumer.py) calls every startup hook once per WORKER
    THREAD, so `-w 4` runs this hook four times inside one process."""
    import threading

    from app.workers import tasks

    monkeypatch.setattr(tasks, "_register_worker", lambda *a, **k: None)
    try:
        for _ in range(4):
            tasks._on_worker_startup()
        running = [t for t in threading.enumerate() if t.name == tasks._REGISTRATION_THREAD_NAME]
        assert len(running) == 1, f"one refresher per process, got {len(running)}"
    finally:
        tasks._stop_registration_refresher()


def test_the_refresher_re_registers_on_its_own_interval(monkeypatch):
    """The whole point: refreshes that arrive without dequeuing anything."""
    import threading

    from app.workers import tasks

    beats = threading.Semaphore(0)
    monkeypatch.setattr(tasks, "_registration_refresh_interval", lambda: 0.02)
    monkeypatch.setattr(tasks, "_register_worker", lambda *a, **k: beats.release())
    try:
        tasks._start_registration_refresher()
        assert beats.acquire(timeout=5), "the refresher never re-registered"
        assert beats.acquire(timeout=5), "the refresher registered once and stopped"
    finally:
        tasks._stop_registration_refresher()


def test_the_refresher_thread_is_a_daemon(monkeypatch):
    """A non-daemon thread would hold `huey_consumer` open at shutdown."""
    import threading

    from app.workers import tasks

    monkeypatch.setattr(tasks, "_register_worker", lambda *a, **k: None)
    try:
        tasks._start_registration_refresher()
        thread = next(t for t in threading.enumerate() if t.name == tasks._REGISTRATION_THREAD_NAME)
        assert thread.daemon
    finally:
        tasks._stop_registration_refresher()


def test_a_refresh_failure_does_not_kill_the_thread(monkeypatch):
    """`_register_worker` swallows its own errors, but a raise from anything else in the
    loop would silently end the only liveness this process has."""
    import threading

    from app.workers import tasks

    calls = threading.Semaphore(0)

    def _boom(*a, **k):
        calls.release()
        raise RuntimeError("redis is having a moment")

    monkeypatch.setattr(tasks, "_registration_refresh_interval", lambda: 0.02)
    monkeypatch.setattr(tasks, "_register_worker", _boom)
    try:
        tasks._start_registration_refresher()
        assert calls.acquire(timeout=5)
        assert calls.acquire(timeout=5), "the thread died on the first failure"
    finally:
        tasks._stop_registration_refresher()


def test_the_refresh_interval_keeps_three_attempts_inside_the_ttl(monkeypatch):
    """`_worker_alive_ttl()` is `max(alive_ttl, interval + 60)`, so a large
    WORKER_HEARTBEAT_INTERVAL buys only 60s of headroom — one missed refresh from expiry."""
    from app.workers import tasks

    monkeypatch.setattr(tasks.settings, "worker_heartbeat_interval", 30)
    assert tasks._registration_refresh_interval() == 30
    assert tasks._registration_refresh_interval() * 3 <= tasks._worker_alive_ttl()

    monkeypatch.setattr(tasks.settings, "worker_heartbeat_interval", 600)
    assert tasks._registration_refresh_interval() * 3 <= tasks._worker_alive_ttl()


# ── The Worker Fleet poll gate ────────────────────────────────────────────────


def test_no_template_latches_the_workers_poll_gate():
    """Set by the templates, the gate could be cleared only by a form submit or a full page
    load — anything OUTSIDE `#workers-region` is unreachable to `/admin/workers/partial`. So
    one keystroke in a capacity box would stop the 5s refresh for the life of the page,
    freezing the fleet table, the queue depth and every heartbeat TTL on it. `app.js` owns
    the flag, and clears it on its own."""
    from pathlib import Path

    offenders = sorted(str(p) for p in Path("app/templates").rglob("*.html") if "__workersPriorityDirty = true" in p.read_text(encoding="utf-8"))
    assert not offenders, f"templates still latch the poll gate: {offenders}"
