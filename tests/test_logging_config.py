"""Logging configuration and request correlation.

Several of these guard failures that are invisible in a diff and in every route test: a
second ``configure_logging()`` doubling every line, the ``huey`` logger printing each
consumer record twice in two formats, and a client-supplied ``X-Request-ID`` reaching a log
line verbatim.
"""

from __future__ import annotations

import io
import json
import logging

import pytest

from app.logging_config import (
    CONTEXT_FIELDS,
    TextFormatter,
    bind,
    configure_logging,
    current_context,
    silence_huey_own_handlers,
)
from app.middleware.observability import _is_skipped, sanitize_request_id


@pytest.fixture(autouse=True)
def _restore_root_logging():
    """Logging is process-global; put the root logger back exactly as it was."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    huey_logger = logging.getLogger("huey")
    saved_huey = (list(huey_logger.handlers), huey_logger.level, huey_logger.propagate)
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    huey_logger.handlers[:], huey_logger.level, huey_logger.propagate = saved_huey
    bind(**dict.fromkeys(CONTEXT_FIELDS))


@pytest.fixture(autouse=True)
def _clear_context():
    bind(**dict.fromkeys(CONTEXT_FIELDS))
    yield
    bind(**dict.fromkeys(CONTEXT_FIELDS))


def _capture(fmt: str) -> tuple[logging.Handler, io.StringIO]:
    handler = configure_logging(level="INFO", fmt=fmt)
    buf = io.StringIO()
    handler.stream = buf
    return handler, buf


# ── configure_logging ────────────────────────────────────────────────────────────


def test_configure_logging_is_idempotent():
    """Calling it twice must not double every line.

    Both processes call it, and the worker calls it again from `on_startup` — once per
    consumer thread. A handler-per-call would multiply every record by the worker count.
    """
    configure_logging(level="INFO", fmt="text")
    configure_logging(level="INFO", fmt="json")
    configure_logging(level="DEBUG", fmt="text")
    ours = [h for h in logging.getLogger().handlers if getattr(h, "_logstotal_handler", False)]
    assert len(ours) == 1


def test_configure_logging_leaves_foreign_handlers_alone():
    root = logging.getLogger()
    foreign = logging.NullHandler()
    root.addHandler(foreign)
    configure_logging(level="INFO", fmt="text")
    assert foreign in root.handlers


def test_an_unknown_format_falls_back_to_text_instead_of_raising():
    """A typo in LOG_FORMAT must not stop the application booting."""
    handler = configure_logging(level="INFO", fmt="yaml-ish")
    assert isinstance(handler.formatter, TextFormatter)


def test_level_is_applied_to_root():
    configure_logging(level="warning", fmt="text")
    assert logging.getLogger().level == logging.WARNING


# ── formatters ───────────────────────────────────────────────────────────────────


def test_json_lines_parse_and_carry_the_context():
    _handler, buf = _capture("json")
    bind(request_id="req-1", job_id="42")
    logging.getLogger("some.module").info("hello %s", "world")
    record = json.loads(buf.getvalue().strip())
    assert record["msg"] == "hello world"
    assert record["level"] == "INFO"
    assert record["logger"] == "some.module"
    assert record["request_id"] == "req-1"
    assert record["job_id"] == "42"
    assert record["thread"]
    assert record["ts"].endswith("+00:00")


def test_json_emits_extra_fields_as_top_level_keys():
    """This is what lets the access log be structured without a second logging API."""
    _handler, buf = _capture("json")
    logging.getLogger("logstotal.access").info("GET / 200", extra={"http_status": 200, "duration_ms": 7})
    record = json.loads(buf.getvalue().strip())
    assert record["http_status"] == 200
    assert record["duration_ms"] == 7


def test_json_survives_an_unserialisable_extra():
    _handler, buf = _capture("json")
    logging.getLogger("x").info("m", extra={"thing": object()})
    record = json.loads(buf.getvalue().strip())
    assert "thing" in record  # repr'd rather than dropped or raised


def test_json_includes_the_traceback_for_an_exception():
    _handler, buf = _capture("json")
    try:
        raise ValueError("boom")
    except ValueError:
        logging.getLogger("x").exception("failed")
    record = json.loads(buf.getvalue().strip())
    assert "ValueError: boom" in record["exc_info"]


def test_text_appends_context_only_when_there_is_some():
    _handler, buf = _capture("text")
    logging.getLogger("x").info("plain")
    assert buf.getvalue().strip().endswith("plain")

    buf.truncate(0)
    buf.seek(0)
    bind(request_id="abc")
    logging.getLogger("x").info("tagged")
    assert buf.getvalue().strip().endswith("[request_id=abc]")


def test_context_is_readable_as_data():
    bind(request_id="r", actor="someone@example.com")
    assert current_context() == {"request_id": "r", "actor": "someone@example.com"}


def test_a_context_field_can_be_cleared():
    bind(job_id="9")
    bind(job_id=None)
    assert "job_id" not in current_context()


# ── the worker's double-logging trap ─────────────────────────────────────────────


def test_silence_huey_own_handlers_drops_the_consumers_handler_but_keeps_propagation():
    """`huey_consumer` calls `setup_logger` AFTER importing our module.

    It does `addHandler(StreamHandler(...))` and `setLevel(...)` on the `huey` logger,
    which propagates to root — so without this, every consumer line prints twice, in two
    formats, with LOG_LEVEL overridden on that tree.
    """
    huey_logger = logging.getLogger("huey")
    huey_logger.addHandler(logging.StreamHandler())
    huey_logger.setLevel(logging.ERROR)

    silence_huey_own_handlers()

    assert huey_logger.handlers == []
    assert huey_logger.level == logging.NOTSET
    assert huey_logger.propagate is True


def test_a_huey_record_reaches_our_handler_exactly_once():
    _handler, buf = _capture("json")
    huey_logger = logging.getLogger("huey")
    huey_logger.addHandler(logging.StreamHandler(io.StringIO()))
    silence_huey_own_handlers()
    huey_logger.info("consumer says hello")
    assert buf.getvalue().count("consumer says hello") == 1


def test_the_worker_startup_hook_calls_the_silencer():
    """Pinned by name: the hook is the only place that runs late enough to work."""
    import inspect

    from app.workers import tasks

    assert "silence_huey_own_handlers()" in inspect.getsource(tasks._on_worker_startup)


def test_huey_app_configures_logging_at_import():
    """The worker has no lifespan, so import time is the only opportunity."""
    from pathlib import Path

    source = Path("app/workers/huey_app.py").read_text(encoding="utf-8")
    assert "configure_logging()" in source


def test_run_analysis_binds_and_clears_the_job_id():
    """Huey's `-k thread` consumer reuses pool threads, so a bind left standing would
    stamp the next job's id onto this job's lines."""
    import inspect

    from app.workers import tasks

    # `@huey.task()` returns a TaskWrapper; `.func` is the function it decorated.
    source = inspect.getsource(tasks.run_analysis.func)
    assert "bind_log_context(job_id=str(job_id))" in source
    assert "bind_log_context(job_id=None)" in source


def test_a_slot_cap_deferral_does_not_leave_the_job_id_bound(monkeypatch):
    """The deferral returns before the `try` whose `finally` unbinds, so the next task on
    that pool thread — a backfill, a webhook, an AI run — logged under this job's id."""
    from app.logging_config import bind as bind_log_context
    from app.logging_config import current_context
    from app.workers import tasks

    bind_log_context(job_id=None)
    monkeypatch.setattr(tasks, "_acquire_job_slot", lambda job_id: False)
    monkeypatch.setattr(tasks.run_analysis, "schedule", lambda *a, **k: None)

    tasks.run_analysis.call_local(42)

    assert "job_id" not in current_context()


# ── request id sanitisation ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "has space",
        "has\nnewline",
        'quote"inside',
        "{json:true}",
        "a" * 65,
        "semi;colon",
    ],
)
def test_a_hostile_request_id_is_replaced_not_sanitised(raw):
    """It is echoed into a structured log field, so a newline would forge a second line."""
    out = sanitize_request_id(raw)
    assert out != raw
    assert len(out) == 32
    assert out.isalnum()


@pytest.mark.parametrize("raw", ["abc123", "trace-id_1.2", "A" * 64])
def test_a_well_formed_request_id_is_preserved(raw):
    assert sanitize_request_id(raw) == raw


@pytest.mark.parametrize("path", ["/static/app.js", "/static/vendor/htmx.min.js", "/health"])
def test_noisy_paths_are_skipped(path):
    assert _is_skipped(path)


@pytest.mark.parametrize("path", ["/", "/jobs/1", "/admin", "/healthz", "/staticky"])
def test_real_paths_are_not_skipped(path):
    assert not _is_skipped(path)


def test_the_consumers_own_handler_is_suppressed_at_the_source():
    """`silence_huey_own_handlers` alone is four lines too late.

    `consumer_main` calls `setup_logger` and then logs its startup banner — "Huey consumer
    started", the scheduler interval, the task list — all before any `@huey.on_startup()`
    hook fires. Measured against a real consumer: those records printed twice, in both
    formats. Patching `setup_logger` prevents the handler instead of removing it.
    """
    from huey import consumer_options

    from app.logging_config import suppress_huey_consumer_handler

    assert suppress_huey_consumer_handler() is True
    assert getattr(consumer_options.ConsumerConfig.setup_logger, "_logstotal_patched", False)

    # The replacement still applies the level — that half of setup_logger's job is wanted.
    target = logging.getLogger("huey.test-probe")
    target.handlers.clear()

    class _Config:
        loglevel = logging.WARNING

    consumer_options.ConsumerConfig.setup_logger(_Config(), target)
    assert target.handlers == [], "it must not add a handler"
    assert target.level == logging.WARNING, "but it must still set the level"
    target.setLevel(logging.NOTSET)


def test_suppression_is_idempotent():
    """The worker imports `huey_app` once, but a test run imports it many times."""
    from app.logging_config import suppress_huey_consumer_handler

    assert suppress_huey_consumer_handler() is True
    assert suppress_huey_consumer_handler() is True


def test_huey_app_suppresses_before_the_consumer_configures_itself():
    """Import time, not an on_startup hook — the banner is logged before any worker exists."""
    from pathlib import Path

    source = Path("app/workers/huey_app.py").read_text(encoding="utf-8")
    assert "suppress_huey_consumer_handler()" in source
