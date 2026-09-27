"""One place that decides what a log line looks like, for both processes.

Pure of FastAPI and Huey — the worker imports this module, so it follows the same rule as
``app/concurrency.py`` and ``app/system_checks.py``.

Two things here are worth knowing before changing anything.

**The correlation fields are contextvars, not arguments.** There are 100+ ``logger.*`` /
``_log.*`` call sites across the application and none of them pass ``extra=``. A
:class:`ContextFilter` on the handler injects ``request_id`` / ``job_id`` / ``actor`` into
every record instead, so a request or a job is traceable end to end without touching a
single existing call. ``contextvars`` is the right primitive rather than thread-locals:
anyio copies the context into ``run_in_threadpool``, so a value set in a pure-ASGI
middleware still reaches a sync DB call three frames down.

**The worker needs de-duplication, not just configuration.** ``huey_consumer`` runs
``config.setup_logger(logging.getLogger('huey'))`` *after* importing the app's huey module,
and that call does ``addHandler(StreamHandler(...))`` **and** ``setLevel(...)`` on the
``huey`` logger. Since that logger propagates to root, configuring root here would print
every consumer line twice, in two different formats, with our level overridden on that
tree.

:func:`suppress_huey_consumer_handler` is the fix, and it runs at *import* time in
``app/workers/huey_app.py`` rather than from an ``@huey.on_startup()`` hook. That ordering
was measured rather than assumed: the consumer logs its startup banner — "Huey consumer
started", the scheduler interval, the whole task list — before any worker thread exists, so
a hook leaves exactly those lines duplicated. :func:`silence_huey_own_handlers` remains as
the fallback for a huey version the patch cannot reach.
"""

from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import sys

# ── Correlation context ───────────────────────────────────────────────────────────

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
job_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("job_id", default=None)
actor_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("actor", default=None)

#: Fields the filter injects, in the order they appear in the text format.
CONTEXT_FIELDS = ("request_id", "job_id", "actor")

_VARS = {"request_id": request_id_var, "job_id": job_id_var, "actor": actor_var}

TEXT = "text"
JSON = "json"
FORMATS = frozenset({TEXT, JSON})

#: Marks the handler we installed, so a second call replaces it instead of stacking.
_OURS = "_logstotal_handler"


def bind(**values: str | None) -> None:
    """Set correlation values on the current context (``None`` clears one)."""
    for key, value in values.items():
        var = _VARS.get(key)
        if var is not None:
            var.set(value)


def current_context() -> dict[str, str]:
    """The correlation fields that are actually set, for callers that want them as data."""
    return {key: var.get() for key, var in _VARS.items() if var.get()}


class ContextFilter(logging.Filter):
    """Attach the correlation contextvars to every record.

    A filter rather than a ``LoggerAdapter`` because it has to apply to records the
    application never creates — uvicorn's, SQLAlchemy's, huey's.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for name in CONTEXT_FIELDS:
            setattr(record, name, _VARS[name].get())
        return True


class TextFormatter(logging.Formatter):
    """The human-readable format, plus a correlation suffix when there is one."""

    default_msec_format = "%s.%03d"

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        bits = [f"{name}={getattr(record, name)}" for name in CONTEXT_FIELDS if getattr(record, name, None)]
        return f"{base} [{' '.join(bits)}]" if bits else base


#: Everything ``logging`` puts on a record itself. Anything else a caller passed via
#: ``extra=`` is theirs, and the JSON formatter emits it — which is what makes a structured
#: access line possible without a second logging API.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Never raises — a formatter that throws loses the line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": _dt.datetime.fromtimestamp(record.created, tz=_dt.UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for name in CONTEXT_FIELDS:
            value = getattr(record, name, None)
            if value:
                payload[name] = value
        payload["thread"] = record.threadName
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        for key, value in record.__dict__.items():
            if key in _RESERVED or key in CONTEXT_FIELDS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = repr(value)
            payload[key] = value
        try:
            return json.dumps(payload, default=str)
        except (TypeError, ValueError):  # pragma: no cover — default=str makes this all but unreachable
            return json.dumps({"ts": payload["ts"], "level": payload["level"], "logger": payload["logger"], "msg": record.getMessage()})


def _build_handler(fmt: str) -> logging.Handler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == JSON else TextFormatter())
    handler.addFilter(ContextFilter())
    setattr(handler, _OURS, True)
    return handler


def configure_logging(*, level: str | None = None, fmt: str | None = None) -> logging.Handler:
    """Install our single root handler. Idempotent — safe to call from several places.

    Returns the installed handler so callers (and tests) can assert on it. An unknown
    *fmt* falls back to text rather than raising: a typo in ``LOG_FORMAT`` must not stop
    the application booting.
    """
    from app.config import settings

    level = (level or settings.log_level or "INFO").upper()
    fmt = (fmt or getattr(settings, "log_format", TEXT) or TEXT).lower()
    if fmt not in FORMATS:
        fmt = TEXT

    root = logging.getLogger()
    for existing in list(root.handlers):
        # Replace our own handler on a re-call. Anything else on root — a handler
        # `basicConfig` left behind, or one a host application added deliberately — stays.
        if getattr(existing, _OURS, False):
            root.removeHandler(existing)
    root.addHandler(_build_handler(fmt))
    root.setLevel(getattr(logging, level, logging.INFO))
    return root.handlers[-1]


def suppress_huey_consumer_handler() -> bool:
    """Stop ``huey_consumer`` installing its own handler at all. Returns True if patched.

    :func:`silence_huey_own_handlers` removes the handler once a worker thread starts, but
    that is too late by four lines: ``consumer_main`` calls ``setup_logger`` and the
    consumer logs its startup banner — "Huey consumer started", the scheduler interval,
    the task list — before any ``@huey.on_startup()`` hook fires. Measured: those four
    records print twice, in both formats.

    So the handler is prevented rather than removed. The replacement keeps the *level*
    ``setup_logger`` would have applied, because that is the part of its job we still
    want; only the `addHandler` is dropped, leaving every record to propagate to root and
    be rendered once.

    Patching a third-party class is deliberate and narrow — there is no configuration hook
    for this — and it is guarded, so a future huey that moves or renames `setup_logger`
    degrades to the `on_startup` path rather than failing to boot the worker.
    """
    try:
        from huey import consumer_options
    except Exception:  # pragma: no cover — huey is a hard dependency; belt and braces
        return False

    config_cls = getattr(consumer_options, "ConsumerConfig", None)
    if config_cls is None or not hasattr(config_cls, "setup_logger"):
        return False
    if getattr(config_cls.setup_logger, "_logstotal_patched", False):
        return True

    def setup_logger(self, logger=None):
        target = logger if logger is not None else logging.getLogger()
        level = getattr(self, "loglevel", None)
        if level is not None:
            target.setLevel(level)

    setup_logger._logstotal_patched = True
    config_cls.setup_logger = setup_logger
    return True


def silence_huey_own_handlers() -> None:
    """Remove any handler the consumer still managed to add, keeping propagation to ours.

    The fallback half of :func:`suppress_huey_consumer_handler`, called from
    ``@huey.on_startup()``. It is what covers a huey version the patch could not reach —
    a few duplicated banner lines rather than a worker that logs everything twice.

    Leaving ``propagate`` alone is deliberate: the records are wanted, it is the second
    rendering of them that is not. The level is cleared too, since ``setup_logger`` pins it
    on that tree and would otherwise ignore ``LOG_LEVEL``.
    """
    huey_logger = logging.getLogger("huey")
    for handler in list(huey_logger.handlers):
        huey_logger.removeHandler(handler)
    huey_logger.setLevel(logging.NOTSET)
    huey_logger.propagate = True
