"""Huey task queue instance — import this module to enqueue or register tasks."""

from huey import RedisHuey

from app.config import settings
from app.logging_config import configure_logging, suppress_huey_consumer_handler

# The worker has no lifespan, so this is the only place it can happen. Import time, so that
# records emitted while the task modules below are importing are formatted too.
configure_logging()
# And stop `huey_consumer` adding its own handler on top of ours. This must happen before
# `consumer_main` calls `setup_logger`, which is why it is here and not in an `on_startup`
# hook: the consumer logs its startup banner before any worker thread exists, so a hook
# would leave those four lines printed twice, in two formats. `_on_worker_startup` still
# calls `silence_huey_own_handlers()` as the fallback for a huey this patch cannot reach.
suppress_huey_consumer_handler()

_huey_kwargs: dict = {"results": True, "store_none": False}
if settings.redis_url:
    _huey_kwargs["url"] = settings.redis_url
else:
    _huey_kwargs["host"] = settings.redis_host
    _huey_kwargs["port"] = settings.redis_port
    _huey_kwargs["password"] = settings.redis_password or None

huey = RedisHuey("logstotal", **_huey_kwargs)

# Import task modules so their @huey.task() decorators register with this instance.
# This must come after `huey` is defined to avoid a circular import.
from app.workers import tasks as _tasks  # noqa: E402, F401
