"""Tests for the Huey queue introspection helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_get_queue_snapshot_returns_correct_shape():
    """Snapshot dict should always contain queue_size, items, and error keys."""
    mock_storage = MagicMock()
    mock_storage.queue_size.return_value = 0
    mock_storage.enqueued_items.return_value = []

    mock_huey = MagicMock()
    mock_huey.storage = mock_storage

    with patch("app.huey_inspect.huey", mock_huey, create=True):
        from app.huey_inspect import get_queue_snapshot

        with patch.dict("sys.modules", {"app.workers.huey_app": MagicMock(huey=mock_huey)}):
            result = get_queue_snapshot(limit=5)

    assert "queue_size" in result
    assert "items" in result
    assert "error" in result
    assert isinstance(result["items"], list)


def test_get_queue_snapshot_deserializes_items():
    """Items in the queue should be deserialized into task_name/args_summary/task_id dicts."""
    mock_task = MagicMock()
    mock_task.name = "run_analysis"
    mock_task.args = (42,)
    mock_task.kwargs = {}
    mock_task.id = "abc-123-def-456"

    mock_storage = MagicMock()
    mock_storage.queue_size.return_value = 1
    mock_storage.enqueued_items.return_value = [b"fake-serialized"]

    mock_huey = MagicMock()
    mock_huey.storage = mock_storage
    mock_huey.deserialize_task.return_value = mock_task

    with patch.dict("sys.modules", {"app.workers.huey_app": MagicMock(huey=mock_huey)}):
        from importlib import reload

        import app.huey_inspect

        reload(app.huey_inspect)
        result = app.huey_inspect.get_queue_snapshot(limit=5)

    assert result["queue_size"] == 1
    assert len(result["items"]) == 1
    assert result["items"][0]["task_name"] == "run_analysis"
    assert "job_id=42" in result["items"][0]["args_summary"]
    assert result["items"][0]["task_id"] == "abc-123-def-456"
    assert result["error"] is None


def test_get_queue_snapshot_handles_redis_error():
    """Redis connection errors should be caught and returned in the error field."""
    from redis.exceptions import ConnectionError as RedisConnectionError

    with patch.dict("sys.modules", {"app.workers.huey_app": MagicMock()}):
        mock_huey = MagicMock()
        mock_huey.storage.queue_size.side_effect = RedisConnectionError("Connection refused")

        import sys

        sys.modules["app.workers.huey_app"].huey = mock_huey

        from importlib import reload

        import app.huey_inspect

        reload(app.huey_inspect)
        result = app.huey_inspect.get_queue_snapshot(limit=5)

    assert result["queue_size"] == 0
    assert result["items"] == []
    assert result["error"] is not None
    assert "Connection refused" in result["error"]


def test_get_queue_snapshot_limit_zero_skips_items():
    """With limit=0, only queue_size should be fetched; enqueued_items should not be called."""
    mock_storage = MagicMock()
    mock_storage.queue_size.return_value = 7

    mock_huey = MagicMock()
    mock_huey.storage = mock_storage

    with patch.dict("sys.modules", {"app.workers.huey_app": MagicMock(huey=mock_huey)}):
        from importlib import reload

        import app.huey_inspect

        reload(app.huey_inspect)
        result = app.huey_inspect.get_queue_snapshot(limit=0)

    assert result["queue_size"] == 7
    assert result["items"] == []
    assert result["error"] is None
    mock_storage.enqueued_items.assert_not_called()


def test_summarize_args_labels_known_tasks():
    """Known task names should produce labelled argument summaries."""
    from app.huey_inspect import _summarize_args

    assert _summarize_args("run_analysis", (42,), {}) == "job_id=42"
    assert _summarize_args("backfill_similarity", (7,), {}) == "bg_task_id=7"
    assert _summarize_args("backfill_analytics", None, {"bg_task_id": 3}) == "bg_task_id=3"


def test_summarize_args_unknown_task_falls_through():
    """Unknown task names should concatenate raw args."""
    from app.huey_inspect import _summarize_args

    assert _summarize_args("unknown_task", (1, "abc"), {"key": "val"}) == "1, abc, key=val"
    assert _summarize_args("unknown_task", None, None) == ""
