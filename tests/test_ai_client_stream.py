"""Tier-1 tests for the streaming read loop in ``app.ai.client``. No network, no DB.

Streaming is not here for a typing effect. It exists because of a specific failure this
project actually hit: a run that sat at ``running`` forever. Three properties are pinned.

**The wall-clock deadline.** httpx's ``timeout`` is *per operation*, so a provider that
emits a keep-alive comment before every read deadline keeps a request alive indefinitely.
OpenRouter really does this (``: OPENROUTER PROCESSING``). Only a deadline measured across
the whole read loop bounds that, and it is the single most important line in the file.

**Cancellation is checked between frames**, which is what makes stopping a run something
other than a flag nobody reads.

**A stream request is not a stream promise.** An older Ollama, a buffering proxy or a
gateway that drops unknown body keys will answer ``stream: true`` with one ordinary JSON
object. Detecting that and falling back is what keeps the change from being a silent
compatibility break for exactly the deployment this feature was written for.
"""

from __future__ import annotations

import threading
import time

import pytest

from app.ai.client import (
    _CANCEL_POLL_SECONDS,
    _CANCEL_TEARDOWN_IDLE_SECONDS,
    PROGRESS_EVERY_CHARS,
    _consume_stream,
    _sse_payload,
)
from app.ai.providers import AiProviderError


class FakeResponse:
    """The two methods ``_consume_stream`` uses, plus a record of being closed."""

    def __init__(self, lines, *, pause: float = 0.0):
        self._lines = list(lines)
        self._pause = pause
        self.closed = False

    def iter_lines(self):
        for line in self._lines:
            if self._pause:
                time.sleep(self._pause)
            yield line

    def close(self):
        self.closed = True


def _openai_frames(*chunks):
    return [f'data: {{"choices":[{{"delta":{{"content":"{c}"}}}}]}}' for c in chunks]


def _consume(lines, *, kind="openai", cancelled=None, deadline=None, note=None, pause=0.0):
    notes: list[str] = []
    result = _consume_stream(
        FakeResponse(lines, pause=pause),
        kind=kind,
        cancelled=cancelled or (lambda: False),
        deadline=deadline if deadline is not None else time.monotonic() + 60,
        note=note or notes.append,
    )
    return result, notes


class TestSsePayload:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ('data: {"a":1}', '{"a":1}'),
            ('data:{"a":1}', '{"a":1}'),
            ("data: [DONE]", "[DONE]"),
            ("data:   spaced   ", "spaced"),
        ],
    )
    def test_a_data_line_yields_its_payload(self, line, expected):
        assert _sse_payload(line) == expected

    @pytest.mark.parametrize("line", ["", "event: message", ": keep-alive", "id: 7", "random noise"])
    def test_everything_else_is_framing_not_content(self, line):
        """Treating any of these as content is how stray characters land in an answer."""
        assert _sse_payload(line) is None


class TestHappyPath:
    def test_deltas_are_concatenated_in_order(self):
        result, _ = _consume([*_openai_frames("Hel", "lo ", "world"), "data: [DONE]"])
        assert result.text == "Hello world"
        assert result.outcome == ""

    def test_done_ends_the_stream_and_is_not_content(self):
        result, _ = _consume([*_openai_frames("kept"), "data: [DONE]", *_openai_frames("AFTER")])
        assert result.text == "kept"
        assert "AFTER" not in result.text

    def test_usage_is_collected_from_the_final_frame(self):
        lines = [*_openai_frames("hi"), 'data: {"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":2}}', "data: [DONE]"]
        result, _ = _consume(lines)
        assert result.usage == {"input_tokens": 11, "output_tokens": 2}

    def test_undecodable_frames_are_skipped_not_fatal(self):
        """A truncated or non-JSON frame must not throw away a generation in progress."""
        lines = [*_openai_frames("a"), "data: {not json", "data: ", *_openai_frames("b"), "data: [DONE]"]
        result, _ = _consume(lines)
        assert result.text == "ab"
        assert result.outcome == ""

    def test_keep_alive_comments_are_ignored_but_still_prove_this_is_a_stream(self):
        result, _ = _consume([": OPENROUTER PROCESSING", ": OPENROUTER PROCESSING", *_openai_frames("x"), "data: [DONE]"])
        assert result.text == "x"
        assert result.outcome == "", "a comment is SSE framing, so this is not the non-stream fallback"

    def test_anthropic_frames(self):
        lines = [
            'data: {"type":"message_start","message":{"usage":{"input_tokens":300,"output_tokens":1}}}',
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Ver"}}',
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"dict"}}',
            'data: {"type":"message_delta","usage":{"output_tokens":42}}',
        ]
        result, _ = _consume(lines, kind="anthropic")
        assert result.text == "Verdict"
        assert result.usage == {"input_tokens": 300, "output_tokens": 42}, "message_delta refreshes output only, so usage merges"


class TestProgressNarration:
    def test_the_first_token_is_announced(self):
        """ "Has it started writing?" is the question a waiting user is actually asking."""
        _, notes = _consume([*_openai_frames("a"), "data: [DONE]"])
        assert any("First tokens" in n for n in notes)

    def test_progress_is_reported_by_volume_not_per_frame(self):
        """One line per token would be a log nobody can read and a write per token."""
        chunk = "x" * (PROGRESS_EVERY_CHARS // 4)
        _, notes = _consume([*_openai_frames(*([chunk] * 12)), "data: [DONE]"])
        progress = [n for n in notes if "Receiving the answer" in n]
        assert 1 <= len(progress) <= 4, f"expected a handful of progress lines, got {len(progress)}"

    def test_a_stream_with_no_content_narrates_nothing(self):
        _, notes = _consume(['data: {"choices":[{"delta":{"role":"assistant"}}]}', "data: [DONE]"])
        assert notes == []


class TestCancellation:
    def test_a_set_flag_stops_the_loop_and_keeps_what_arrived(self):
        seen = {"n": 0}

        def cancelled():
            seen["n"] += 1
            return seen["n"] > 2

        result, _ = _consume(_openai_frames(*"abcdefgh"), cancelled=cancelled)
        assert result.outcome == "cancelled"
        assert len(result.text) < 8, "the loop must stop, not run to completion"

    def test_cancellation_is_checked_before_the_first_frame_is_parsed(self):
        result, _ = _consume(_openai_frames("never"), cancelled=lambda: True)
        assert result.outcome == "cancelled"
        assert result.text == ""


class TestTheWallClockDeadline:
    def test_a_stream_past_its_deadline_is_stalled(self):
        """The case this exists for: keep-alive traffic that never becomes an answer."""
        result, _ = _consume([": ping"] * 50, deadline=time.monotonic() - 1)
        assert result.outcome == "stalled"

    def test_keep_alive_traffic_cannot_extend_a_run_indefinitely(self):
        """A provider dripping comments resets httpx's per-read timeout but not this one."""
        result, _ = _consume([": OPENROUTER PROCESSING"] * 40, deadline=time.monotonic() + 0.05, pause=0.01)
        assert result.outcome == "stalled"

    def test_the_deadline_does_not_fire_on_a_prompt_stream(self):
        result, _ = _consume([*_openai_frames("fast"), "data: [DONE]"], deadline=time.monotonic() + 60)
        assert result.outcome == ""
        assert result.text == "fast"


class TestNonStreamingFallback:
    """A 2xx that is not SSE is a compatibility case, not a failure.

    Without this, a provider that ignores ``stream: true`` produces an empty answer and the
    run is reported as "the model returned an empty answer" — blaming the model for a
    protocol mismatch, and leaving the operator with no idea what to change.
    """

    def test_a_plain_json_body_is_handed_back_for_the_ordinary_parser(self):
        body = '{"choices":[{"message":{"content":"hello"}}]}'
        result, _ = _consume([body])
        assert result.outcome == "not_a_stream"
        assert result.body == body
        assert result.text == ""

    def test_a_multi_line_json_body_is_reassembled(self):
        lines = ["{", '  "choices": [{"message": {"content": "hi"}}]', "}"]
        result, _ = _consume(lines)
        assert result.outcome == "not_a_stream"
        assert result.body == "\n".join(lines)

    def test_one_data_frame_is_enough_to_rule_the_fallback_out(self):
        result, _ = _consume(["{", *_openai_frames("real"), "}"])
        assert result.outcome == ""
        assert result.text == "real"


class TestMidStreamProviderError:
    def test_it_propagates_rather_than_being_swallowed(self):
        """A provider refusing halfway is the one frame that must not be skipped.

        `run_completion` catches this and turns it into the run's error_message; silently
        continuing would return a truncated answer as if it were complete.
        """
        lines = [*_openai_frames("partial"), 'data: {"error":{"message":"context length exceeded"}}']
        with pytest.raises(AiProviderError, match="context length"):
            _consume(lines)


class TestTheCancelWatcher:
    """The watcher must stand down while frames are arriving.

    The obvious watcher — close the response the moment the flag appears — makes
    cancellation **slower than having no watcher at all**: closing an httpx response from
    another thread does not interrupt a read already in progress, so it leaves the reader
    blocked until the read timeout. Measured against a stream emitting a token every 150ms:
    a cancel that should take ~1s took 61s.

    The read loop is the primary mechanism; this thread is only for a stream that has gone
    silent, where there is no next frame for the loop to check on.
    """

    def test_it_does_not_close_a_stream_that_is_still_producing(self):
        from app.ai.client import _StreamActivity, _watch_for_cancel

        response = FakeResponse([])
        activity = _StreamActivity()
        cancel = threading.Event()
        cancel.set()

        stop = _watch_for_cancel(cancel, response, activity)
        try:
            # Keep the stream "alive" the way the read loop does, for longer than the
            # teardown idle threshold.
            deadline = time.monotonic() + (_CANCEL_TEARDOWN_IDLE_SECONDS + 0.6)
            while time.monotonic() < deadline:
                activity.touch()
                time.sleep(0.05)
            assert not response.closed, "frames are still arriving; the read loop must do the stopping"
        finally:
            stop()

    def test_it_does_close_a_stream_that_has_gone_quiet(self):
        from app.ai.client import _StreamActivity, _watch_for_cancel

        response = FakeResponse([])
        activity = _StreamActivity()
        activity.last -= _CANCEL_TEARDOWN_IDLE_SECONDS + 5  # already long silent
        cancel = threading.Event()
        cancel.set()

        stop = _watch_for_cancel(cancel, response, activity)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not response.closed:
                time.sleep(0.05)
            assert response.closed, "a silent stream can only be stopped by dropping the connection"
        finally:
            stop()

    def test_it_never_closes_without_a_cancel(self):
        from app.ai.client import _StreamActivity, _watch_for_cancel

        response = FakeResponse([])
        activity = _StreamActivity()
        activity.last -= 60  # silent, but nobody asked to stop
        stop = _watch_for_cancel(threading.Event(), response, activity)
        try:
            time.sleep(_CANCEL_POLL_SECONDS * 3)
            assert not response.closed
        finally:
            stop()

    def test_no_cancel_event_means_no_thread_at_all(self):
        from app.ai.client import _StreamActivity, _watch_for_cancel

        before = threading.active_count()
        stop = _watch_for_cancel(None, FakeResponse([]), _StreamActivity())
        assert threading.active_count() == before
        stop()  # still callable, so the caller's finally: needs no branch


class TestStreamActivity:
    def test_touch_resets_the_idle_clock(self):
        from app.ai.client import _StreamActivity

        activity = _StreamActivity()
        activity.last -= 10
        assert activity.idle_for() >= 10
        activity.touch()
        assert activity.idle_for() < 1

    def test_the_read_loop_touches_on_every_line_including_keep_alives(self):
        """A comment carries no content but proves a next frame is coming."""
        from app.ai.client import _StreamActivity

        activity = _StreamActivity()
        activity.last -= 30
        _consume_stream(
            FakeResponse([": ping", ": ping"]),
            kind="openai",
            cancelled=lambda: False,
            deadline=time.monotonic() + 60,
            note=lambda _m: None,
            activity=activity,
        )
        assert activity.idle_for() < 1


class TestAbortingConnections:
    """`Client.close()` cannot reach a reader already blocked in recv(); shutdown() can.

    Without shutdown(), Stop appears to do nothing for the whole of a local model's
    prompt-processing phase, because during it there is no response object and the
    only thing holding the worker is a socket read. Measured against a stub that accepts the
    request and sends nothing: close() alone deferred the cancel for the entire remaining
    timeout (40s), a socket shutdown ended it in 2s.

    Reaching through httpx into httpcore is deliberate — the sync client exposes no
    cancellation API — so the walk is pinned here, and so is its *degradation*: an httpx that
    moves these attributes must return 0, never raise, falling back to the timeout.
    """

    class _Sock:
        def __init__(self, boom=None):
            self.boom = boom
            self.calls = []

        def shutdown(self, how):
            self.calls.append(how)
            if self.boom:
                raise self.boom

    def _client(self, *socks):
        """The exact private chain `_abort_client_connections` walks."""

        def conn(sock):
            return type("Conn", (), {"_connection": type("Inner", (), {"_network_stream": type("S", (), {"_sock": sock})()})()})()

        pool = type("Pool", (), {"_connections": [conn(s) for s in socks]})()
        return type("Client", (), {"_transport": type("T", (), {"_pool": pool})()})()

    def test_it_shuts_down_every_live_socket(self):
        import socket as socket_mod

        from app.ai.client import _abort_client_connections

        a, b = self._Sock(), self._Sock()
        assert _abort_client_connections(self._client(a, b)) == 2
        assert a.calls == [socket_mod.SHUT_RDWR]
        assert b.calls == [socket_mod.SHUT_RDWR]

    def test_an_already_closed_socket_does_not_stop_the_others(self):
        """Connections close on their own; one raising must not abandon the cancellation."""
        from app.ai.client import _abort_client_connections

        dead, live = self._Sock(boom=OSError("closed")), self._Sock()
        assert _abort_client_connections(self._client(dead, live)) == 1
        assert live.calls, "the second socket must still be reached"

    @pytest.mark.parametrize(
        "client",
        [
            object(),  # no _transport at all
            type("C", (), {"_transport": object()})(),  # no _pool
            type("C", (), {"_transport": type("T", (), {"_pool": object()})()})(),  # no _connections
        ],
    )
    def test_an_unrecognised_shape_returns_zero_rather_than_raising(self, client):
        """The degradation contract: a future httpx loses the fast cancel, not the run."""
        from app.ai.client import _abort_client_connections

        assert _abort_client_connections(client) == 0

    def test_a_connection_with_no_socket_yet_is_skipped(self):
        """A connection still handshaking has no `_sock`; that is not an error."""
        from app.ai.client import _abort_client_connections

        assert _abort_client_connections(self._client(None)) == 0

    def test_the_watcher_aborts_as_well_as_closing(self):
        """Both, and in that order — close() is still what releases the pool."""
        from app.ai.client import _StreamActivity, _watch_for_cancel

        order = []

        class Client:
            _transport = None

            def close(self):
                order.append("close")

        import app.ai.client as mod

        original = mod._abort_client_connections
        mod._abort_client_connections = lambda c: order.append("abort") or 0
        try:
            activity = _StreamActivity()
            activity.last -= _CANCEL_TEARDOWN_IDLE_SECONDS + 5
            cancel = threading.Event()
            cancel.set()
            stop = _watch_for_cancel(cancel, Client(), activity)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and "close" not in order:
                time.sleep(0.05)
            stop()
        finally:
            mod._abort_client_connections = original

        assert order == ["abort", "close"], f"expected abort then close, got {order}"
