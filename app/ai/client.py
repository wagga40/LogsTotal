"""One outbound completion request. Sync, worker-side only.

**Which SSRF guard, and why.** This does *not* use
``live_enrichment.resolve_and_validate_url``, which rejects every non-public address. It uses
``app.intel.webhooks.validate_url_addresses``, the guard written for admin/owner-configured
receivers, with ``require_public=settings.ai_require_public_host`` (default ``False``).
The reference deployment for this feature is an Ollama on ``127.0.0.1``; a public-only
guard would reject it, and every self-hosted install with it. What stays unconditional is
the part that has no legitimate use: the cloud metadata address is blocked either way, and
the connection is pinned to the address that was approved so a short-TTL DNS record cannot
rebind between the check and the request.

The stricter posture is one env var away, and ``docs/security.md`` states the boundary.

**The token never leaves the header dict.** ``build_request`` puts it in a header and
nowhere else, and every error path here reports an exception *type* plus our own wording —
never ``str(exc)``, which for httpx can carry the request URL. Nothing from this module
reaches a log line or ``JobAiAnalysis.error_message`` with a credential in it.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import NamedTuple
from urllib.parse import urlparse

from app.ai.providers import SSE_DONE, AiProviderError, build_request, parse_response, parse_stream_event
from app.intel.webhooks import WebhookError, validate_url_addresses
from app.json_utils import loads as json_loads
from app.network.url_pinning import pin_url_to_ip

_log = logging.getLogger(__name__)

# Generous next to enrichment's 64 KB: this body is the answer we are here for, and a long
# analysis of a busy job is legitimately tens of kilobytes. Still bounded, and still
# enforced while streaming rather than after the fact — `.content` only exists once the
# whole body has been read, which is not a limit at all.
MAX_RESPONSE_BYTES = 1024 * 1024

# Distinguishes "the user stopped this" from a failure, the way `tools.base.CANCELLED_ERROR`
# does for a tool. The worker maps it to a CANCELLED status rather than FAILED.
CANCELLED_ERROR = "cancelled"

# How much text must arrive before the run narrates itself again. Frequent enough that a
# slow model visibly progresses, rare enough that the log stays readable and the row is not
# rewritten on every token.
PROGRESS_EVERY_CHARS = 400

# A connect that has not completed in this long is a dead address, whatever the model
# timeout says. It is bounded *separately* from `timeout` because the validated addresses
# are tried in order: with one value applied to every phase, a single blackholed address
# burns the whole budget before the one that would have worked is even attempted. That is
# not hypothetical here — `localhost` yields ::1 first and a local Ollama listens only on
# 127.0.0.1 (see the address loop below).
CONNECT_TIMEOUT_SECONDS = 10.0

# Bound on the body kept when a provider turns out not to be streaming at all. It only has
# to hold one JSON completion, and it exists so a provider that answers a stream request
# with an endless non-SSE body cannot be buffered without limit.
_NON_STREAM_MAX_CHARS = MAX_RESPONSE_BYTES


class StreamOutcome(NamedTuple):
    """What one pass over a streamed response produced.

    ``outcome`` is ``""`` for a clean finish, or ``cancelled`` / ``stalled`` / ``over_cap``
    / ``not_a_stream``. The last one is not an error: it means the provider ignored
    ``stream: true`` and replied with a single JSON object, whose text is in ``body`` for
    the ordinary non-streaming parser to handle.
    """

    text: str
    usage: dict
    outcome: str
    body: str


def _read_error_body(response) -> tuple[bytearray, bool]:
    """Read a non-2xx body to the cap. Returns ``(body, hit_cap)``.

    A failing provider replies with an ordinary JSON object rather than a stream, and its
    message is the most useful thing we can show — so this path stays byte-oriented and
    hands off to the non-streaming parser.
    """
    raw = bytearray()
    for chunk in response.iter_bytes():
        raw.extend(chunk)
        if len(raw) > MAX_RESPONSE_BYTES:
            return raw, True
    return raw, False


def _consume_stream(response, *, kind, cancelled, deadline, note, activity=None) -> StreamOutcome:
    """Read one SSE response to completion.

    Split out of :func:`run_completion`: the address-retry loop, the error-body path and the
    token loop are three separate concerns.

    **Not every 2xx is a stream.** Asking for one is a request, not a guarantee: an older
    Ollama, a proxy that buffers, or a gateway that drops unknown body keys will answer with
    a single JSON object. Detecting that here — rather than returning an empty answer and
    blaming the model — is what keeps `stream: true` from being a compatibility break. Any
    SSE framing at all (a ``data:`` line *or* a ``:`` keep-alive comment) proves it is a
    stream; only its total absence triggers the fallback.
    """
    pieces: list[str] = []
    usage: dict = {}
    produced = 0
    last_reported = 0
    saw_frame = False
    first_token_seen = False
    other: list[str] = []
    other_chars = 0

    for line in response.iter_lines():
        # Tells the cancel watcher the stream is alive, so it stands down and lets this
        # loop do the stopping. Every line counts, keep-alive comments included — the point
        # is whether a *next* frame is coming, not whether it carries content.
        if activity is not None:
            activity.touch()
        # Both checks come first, before any parsing: they are the two ways this loop is
        # meant to end early, and a line that takes a slow path to parse should not delay
        # either of them.
        if cancelled():
            return StreamOutcome("".join(pieces), usage, "cancelled", "")
        if time.monotonic() > deadline:
            return StreamOutcome("".join(pieces), usage, "stalled", "")

        if line.startswith(":"):
            # An SSE comment. OpenRouter sends ": OPENROUTER PROCESSING" as a keep-alive,
            # and that keep-alive is the whole reason the wall-clock deadline above exists —
            # it resets httpx's per-operation read timeout indefinitely.
            saw_frame = True
            continue

        payload = _sse_payload(line)
        if payload is None:
            if line and other_chars < _NON_STREAM_MAX_CHARS:
                other.append(line)
                other_chars += len(line) + 1
            continue

        saw_frame = True
        if payload == SSE_DONE:
            break
        try:
            event = json_loads(payload)
        except (ValueError, TypeError):
            continue
        # parse_stream_event raises AiProviderError when the provider reports an error
        # mid-stream. That is deliberately *not* caught here — it is the provider refusing,
        # and run_completion turns it into the run's error message.
        piece, usage_update = parse_stream_event(kind, event)
        if piece:
            if not first_token_seen:
                first_token_seen = True
                note("First tokens received — the model is writing.")
            pieces.append(piece)
            produced += len(piece)
            if produced - last_reported >= PROGRESS_EVERY_CHARS:
                last_reported = produced
                note(f"Receiving the answer — {produced} characters so far.")
        if usage_update:
            usage.update({k: v for k, v in usage_update.items() if v is not None})
        if produced > MAX_RESPONSE_BYTES:
            return StreamOutcome("".join(pieces), usage, "over_cap", "")

    if not saw_frame:
        return StreamOutcome("", {}, "not_a_stream", "\n".join(other))
    return StreamOutcome("".join(pieces), usage, "", "")


def _sse_payload(line: str) -> str | None:
    """The `data:` value of one SSE line, or None for framing we do not care about.

    Streams carry blank keep-alive lines, `event:` names and comments; treating any of them
    as content is how a parser ends up with stray characters in the answer.
    """
    if not line:
        return None
    if line.startswith("data:"):
        return line[5:].strip()
    return None


# How often the watcher re-checks the cancel flag while a request is in flight.
_CANCEL_POLL_SECONDS = 0.5

# How long the stream must have been silent before the watcher is allowed to tear the
# connection down. See _watch_for_cancel — this constant is the whole design.
_CANCEL_TEARDOWN_IDLE_SECONDS = 2.0


def _abort_client_connections(client) -> int:
    """Shut down every live socket in *client*'s pool. Returns how many were shut.

    **``Client.close()`` is not enough.** A sync httpx request blocked waiting for response
    headers is inside a plain ``recv()``; closing the client returns the connection to the
    pool and marks the transport closed, but it does not touch the descriptor the reader is
    parked on. Measured: a cancel during that window waits out the *entire* remaining
    timeout — 40s in the harness, and in practice the
    whole of a local model's prompt-processing phase, which is precisely when a user is most
    likely to press Stop. ``shutdown(SHUT_RDWR)`` is the call that unblocks a reader in
    another thread; it returns immediately with a protocol error, which the caller maps to
    "cancelled" because it checks the flag first.

    It is also what actually frees the provider. Dropping the connection is what makes a
    local model stop generating — a cancel that leaves the GPU busy has only hidden the run.

    **This reaches into httpx/httpcore internals**, and does so deliberately: the sync client
    exposes no cancellation API at all, and the alternative is abandoning the request thread
    and lying about having stopped it. Every step is guarded, so a future httpx that moves
    these attributes degrades to the run ending at its timeout rather than raising.
    `test_ai_client_stream.py` pins the walk and the degradation.
    """
    aborted = 0
    try:
        connections = list(getattr(client._transport._pool, "_connections", None) or [])
    except Exception:
        return 0
    for conn in connections:
        try:
            stream = getattr(getattr(conn, "_connection", None), "_network_stream", None)
            sock = getattr(stream, "_sock", None)
            if sock is None:
                continue
            sock.shutdown(socket.SHUT_RDWR)
            aborted += 1
        except Exception:
            # An already-closed socket, a connection mid-handshake, or a shape we do not
            # recognise. None of them is worth failing a cancellation over.
            continue
    return aborted


class _StreamActivity:
    """When the read loop last saw a line. Shared with the cancel watcher.

    One float behind two threads, written by the reader and read by the watcher. No lock:
    a float assignment is atomic under the GIL, and the only consumer is a "has it been
    quiet for a couple of seconds?" comparison that a stale read cannot get dangerously
    wrong in either direction.
    """

    __slots__ = ("last",)

    def __init__(self) -> None:
        self.last = time.monotonic()

    def touch(self) -> None:
        self.last = time.monotonic()

    def idle_for(self) -> float:
        return time.monotonic() - self.last


def _watch_for_cancel(cancel_event, closeable, activity: _StreamActivity):
    """Tear *closeable* down when a cancel cannot be honoured any other way.

    *closeable* is the ``httpx.Client``, not the response, and it is watched from **before**
    the request is sent. A provider emits no response headers until it begins generating, so
    for the whole of prompt processing (26.5s for a 34k brief on a local model) there is no
    response object in existence — watching one would silently defer Stop until the model
    speaks (16s, measured). Teardown goes through :func:`_abort_client_connections`,
    because ``close()`` on its own cannot reach a reader already blocked in that window.

    **The read loop is the primary mechanism**, not this. It checks the cancel flag between
    frames, so on a stream that is producing anything at all a cancel is honoured within one
    frame and the connection closes cleanly on the way out.

    This thread exists for the two phases the loop cannot cover: waiting for headers, and a
    model that sends nothing while it thinks — in both, the reader is blocked inside a single
    socket read and there is no next frame to check on.

    The idle guard is the load-bearing part: the obvious version — close as soon as the flag
    appears — is **slower than doing nothing**. Closing an httpx response from another
    thread does not interrupt a read already in progress; it leaves the reader blocked until
    the read timeout expires. Racing the loop that way turns a one-second cancel into a
    sixty-second one, measured. So the watcher stands
    down whenever frames are still arriving, and only reaches for the socket once the
    stream has genuinely gone quiet.
    """
    if cancel_event is None:
        return lambda: None

    done = threading.Event()

    def _watch():
        while not done.wait(_CANCEL_POLL_SECONDS):
            if not cancel_event.is_set():
                continue
            if activity.idle_for() < _CANCEL_TEARDOWN_IDLE_SECONDS:
                # Frames are still arriving: the read loop will stop itself, cleanly.
                continue
            # Order matters. The socket shutdown is what unblocks a reader parked on a
            # recv(); close() alone leaves it there until the timeout. Both, because
            # close() is still what releases the pool.
            _abort_client_connections(closeable)
            try:
                closeable.close()
            except Exception:
                pass
            return

    threading.Thread(target=_watch, name="ai-cancel-watch", daemon=True).start()
    return done.set


class _Attempt(NamedTuple):
    """One request to one pinned address, as far as it got.

    ``result`` is ``None`` for a non-2xx, where the body is in ``raw`` for the ordinary
    JSON parser — a failing provider puts its most useful message there, and "model not
    found" beats "HTTP 404".
    """

    status_code: int
    encoding: str
    raw: bytearray
    over_cap: bool
    result: StreamOutcome | None


def _send_once(httpx, *, url, body, headers, extensions, client_timeout, kind, cancelled, cancel_event, deadline, note) -> _Attempt:
    """Send the request to one already-validated address and read the reply.

    Extracted from :func:`run_completion` so the address-retry loop reads as a loop. The
    ``httpx`` module is passed in because the caller imports it lazily — this module is
    imported by the worker at startup and the dependency is only needed on a real run.
    """
    with httpx.Client(timeout=client_timeout, follow_redirects=False) as client:
        # The watcher guards the client and starts before the request, not after the response
        # headers arrive — see `_watch_for_cancel` for the measurement behind that ordering.
        activity = _StreamActivity()
        stop_watching = _watch_for_cancel(cancel_event, client, activity)
        try:
            with client.stream("POST", url, json=body, headers=headers, extensions=extensions) as resp:
                activity.touch()  # headers arrived; the silent phase is over
                encoding = resp.encoding or "utf-8"
                if resp.status_code >= 400:
                    raw, over_cap = _read_error_body(resp)
                    return _Attempt(resp.status_code, encoding, raw, over_cap, None)
                note(f"Provider accepted the request (HTTP {resp.status_code}); waiting for the model.")
                result = _consume_stream(resp, kind=kind, cancelled=cancelled, deadline=deadline, note=note, activity=activity)
                return _Attempt(resp.status_code, encoding, bytearray(), False, result)
        finally:
            stop_watching()


EMPTY_ANSWER_ERROR = "the model returned an empty answer — raise Max output tokens if it is a reasoning model"


def _read_whole_body(text_body: str, *, kind: str, status_code: int) -> tuple[str, dict, str | None]:
    """Interpret a complete (non-streamed) body. Returns ``(text, usage, error)``.

    Serves two callers that look different and are not: a non-2xx error body, and a 2xx
    from a provider that ignored ``stream: true``. Both are one JSON object and both want
    the provider's own message rather than ours.
    """
    try:
        parsed = json_loads(text_body)
    except (ValueError, TypeError):
        snippet = " ".join(text_body.split())[:200]
        detail = f" — {snippet}" if snippet else ""
        return "", {}, f"HTTP {status_code}: response was not JSON{detail}"

    # Parse before branching on status: providers put their most useful message in the
    # error body of a 4xx, and "model not found" beats "HTTP 404".
    try:
        text, usage = parse_response(kind, parsed)
    except AiProviderError as exc:
        prefix = "" if status_code < 400 else f"HTTP {status_code}: "
        return "", {}, f"{prefix}{exc}{_status_hint(status_code, str(exc))}"[:400]

    if status_code >= 400:
        return "", {}, f"HTTP {status_code} from the provider"
    if not (text or "").strip():
        return "", {}, EMPTY_ANSWER_ERROR
    return text, usage, None


def _status_hint(status_code: int, message: str) -> str:
    """Append the question the status code is really asking, when the provider won't.

    A gateway answering a wrong path says ``"Not Found"`` and nothing else, which sends an
    admin to check the model name — the one thing that is usually right. The base URL is
    normalised before the request, so a doubled endpoint path is not the cause; what
    remains is a base URL missing its version prefix, or a genuinely unknown
    model. Say both, and only when the provider's own message is too terse to help.
    """
    if status_code == 404 and len(message) < 60:
        return " — check the Model name, and that the Base URL includes the provider's version prefix (e.g. https://openrouter.ai/api/v1)"
    if status_code in (401, 403):
        return " — check the API token"
    return ""


def run_completion(
    *,
    kind: str,
    base_url: str,
    model: str,
    token: str | None,
    system: str,
    user: str,
    temperature: float = 0.2,
    max_output_tokens: int = 20_000,
    timeout: float = 120.0,
    require_public: bool = False,
    cancel_event=None,
    on_progress=None,
) -> tuple[str | None, dict, int, str | None]:
    """Run one completion.

    Returns ``(text, usage, duration_ms, error)``. Exactly one of ``text`` and ``error`` is
    set. Never raises: the caller is a Huey task whose job is to record the outcome on a
    row, and an exception there would leave the run stuck at ``running`` forever.

    ``cancel_event`` is a ``threading.Event``; when set, the in-flight request is torn down
    and :data:`CANCELLED_ERROR` is returned. ``on_progress`` is an optional ``callable(str)``
    used to narrate the run into the row's log — best-effort, never allowed to raise.

    ``timeout`` is enforced twice, deliberately. httpx's is *per operation*: a server that
    sends one byte before each read deadline keeps a request alive indefinitely, which is
    the shape of a real hang. The wall-clock deadline in the read loop is what actually
    bounds the call.
    """
    import httpx

    started = time.monotonic()
    deadline = started + timeout

    def _elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    def _note(message: str) -> None:
        if on_progress is None:
            return
        try:
            on_progress(message)
        except Exception:
            pass

    def _cancelled() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    try:
        url, headers, body = build_request(
            kind=kind,
            base_url=base_url,
            model=model,
            token=token,
            system=system,
            user=user,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            stream=True,
        )
    except AiProviderError as exc:
        return None, {}, _elapsed(), str(exc)[:400]

    # Validate the URL we will actually request, not the configured base — a base URL can
    # be fine while the joined path resolves somewhere else entirely.
    try:
        addresses = validate_url_addresses(url, require_public=require_public, public_setting_name="AI_REQUIRE_PUBLIC_HOST")
    except WebhookError as exc:
        # WebhookError text references host/IP only, never a credential.
        return None, {}, _elapsed(), f"blocked by SSRF guard: {exc}"[:400]

    parsed_url = urlparse(url)
    # Keep the real hostname as TLS SNI so the certificate is checked against the name, not
    # the pinned IP. Plain http has no SNI to preserve.
    extensions = {"sni_hostname": parsed_url.hostname} if parsed_url.scheme == "https" else None

    over_cap = False
    stalled = False
    aborted = False
    streamed = False
    streamed_text = ""
    streamed_usage: dict = {}
    non_stream_body: str | None = None
    raw = bytearray()
    status_code: int | None = None
    encoding = "utf-8"
    connect_error: str | None = None

    if _cancelled():
        return None, {}, _elapsed(), CANCELLED_ERROR
    # The gap after this line is the longest silence in a run and the one that reads as a
    # hang: a provider sends no response headers at all until it starts generating, which
    # for a local model on a large brief is prompt-processing time. Measured at 26.9s for a
    # 33k-char brief on llama3.2:3b. Saying so here is the difference between a log that has
    # stopped and a log that is waiting.
    _note(f"Sending request to {parsed_url.hostname} for model {model} — no reply arrives until the model starts generating.")

    # Connect fast, read slow. See CONNECT_TIMEOUT_SECONDS: the read phase legitimately
    # takes minutes on a local model, the connect phase never does.
    client_timeout = httpx.Timeout(timeout, connect=min(CONNECT_TIMEOUT_SECONDS, timeout))

    # Try each validated address in turn. They all passed the same guard, so falling
    # through the list costs nothing in safety and buys the case that matters most here:
    # `localhost` resolves to ::1 and 127.0.0.1, and a local Ollama listens only on the
    # latter. Pinning to one address and giving up is how the most likely configuration in
    # the docs fails with "could not reach the provider".
    for index, pinned_ip in enumerate(addresses):
        connect_url, host_header = pin_url_to_ip(url, pinned_ip)
        raw = bytearray()
        try:
            attempt = _send_once(
                httpx,
                url=connect_url,
                body=body,
                headers={**headers, "Host": host_header},
                extensions=extensions,
                client_timeout=client_timeout,
                kind=kind,
                cancelled=_cancelled,
                cancel_event=cancel_event,
                deadline=deadline,
                note=_note,
            )
            status_code = attempt.status_code
            encoding = attempt.encoding
            raw = attempt.raw
            over_cap = attempt.over_cap
            result = attempt.result
            if result is not None:
                if result.outcome == "not_a_stream":
                    # The provider ignored `stream: true`. Hand the body to the ordinary
                    # parser below rather than report an empty answer.
                    _note("Provider replied without streaming; reading the whole response.")
                    non_stream_body = result.body
                else:
                    streamed = True
                    streamed_text = result.text
                    streamed_usage = result.usage
                    aborted = result.outcome == "cancelled"
                    stalled = result.outcome == "stalled"
                    over_cap = result.outcome == "over_cap"
            connect_error = None
            break
        except AiProviderError as exc:
            # The provider refused mid-stream. Another address is the same service, so
            # there is nothing to retry.
            return None, {}, _elapsed(), f"the provider reported an error: {exc}"[:400]
        except httpx.TimeoutException:
            if _cancelled():
                return None, {}, _elapsed(), CANCELLED_ERROR
            # A timeout means we reached something; another address will not help, and
            # retrying would multiply an already-long wait by the address count.
            return None, {}, _elapsed(), f"the model did not respond within {int(timeout)}s — raise the provider's timeout or use a smaller model"
        except httpx.HTTPError as exc:
            # A cancel tears the connection down from the watcher thread, which lands here
            # as a read error. Checking the flag first is what keeps "stopped by the user"
            # from being reported as "could not reach the provider".
            if _cancelled():
                return None, {}, _elapsed(), CANCELLED_ERROR
            # Never str(exc): httpx puts the URL in it, and a misconfigured provider could
            # have a credential in the URL even though we never put one there.
            #
            # Only the *last* address warns. Falling through ::1 to 127.0.0.1 is the normal,
            # expected path for a local Ollama, so warning on each attempt would put a line
            # in the worker log for every successful analysis.
            is_last = index == len(addresses) - 1
            _log.log(
                logging.WARNING if is_last else logging.DEBUG,
                "AI completion attempt %d/%d failed (%s)",
                index + 1,
                len(addresses),
                type(exc).__name__,
            )
            connect_error = f"could not reach the provider ({type(exc).__name__}) — check the base URL and that the service is running"

    if connect_error is not None:
        return None, {}, _elapsed(), connect_error

    if aborted or _cancelled():
        return None, {}, _elapsed(), CANCELLED_ERROR
    if stalled:
        return (
            None,
            {},
            _elapsed(),
            f"the provider sent nothing for {int(timeout)}s and the run was stopped — the request stayed open on keep-alive traffic without producing an answer",
        )
    if over_cap:
        return None, {}, _elapsed(), "the provider's response was too large"

    if streamed:
        if not streamed_text.strip():
            return None, {}, _elapsed(), EMPTY_ANSWER_ERROR
        _note(f"Answer complete: {len(streamed_text)} characters.")
        return streamed_text, dict(streamed_usage), _elapsed(), None

    text_body = non_stream_body if non_stream_body is not None else bytes(raw).decode(encoding, errors="replace")
    text, usage, error = _read_whole_body(text_body, kind=kind, status_code=status_code)
    if error is not None:
        return None, {}, _elapsed(), error
    _note(f"Answer complete: {len(text)} characters.")
    return text, usage, _elapsed(), None
