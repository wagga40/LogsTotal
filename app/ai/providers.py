"""Request/response shapes for the LLM endpoints we talk to. Pure.

Two shapes cover every provider worth naming, so this is a registry of *wire formats*, not
of vendors:

``openai``
    ``POST {base_url}/chat/completions`` — the format Ollama, LM Studio, vLLM, OpenRouter,
    Groq, Together and OpenAI itself all speak. Auth is ``Authorization: Bearer``, and it
    is **omitted entirely when there is no token**, which is what a local Ollama needs.

``anthropic``
    ``POST {base_url}/messages`` — auth is ``x-api-key`` plus a required
    ``anthropic-version``, and the system prompt is a top-level field rather than a message.

The registry idiom is ``app/tools/registry.py``'s: a module-level dict keyed by name, with
one builder and one parser per entry. Adding a third shape means adding one entry.

**The token only ever appears in a header.** Nothing here interpolates it into a URL or a
body, which is what lets the caller put a failed request's URL in an error message without
leaking a credential.
"""

from __future__ import annotations

from typing import Any

# Ordered, because it is also the order the admin form's <select> renders in.
PROVIDER_KINDS: tuple[str, ...] = ("openai", "anthropic")

PROVIDER_LABELS: dict[str, str] = {
    "openai": "OpenAI-compatible (OpenAI, Ollama, LM Studio, vLLM, OpenRouter, Groq…)",
    "anthropic": "Anthropic (Claude)",
}

# Anthropic requires this header on every request and treats its absence as an error.
ANTHROPIC_VERSION = "2023-06-01"

# Example base URLs shown as placeholders on the admin form. Not validation — an
# OpenAI-compatible endpoint can live anywhere.
PROVIDER_BASE_URL_HINTS: dict[str, str] = {
    "openai": "http://localhost:11434/v1",
    "anthropic": "https://api.anthropic.com/v1",
}


class AiProviderError(Exception):
    """A provider returned something we cannot use.

    Raised only with text derived from the response body or our own wording — never with a
    token, which by construction never leaves the header dict.
    """


# The endpoint each kind appends — and therefore the suffix that must be stripped off a
# base URL that already carries it. No real LLM base URL ends in either of these.
_ENDPOINT_PATHS: dict[str, str] = {"openai": "chat/completions", "anthropic": "messages"}


def normalize_base_url(base_url: str, kind: str | None = None) -> str:
    """Strip a trailing endpoint path from a pasted base URL.

    Every provider's documentation shows the **full** endpoint —
    ``https://openrouter.ai/api/v1/chat/completions``, ``https://api.anthropic.com/v1/messages``
    — so pasting that into a field labelled "Base URL" is the default behaviour, not a
    careless one. Without this the path is appended twice and the provider answers 404 with
    a message like ``"Not Found"``, which points at nothing.

    Only the two paths we would otherwise append are stripped, and the check is
    case-insensitive on the suffix while the rest of the URL is left byte-for-byte alone
    (paths can be case-sensitive; the host is not our business here).
    """
    cleaned = (base_url or "").strip().rstrip("/")
    lowered = cleaned.lower()
    # Longest first, so "/chat/completions" is not half-matched by a future "/completions".
    for suffix in sorted({f"/{p}" for p in _ENDPOINT_PATHS.values()}, key=len, reverse=True):
        if lowered.endswith(suffix):
            return cleaned[: -len(suffix)].rstrip("/")
    return cleaned


def _join_url(base_url: str, path: str) -> str:
    """Join a configured base URL with an endpoint path.

    Operators paste base URLs with and without trailing slashes in roughly equal measure,
    and ``urljoin`` would drop the last path segment of ``http://host/v1`` — turning a
    correct configuration into a 404 that reads like a broken endpoint.
    """
    return f"{normalize_base_url(base_url)}/{path.lstrip('/')}"


def _build_openai(*, base_url, model, token, system, user, temperature, max_output_tokens, stream=False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max_output_tokens,
        "stream": bool(stream),
    }
    if stream:
        # Without this the streamed form reports no token counts at all. Supported by
        # OpenAI, OpenRouter and current Ollama; a provider that rejects it says so in an
        # error we surface verbatim, which is a better failure than silently losing usage.
        body["stream_options"] = {"include_usage": True}
    return _join_url(base_url, "chat/completions"), headers, body


def _build_anthropic(*, base_url, model, token, system, user, temperature, max_output_tokens, stream=False):
    headers = {"Content-Type": "application/json", "anthropic-version": ANTHROPIC_VERSION}
    if token:
        headers["x-api-key"] = token
    body: dict[str, Any] = {
        "model": model,
        # Anthropic carries the system prompt as a top-level field, not a message with
        # role="system" — passing one as a message is a 400.
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "temperature": temperature,
        "max_tokens": max_output_tokens,
    }
    if stream:
        body["stream"] = True
    return _join_url(base_url, "messages"), headers, body


def _parse_openai(body: dict) -> tuple[str, dict]:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AiProviderError("response contained no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        # A reasoning model that spends its entire budget on hidden thinking returns an
        # empty content string with finish_reason="length". Saying so beats "no text".
        reason = choices[0].get("finish_reason") if isinstance(choices[0], dict) else None
        if reason == "length":
            raise AiProviderError("the model hit its output-token limit before producing an answer — raise Max output tokens")
        raise AiProviderError("response contained no text")
    usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
    return content, {
        "input_tokens": usage.get("prompt_tokens"),
        "output_tokens": usage.get("completion_tokens"),
    }


def _blocks_have_text(blocks: object) -> bool:
    """True when an Anthropic content list carries at least one non-empty text block."""
    if not isinstance(blocks, list):
        return False
    return any(isinstance(b, dict) and b.get("type") == "text" and str(b.get("text", "")).strip() for b in blocks)


def _parse_anthropic(body: dict) -> tuple[str, dict]:
    blocks = body.get("content")
    # Checked before the shape guard, not after: a reasoning model that spends its whole
    # budget thinking returns `{"content": [], "stop_reason": "max_tokens"}`, and reporting
    # that as "no content blocks" sends an admin looking for a broken endpoint instead of a
    # setting they can raise.
    if body.get("stop_reason") == "max_tokens" and not _blocks_have_text(blocks):
        raise AiProviderError("the model hit its output-token limit before producing an answer — raise Max output tokens")
    if not isinstance(blocks, list) or not blocks:
        raise AiProviderError("response contained no content blocks")
    # Claude may interleave text with thinking/tool blocks; keep the text ones in order.
    parts = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
    text = "".join(parts)
    if not text.strip():
        raise AiProviderError("response contained no text")
    usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
    return text, {
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
    }


_REGISTRY: dict[str, dict[str, Any]] = {
    "openai": {"build": _build_openai, "parse": _parse_openai},
    "anthropic": {"build": _build_anthropic, "parse": _parse_anthropic},
}


def build_request(
    *,
    kind: str,
    base_url: str,
    model: str,
    token: str | None,
    system: str,
    user: str,
    temperature: float = 0.2,
    max_output_tokens: int = 20_000,
    stream: bool = False,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Return ``(url, headers, json_body)`` for one completion request.

    Raises :class:`AiProviderError` for an unknown ``kind`` rather than defaulting to one —
    silently treating an Anthropic row as OpenAI-compatible would produce a 404 that looks
    like a wrong base URL.
    """
    entry = _REGISTRY.get((kind or "").lower())
    if entry is None:
        raise AiProviderError(f"unknown provider kind {kind!r} (expected one of {', '.join(PROVIDER_KINDS)})")
    return entry["build"](
        base_url=base_url,
        model=model,
        token=token,
        system=system,
        user=user,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        stream=stream,
    )


def parse_response(kind: str, body: Any) -> tuple[str, dict]:
    """Extract ``(text, usage)`` from a decoded response body.

    ``usage`` values may be ``None`` — Ollama omits some of them, and a missing token count
    is not a failure. A provider-shaped error body is turned into an
    :class:`AiProviderError` carrying the provider's own message, which is the single most
    useful thing to show an admin who has just mistyped a model name.
    """
    entry = _REGISTRY.get((kind or "").lower())
    if entry is None:
        raise AiProviderError(f"unknown provider kind {kind!r}")
    if not isinstance(body, dict):
        raise AiProviderError("response was not a JSON object")

    err = body.get("error")
    if isinstance(err, dict) and err.get("message"):
        raise AiProviderError(str(err["message"])[:300])
    if isinstance(err, str) and err.strip():
        raise AiProviderError(err[:300])

    return entry["parse"](body)


# ── Streaming ──────────────────────────────────────────────────────────────────
#
# Streaming is here for two reasons that have nothing to do with typing effects. A
# non-streaming completion blocks the worker inside one socket read for the whole
# generation — minutes on a local model — during which a cancel cannot be honoured and
# nothing can be reported. With a stream, bytes arrive continuously: the read loop checks
# the cancel flag between chunks, and dropping the connection there actually stops the
# provider generating. It is also the only honest source of "still working" feedback.

# The sentinel the OpenAI wire format ends with. Not JSON, so it is matched before decoding.
SSE_DONE = "[DONE]"


def _stream_openai(event: dict) -> tuple[str, dict | None]:
    """One decoded `data:` object -> (text delta, usage or None)."""
    text = ""
    choices = event.get("choices")
    if isinstance(choices, list) and choices:
        delta = choices[0].get("delta") if isinstance(choices[0], dict) else None
        if isinstance(delta, dict):
            piece = delta.get("content")
            if isinstance(piece, str):
                text = piece
    usage = event.get("usage")
    if isinstance(usage, dict):
        return text, {"input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens")}
    return text, None


def _stream_anthropic(event: dict) -> tuple[str, dict | None]:
    kind = event.get("type")
    if kind == "content_block_delta":
        delta = event.get("delta")
        if isinstance(delta, dict) and delta.get("type") == "text_delta":
            return str(delta.get("text") or ""), None
        return "", None
    if kind == "message_start":
        message = event.get("message")
        usage = message.get("usage") if isinstance(message, dict) else None
        if isinstance(usage, dict):
            return "", {"input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")}
        return "", None
    if kind == "message_delta":
        usage = event.get("usage")
        if isinstance(usage, dict):
            # Only output_tokens is refreshed here, so the caller merges rather than replaces.
            return "", {"output_tokens": usage.get("output_tokens")}
        return "", None
    return "", None


_STREAM_PARSERS = {"openai": _stream_openai, "anthropic": _stream_anthropic}


def parse_stream_event(kind: str, event: Any) -> tuple[str, dict | None]:
    """Extract ``(text_delta, usage_or_None)`` from one decoded SSE ``data:`` payload.

    Never raises on a shape it does not recognise — a stream carries keep-alives, ping
    events and provider-specific extras, and treating an unknown one as fatal would abort a
    perfectly good generation. An explicit error object is the exception: that is the
    provider refusing mid-stream, and it must surface.
    """
    parser = _STREAM_PARSERS.get((kind or "").lower())
    if parser is None or not isinstance(event, dict):
        return "", None
    err = event.get("error")
    if isinstance(err, dict) and err.get("message"):
        raise AiProviderError(str(err["message"])[:300])
    if isinstance(err, str) and err.strip():
        raise AiProviderError(err[:300])
    try:
        return parser(event)
    except (KeyError, TypeError, ValueError):
        return "", None
