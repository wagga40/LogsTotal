"""Tier-1 tests for app.ai.providers — pure, no DB, no network, no FastAPI.

Three things are pinned here.

**The URL join**, because operators paste base URLs with and without a trailing slash in
roughly equal measure and ``urljoin`` would eat the last path segment of ``http://host/v1``
— turning a correct configuration into a 404 that reads like a broken endpoint.

**The credential boundary**: the token appears in a request *header* and nowhere else. That
is what lets the caller put a failed request's URL into ``JobAiAnalysis.error_message``
without leaking it. The absence of the auth header when there is no token is equally
load-bearing — it is what a local Ollama needs.

**Every failure is an AiProviderError**, never a bare ``KeyError``/``IndexError`` escaping
into the worker, because the worker turns the message into the row's ``error_message`` and
a traceback string there tells an admin nothing about the model name they mistyped.
"""

from __future__ import annotations

import json

import pytest

from app.ai.providers import (
    ANTHROPIC_VERSION,
    PROVIDER_KINDS,
    AiProviderError,
    build_request,
    normalize_base_url,
    parse_response,
    parse_stream_event,
)

TOKEN = "sk-live-SUPER-SECRET-9f3c2b1a"

ENDPOINT_PATH = {"openai": "chat/completions", "anthropic": "messages"}


def _build(kind: str, **kw):
    args = {
        "kind": kind,
        "base_url": "http://llm.internal/v1",
        "model": "test-model",
        "token": TOKEN,
        "system": "SYSTEM PROMPT",
        "user": "=== JOB BRIEF ===\nuser content",
    }
    args.update(kw)
    return build_request(**args)


@pytest.mark.parametrize("kind", PROVIDER_KINDS)
def test_default_output_budget(kind):
    _url, _headers, body = _build(kind)
    assert body["max_tokens"] == 20_000


# ── URL join ───────────────────────────────────────────────────────────────────


class TestUrlJoin:
    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    @pytest.mark.parametrize("base", ["http://h/v1", "http://h/v1/", "http://h/v1//"])
    def test_trailing_slash_does_not_change_the_endpoint(self, kind, base):
        url, _headers, _body = _build(kind, base_url=base)
        assert url == f"http://h/v1/{ENDPOINT_PATH[kind]}"

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_a_bare_host_gets_the_path_appended(self, kind):
        url, _headers, _body = _build(kind, base_url="http://localhost:11434")
        assert url == f"http://localhost:11434/{ENDPOINT_PATH[kind]}"

    def test_the_last_path_segment_is_never_dropped(self):
        # The urljoin trap: urljoin("http://h/v1", "chat/completions") loses "/v1".
        url, _headers, _body = _build("openai", base_url="https://api.example.test/openai/v1")
        assert url == "https://api.example.test/openai/v1/chat/completions"


# ── Request shapes ─────────────────────────────────────────────────────────────


class TestOpenAiRequest:
    def test_bearer_header_when_a_token_is_configured(self):
        _url, headers, _body = _build("openai")
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        assert headers["Content-Type"] == "application/json"

    def test_the_auth_header_is_absent_entirely_without_a_token(self):
        # A local Ollama rejects nothing, but an empty "Authorization: Bearer " header is
        # a 401 on several OpenAI-compatible gateways. Absent, not blank.
        _url, headers, _body = _build("openai", token=None)
        assert "Authorization" not in headers
        assert headers == {"Content-Type": "application/json"}

    def test_an_empty_token_is_treated_as_no_token(self):
        _url, headers, _body = _build("openai", token="")
        assert "Authorization" not in headers

    def test_body_carries_system_and_user_as_messages(self):
        _url, _headers, body = _build("openai")
        assert body["model"] == "test-model"
        assert body["messages"] == [
            {"role": "system", "content": "SYSTEM PROMPT"},
            {"role": "user", "content": "=== JOB BRIEF ===\nuser content"},
        ]
        assert body["stream"] is False

    def test_temperature_and_max_output_tokens_are_passed_through(self):
        _url, _headers, body = _build("openai", temperature=0.7, max_output_tokens=1234)
        assert body["temperature"] == 0.7
        assert body["max_tokens"] == 1234


class TestAnthropicRequest:
    def test_api_key_and_version_headers(self):
        _url, headers, _body = _build("anthropic")
        assert headers["x-api-key"] == TOKEN
        assert headers["anthropic-version"] == ANTHROPIC_VERSION
        assert headers["Content-Type"] == "application/json"

    def test_version_header_survives_a_missing_token(self):
        _url, headers, _body = _build("anthropic", token=None)
        assert "x-api-key" not in headers
        # Anthropic treats a missing anthropic-version as an error, token or not.
        assert headers["anthropic-version"] == ANTHROPIC_VERSION

    def test_system_prompt_is_a_top_level_field_not_a_message(self):
        _url, _headers, body = _build("anthropic")
        assert body["system"] == "SYSTEM PROMPT"
        assert body["messages"] == [{"role": "user", "content": "=== JOB BRIEF ===\nuser content"}]
        # A system *message* is a 400 on this API.
        assert all(m["role"] != "system" for m in body["messages"])

    def test_temperature_and_max_output_tokens_are_passed_through(self):
        _url, _headers, body = _build("anthropic", temperature=0.7, max_output_tokens=1234)
        assert body["temperature"] == 0.7
        assert body["max_tokens"] == 1234


class TestTokenNeverLeavesTheHeaders:
    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_token_appears_in_no_url_and_in_no_body(self, kind):
        url, headers, body = _build(kind)
        assert TOKEN not in url
        assert TOKEN not in json.dumps(body)
        # …and it really is being sent, in exactly one header value.
        assert sum(1 for v in headers.values() if TOKEN in str(v)) == 1

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_token_is_not_a_header_name_either(self, kind):
        _url, headers, _body = _build(kind)
        assert all(TOKEN not in name for name in headers)

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_a_token_shaped_base_url_is_still_the_only_place_it_could_be(self, kind):
        # Guards the inverse mistake: interpolating the token into the URL "for Ollama".
        url, _headers, body = _build(kind, base_url="http://llm.internal/v1", token=TOKEN)
        assert "sk-" not in url
        assert "sk-" not in json.dumps(body)


# ── Response parsing ───────────────────────────────────────────────────────────


class TestParseSuccess:
    def test_openai_shape(self):
        body = {
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "## Verdict\nlooks benign"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1234, "completion_tokens": 56},
        }
        text, usage = parse_response("openai", body)
        assert text == "## Verdict\nlooks benign"
        assert usage == {"input_tokens": 1234, "output_tokens": 56}

    def test_anthropic_shape(self):
        body = {
            "content": [{"type": "text", "text": "## Verdict\nlooks benign"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1234, "output_tokens": 56},
        }
        text, usage = parse_response("anthropic", body)
        assert text == "## Verdict\nlooks benign"
        assert usage == {"input_tokens": 1234, "output_tokens": 56}

    def test_anthropic_keeps_text_blocks_in_order_and_ignores_the_rest(self):
        body = {"content": [{"type": "thinking", "thinking": "hmm"}, {"type": "text", "text": "one "}, {"type": "text", "text": "two"}]}
        text, _usage = parse_response("anthropic", body)
        assert text == "one two"

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_missing_usage_is_not_a_failure(self, kind):
        # Ollama omits token counts; a missing count is not an error.
        body = {"choices": [{"message": {"content": "ok"}}]} if kind == "openai" else {"content": [{"type": "text", "text": "ok"}]}
        text, usage = parse_response(kind, body)
        assert text == "ok"
        assert usage == {"input_tokens": None, "output_tokens": None}

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_kind_is_case_insensitive(self, kind):
        body = {"choices": [{"message": {"content": "ok"}}]} if kind == "openai" else {"content": [{"type": "text", "text": "ok"}]}
        assert parse_response(kind.upper(), body)[0] == "ok"


class TestParseFailures:
    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    @pytest.mark.parametrize("body", ["a string", 42, None, ["a", "list"], b"bytes"])
    def test_a_non_object_body_is_a_provider_error(self, kind, body):
        with pytest.raises(AiProviderError, match="not a JSON object"):
            parse_response(kind, body)

    def test_openai_empty_or_missing_choices(self):
        for body in ({"choices": []}, {}, {"choices": None}, {"choices": "nope"}):
            with pytest.raises(AiProviderError, match="no choices"):
                parse_response("openai", body)

    def test_anthropic_empty_or_missing_content(self):
        for body in ({"content": []}, {}, {"content": None}, {"content": "nope"}):
            with pytest.raises(AiProviderError, match="no content blocks"):
                parse_response("anthropic", body)

    def test_openai_missing_text(self):
        for body in ({"choices": [{"message": {}}]}, {"choices": [{"message": {"content": "   "}}]}, {"choices": [{}]}, {"choices": ["not a dict"]}):
            with pytest.raises(AiProviderError, match="no text"):
                parse_response("openai", body)

    def test_anthropic_missing_text(self):
        for body in ({"content": [{"type": "thinking", "thinking": "…"}]}, {"content": [{"type": "text", "text": "  "}]}, {"content": ["not a dict"]}):
            with pytest.raises(AiProviderError, match="no text"):
                parse_response("anthropic", body)

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_a_provider_error_object_carries_the_providers_own_message(self, kind):
        with pytest.raises(AiProviderError, match="model 'gtp-4' not found"):
            parse_response(kind, {"error": {"message": "model 'gtp-4' not found", "type": "invalid_request_error"}})

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_a_provider_error_string_is_reported_too(self, kind):
        # Ollama answers a bad model name with {"error": "model not found"}.
        with pytest.raises(AiProviderError, match="model not found"):
            parse_response(kind, {"error": "model not found"})

    def test_a_long_provider_message_is_bounded(self):
        with pytest.raises(AiProviderError) as excinfo:
            parse_response("openai", {"error": {"message": "x" * 5000}})
        assert len(str(excinfo.value)) <= 300

    @pytest.mark.parametrize("kind", PROVIDER_KINDS)
    def test_failures_are_never_a_bare_key_or_index_error(self, kind):
        """Every malformed shape reaches the worker as AiProviderError, not a traceback."""
        malformed = [
            {},
            {"choices": [{}]},
            {"choices": [[]]},
            {"content": [{}]},
            {"content": [[]]},
            {"choices": {}, "content": {}},
            {"usage": "nope"},
        ]
        for body in malformed:
            with pytest.raises(AiProviderError):
                parse_response(kind, body)


class TestOutputTokenLimit:
    def test_openai_finish_reason_length_with_empty_content(self):
        body = {"choices": [{"message": {"content": ""}, "finish_reason": "length"}], "usage": {"completion_tokens": 2000}}
        with pytest.raises(AiProviderError) as excinfo:
            parse_response("openai", body)
        message = str(excinfo.value).lower()
        assert "token" in message and "limit" in message

    def test_anthropic_stop_reason_max_tokens(self):
        body = {"content": [{"type": "text", "text": ""}], "stop_reason": "max_tokens"}
        with pytest.raises(AiProviderError) as excinfo:
            parse_response("anthropic", body)
        message = str(excinfo.value).lower()
        assert "token" in message and "limit" in message

    def test_a_reasoning_model_that_spends_its_budget_on_thinking(self):
        body = {"content": [{"type": "thinking", "thinking": "…"}], "stop_reason": "max_tokens"}
        with pytest.raises(AiProviderError, match="output-token limit"):
            parse_response("anthropic", body)

    def test_the_limit_message_is_distinct_from_plain_no_text(self):
        stopped = {"choices": [{"message": {"content": ""}, "finish_reason": "stop"}]}
        with pytest.raises(AiProviderError, match="no text"):
            parse_response("openai", stopped)


class TestUnknownKind:
    @pytest.mark.parametrize("kind", ["gemini", "", None, "openai-compatible"])
    def test_build_request_refuses_rather_than_defaulting_to_a_shape(self, kind):
        # Silently treating an Anthropic row as OpenAI-compatible produces a 404 that reads
        # like a wrong base URL.
        with pytest.raises(AiProviderError, match="unknown provider kind"):
            _build(kind)

    @pytest.mark.parametrize("kind", ["gemini", "", None])
    def test_parse_response_refuses_too(self, kind):
        with pytest.raises(AiProviderError, match="unknown provider kind"):
            parse_response(kind, {"choices": [{"message": {"content": "ok"}}]})

    def test_the_error_names_the_kinds_that_do_work(self):
        with pytest.raises(AiProviderError) as excinfo:
            _build("gemini")
        for kind in PROVIDER_KINDS:
            assert kind in str(excinfo.value)

    def test_every_registered_kind_actually_builds(self):
        for kind in PROVIDER_KINDS:
            url, headers, body = _build(kind)
            assert url.startswith("http://llm.internal/v1/")
            assert headers["Content-Type"] == "application/json"
            assert body["model"] == "test-model"


class TestBaseUrlNormalisation:
    """A pasted endpoint URL must not have the endpoint appended to it a second time.

    Every provider documents the *full* endpoint — `https://openrouter.ai/api/v1/chat/completions`,
    `https://api.anthropic.com/v1/messages` — so pasting that into a field labelled "Base URL"
    is the default behaviour, not a careless one. Appended twice, the path makes the provider
    answer `{"error":{"message":"Not Found","code":404}}`, whose text points at nothing and
    sends an admin off to check a model name that is correct all along.
    """

    @pytest.mark.parametrize(
        "kind,base,expected",
        [
            ("openai", "https://openrouter.ai/api/v1/chat/completions", "https://openrouter.ai/api/v1/chat/completions"),
            ("openai", "https://openrouter.ai/api/v1/chat/completions/", "https://openrouter.ai/api/v1/chat/completions"),
            ("openai", "https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1/chat/completions"),
            ("openai", "https://openrouter.ai/api/v1/", "https://openrouter.ai/api/v1/chat/completions"),
            ("openai", "https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/chat/completions"),
            ("openai", "http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions"),
            ("anthropic", "https://api.anthropic.com/v1/messages", "https://api.anthropic.com/v1/messages"),
            ("anthropic", "https://api.anthropic.com/v1/messages/", "https://api.anthropic.com/v1/messages"),
            ("anthropic", "https://api.anthropic.com/v1", "https://api.anthropic.com/v1/messages"),
        ],
    )
    def test_every_spelling_of_a_base_url_reaches_one_endpoint(self, kind, base, expected):
        url, _headers, _body = build_request(kind=kind, base_url=base, model="m", token="t", system="s", user="u")
        assert url == expected

    def test_the_endpoint_is_never_doubled(self):
        """The specific case: a 404 from a path appended to itself."""
        url, _h, _b = build_request(
            kind="openai",
            base_url="https://openrouter.ai/api/v1/chat/completions",
            model="google/gemini-3.7-flash",
            token="t",
            system="s",
            user="u",
        )
        assert url.count("/chat/completions") == 1

    @pytest.mark.parametrize(
        "base",
        [
            "https://host/messages-api/v1",  # merely contains the word
            "https://host/v1/chat/completions/extra",  # the endpoint is not the tail
            "https://host/v1",
            "https://host",
        ],
    )
    def test_a_url_that_is_not_an_endpoint_is_left_alone(self, base):
        assert normalize_base_url(base) == base.rstrip("/")

    def test_normalisation_is_idempotent(self):
        once = normalize_base_url("https://openrouter.ai/api/v1/chat/completions")
        assert normalize_base_url(once) == once

    @pytest.mark.parametrize("junk", ["", "   ", None])
    def test_junk_does_not_raise(self, junk):
        assert normalize_base_url(junk) == ""


class TestStreamRequestShape:
    """`stream=True` must change the body and nothing else.

    A streamed request is the same request: same URL, same auth header, same model. If it
    were not, every failure of the streaming path would also be a failure of the
    non-streaming one and neither could be diagnosed from the other.
    """

    @pytest.mark.parametrize("kind", sorted(PROVIDER_KINDS))
    def test_the_url_and_headers_are_untouched(self, kind):
        plain_url, plain_headers, _ = _build(kind)
        stream_url, stream_headers, _ = _build(kind, stream=True)
        assert stream_url == plain_url
        assert stream_headers == plain_headers

    @pytest.mark.parametrize("kind", sorted(PROVIDER_KINDS))
    def test_the_token_still_appears_only_in_a_header(self, kind):
        _, headers, body = _build(kind, stream=True)
        assert TOKEN in json.dumps(headers)
        assert TOKEN not in json.dumps(body), "the credential must never reach the request body"

    def test_openai_asks_for_usage_because_a_stream_otherwise_reports_none(self):
        """Without `stream_options`, a streamed OpenAI-shaped reply carries no token counts.

        The panel shows "in / out" for every run; silently losing it on the streaming path
        would look like the provider stopped reporting.
        """
        _, _, body = _build("openai", stream=True)
        assert body["stream"] is True
        assert body["stream_options"] == {"include_usage": True}

    def test_openai_does_not_ask_for_usage_when_not_streaming(self):
        _, _, body = _build("openai")
        assert body["stream"] is False
        assert "stream_options" not in body

    def test_anthropic_sets_stream_only_when_asked(self):
        assert _build("anthropic", stream=True)[2]["stream"] is True
        assert "stream" not in _build("anthropic")[2]


class TestStreamEventParsing:
    """One decoded SSE `data:` object -> (text delta, usage or None).

    The governing rule is that an unrecognised event is **not** an error. A live stream
    carries pings, `event:` names, provider-specific extras and shapes that postdate this
    code; treating any of them as fatal would abort a generation that was going fine. The
    single exception is an explicit error object, which is the provider refusing mid-stream
    and is the one thing that must surface.
    """

    def test_openai_text_delta(self):
        event = {"choices": [{"delta": {"content": "Hello"}}]}
        assert parse_stream_event("openai", event) == ("Hello", None)

    def test_openai_usage_frame_carries_no_text(self):
        event = {"choices": [], "usage": {"prompt_tokens": 120, "completion_tokens": 45}}
        text, usage = parse_stream_event("openai", event)
        assert text == ""
        assert usage == {"input_tokens": 120, "output_tokens": 45}

    def test_openai_role_only_first_frame_is_not_text(self):
        """The opening frame announces the role and has no content — a real wire case."""
        assert parse_stream_event("openai", {"choices": [{"delta": {"role": "assistant"}}]}) == ("", None)

    def test_anthropic_text_delta(self):
        event = {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Hi"}}
        assert parse_stream_event("anthropic", event) == ("Hi", None)

    def test_anthropic_thinking_delta_is_not_answer_text(self):
        """A reasoning delta is not the answer; counting it would corrupt the content."""
        event = {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "hmm"}}
        assert parse_stream_event("anthropic", event) == ("", None)

    def test_anthropic_message_start_carries_the_input_count(self):
        event = {"type": "message_start", "message": {"usage": {"input_tokens": 900, "output_tokens": 1}}}
        assert parse_stream_event("anthropic", event) == ("", {"input_tokens": 900, "output_tokens": 1})

    def test_anthropic_message_delta_refreshes_only_the_output_count(self):
        """It reports a running total for output alone, which is why the caller merges."""
        event = {"type": "message_delta", "usage": {"output_tokens": 77}}
        assert parse_stream_event("anthropic", event) == ("", {"output_tokens": 77})

    @pytest.mark.parametrize(
        "event",
        [
            {},
            {"type": "ping"},
            {"type": "content_block_start"},
            {"choices": []},
            {"choices": [None]},
            {"choices": [{"delta": None}]},
            {"choices": [{"delta": {"content": None}}]},
            {"usage": "not-a-dict"},
            {"type": "something_invented_next_year", "payload": {"deep": [1, 2]}},
        ],
    )
    @pytest.mark.parametrize("kind", sorted(PROVIDER_KINDS))
    def test_an_unrecognised_frame_is_silence_not_a_crash(self, kind, event):
        assert parse_stream_event(kind, event) == ("", None)

    @pytest.mark.parametrize("event", ["a string", 42, None, ["list"]])
    def test_a_non_dict_payload_is_ignored(self, event):
        assert parse_stream_event("openai", event) == ("", None)

    def test_an_unknown_kind_is_ignored_rather_than_raising(self):
        assert parse_stream_event("gopher", {"choices": [{"delta": {"content": "x"}}]}) == ("", None)

    @pytest.mark.parametrize("kind", sorted(PROVIDER_KINDS))
    def test_an_error_object_mid_stream_surfaces(self, kind):
        with pytest.raises(AiProviderError, match="rate limit"):
            parse_stream_event(kind, {"error": {"message": "rate limit exceeded"}})

    @pytest.mark.parametrize("kind", sorted(PROVIDER_KINDS))
    def test_an_error_string_mid_stream_surfaces_too(self, kind):
        with pytest.raises(AiProviderError, match="upstream died"):
            parse_stream_event(kind, {"error": "upstream died"})

    def test_a_long_mid_stream_error_is_bounded(self):
        with pytest.raises(AiProviderError) as excinfo:
            parse_stream_event("openai", {"error": {"message": "x" * 5000}})
        assert len(str(excinfo.value)) <= 300
