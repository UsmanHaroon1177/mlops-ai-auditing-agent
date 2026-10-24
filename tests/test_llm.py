import pytest

from llm import GeminiLLM, LLMError, _retry_delay, _status_code


class APIError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code} {message}")
        self.code = code


class FakeResponse:
    def __init__(self, text="{}", tokens=10):
        self.text = text
        self.usage_metadata = type("U", (), {"total_token_count": tokens})()


class FakeClient:
    def __init__(self, script):
        self.script, self.models_used = list(script), []
        self.models = self

    def generate_content(self, model, contents, config):
        self.models_used.append(model)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make(script, models=("m1", "m2"), **kw):
    sleeps, client = [], FakeClient(script)
    t = {"now": 0.0}

    def sleep(s):
        sleeps.append(s); t["now"] += s

    llm = GeminiLLM("k", list(models), client=client, sleep=sleep, clock=lambda: t["now"], log=lambda m: None, **kw)
    return llm, client, sleeps


def test_success_counts_calls_and_tokens():
    llm, _, _ = make([FakeResponse('{"a":1}', 42)])
    assert llm.generate("s", "p") == '{"a":1}' and llm.calls == 1 and llm.total_tokens == 42


def test_requests_are_paced_to_protect_per_minute_quota():
    llm, _, sleeps = make([FakeResponse(), FakeResponse()], min_interval=4.5)
    llm.generate("s", "p"); llm.generate("s", "p")
    assert sleeps and 4.4 < sleeps[0] <= 4.5


def test_per_minute_429_waits_for_server_hint_then_retries():
    err = APIError(429, "RESOURCE_EXHAUSTED. Please retry in 12.5s. quota metric PerMinute")
    llm, client, sleeps = make([err, FakeResponse("ok")], min_interval=0)
    assert llm.generate("s", "p") == "ok" and any(s >= 12.5 for s in sleeps) and client.models_used == ["m1", "m1"]


def test_daily_quota_switches_to_fallback_model():
    err = APIError(429, "RESOURCE_EXHAUSTED GenerateRequestsPerDayPerProjectPerModel-FreeTier")
    llm, client, _ = make([err, FakeResponse("ok")], min_interval=0)
    assert llm.generate("s", "p") == "ok" and client.models_used == ["m1", "m2"] and llm.model == "m2"


def test_daily_quota_everywhere_is_a_clear_fatal_error():
    err = APIError(429, "RESOURCE_EXHAUSTED requests per day")
    llm, _, _ = make([err, err], min_interval=0)
    with pytest.raises(LLMError, match="DAILY quota"):
        llm.generate("s", "p")


def test_persistent_rate_limit_eventually_falls_back_or_fails():
    err = APIError(429, "RESOURCE_EXHAUSTED")
    llm, _, _ = make([err] * 3, models=("only",), max_retries=2, min_interval=0)
    with pytest.raises(LLMError, match="429"):
        llm.generate("s", "p")


def test_transient_503_is_retried_with_backoff():
    llm, _, sleeps = make([APIError(503, "UNAVAILABLE high demand"), FakeResponse("ok")], min_interval=0)
    assert llm.generate("s", "p") == "ok" and sleeps


def test_network_errors_without_status_are_retried():
    llm, _, _ = make([ConnectionError("connection reset"), FakeResponse("ok")], min_interval=0)
    assert llm.generate("s", "p") == "ok"


def test_bad_key_fails_fast_without_retry():
    llm, client, _ = make([APIError(403, "API key not valid")], min_interval=0)
    with pytest.raises(LLMError, match="API key"):
        llm.generate("s", "p")
    assert len(client.models_used) == 1


def test_unknown_model_falls_back():
    llm, client, _ = make([APIError(404, "model not found"), FakeResponse("ok")], min_interval=0)
    assert llm.generate("s", "p") == "ok" and client.models_used == ["m1", "m2"]


def test_thinking_config_rejection_retries_without_it():
    llm, _, _ = make([APIError(400, "Thinking budget is not supported for this model"), FakeResponse("ok")], min_interval=0)
    llm._use_thinking_config = True  # opt-in path
    assert llm.generate("s", "p") == "ok" and llm._use_thinking_config is False


def test_empty_response_returns_empty_string_not_crash():
    llm, _, _ = make([FakeResponse(None)], min_interval=0)
    assert llm.generate("s", "p") == ""


def test_helpers():
    assert _retry_delay("Please retry in 7.2s") == 7.2
    assert _retry_delay("'retryDelay': '33s'") == 33.0
    assert _status_code(APIError(429, "x")) == 429 and _status_code(Exception("503 UNAVAILABLE")) == 503
    assert _status_code(Exception("limit is 500 requests")) is None
