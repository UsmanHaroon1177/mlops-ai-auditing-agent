"""Thin Gemini wrapper tuned for the free Google AI Studio tier.

Handles: request pacing (requests/minute), 429 retry with the server-suggested delay,
per-day quota exhaustion (switches to a fallback model), transient 5xx/network errors,
unknown model names, and a hard per-request timeout. No agent framework is used.
"""

from __future__ import annotations

import re
import sys
import time
from typing import Any, Callable, Protocol

from tools import ToolError

DEFAULT_MODELS = ["gemini-flash-lite-latest", "gemini-flash-latest"]
REQUEST_TIMEOUT_MS = 60_000


class LLM(Protocol):
    """Anything with this method can drive the agent (tests use a scripted fake)."""

    def generate(self, system: str, prompt: str) -> str: ...


class LLMError(ToolError):
    """Fatal LLM problem (bad key, quota exhausted everywhere, repeated failures)."""


def _status_code(exc: Exception) -> int | None:
    for attr in ("code", "status_code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    match = re.match(r"\s*([45]\d\d)\b", str(exc)) or re.search(r"['\"]code['\"]:\s*([45]\d\d)", str(exc))
    return int(match.group(1)) if match else None


def _retry_delay(message: str) -> float | None:
    match = re.search(r"retry(?:Delay)?\D{0,12}?(\d+(?:\.\d+)?)\s*s", message, re.I)
    return float(match.group(1)) if match else None


class GeminiLLM:
    def __init__(
        self,
        api_key: str,
        models: list[str] | None = None,
        *,
        min_interval: float = 4.5,
        max_retries: int = 5,
        client: Any = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.models = [m for m in (models or DEFAULT_MODELS) if m] or list(DEFAULT_MODELS)
        self.active = 0
        self.min_interval = max(0.0, min_interval)
        self.max_retries = max_retries
        self._sleep, self._clock = sleep, clock
        self._last_call = float("-inf")
        self._log = log or (lambda msg: print(msg, file=sys.stderr))
        self._use_thinking_config = False  # opt in; some models (e.g. flash-lite-latest) reject thinking_config
        self.calls = 0
        self.total_tokens = 0
        if client is not None:
            self._client = client
        else:
            try:
                from google import genai
                from google.genai import types
            except ImportError as exc:  # pragma: no cover - environment issue
                raise LLMError("google-genai is not installed; run: pip install -r requirements.txt") from exc
            self._client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=REQUEST_TIMEOUT_MS))

    @property
    def model(self) -> str:
        return self.models[self.active]

    # ------------------------------------------------------------------ #
    def _config(self, system: str) -> Any:
        from google.genai import types

        kwargs: dict[str, Any] = dict(
            system_instruction=system, temperature=0.0, seed=7, response_mime_type="application/json", max_output_tokens=8192
        )
        if self._use_thinking_config:
            kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)  # spend quota on answers, not thoughts
        return types.GenerateContentConfig(**kwargs)

    def _switch_model(self, reason: str) -> bool:
        if self.active + 1 >= len(self.models):
            return False
        self.active += 1
        self._log(f"[llm] {reason}; switching to fallback model {self.model}")
        return True

    def _pace(self) -> None:
        wait = self.min_interval - (self._clock() - self._last_call)
        if wait > 0:
            self._sleep(wait)

    def generate(self, system: str, prompt: str) -> str:
        attempt = 0
        while True:
            self._pace()
            self._last_call = self._clock()
            try:
                response = self._client.models.generate_content(
                    model=self.model, contents=prompt, config=self._config(system)
                )
                self.calls += 1
                usage = getattr(response, "usage_metadata", None)
                self.total_tokens += int(getattr(usage, "total_token_count", 0) or 0)
                return (getattr(response, "text", None) or "").strip()
            except Exception as exc:  # noqa: BLE001 - classified below
                message = str(exc)
                code = _status_code(exc)
                lowered = message.lower()
                attempt += 1

                if self._use_thinking_config and code == 400 and "api key" not in lowered:
                    self._use_thinking_config = False
                    self._log("[llm] request rejected (400); retrying without thinking config")
                    attempt -= 1
                    continue
                if code in (401, 403) or ("api key" in lowered and code in (400, None)):
                    raise LLMError("Gemini rejected the API key (check GEMINI_API_KEY in .env / Google AI Studio).") from exc
                if code == 404 or ("not found" in lowered and "model" in lowered):
                    if self._switch_model(f"model '{self.model}' is unavailable"):
                        attempt = 0
                        continue
                    raise LLMError(f"Gemini model '{self.model}' not found; set GEMINI_MODEL to a valid model.") from exc
                if code == 429 or "resource_exhausted" in lowered:
                    if "perday" in lowered.replace(" ", "").replace("_", "") or "per day" in lowered:
                        if self._switch_model(f"daily quota exhausted for '{self.model}'"):
                            attempt = 0
                            continue
                        raise LLMError(
                            "Gemini free-tier DAILY quota exhausted for all configured models; retry after the quota resets "
                            "(midnight Pacific time) or set GEMINI_MODEL / GEMINI_FALLBACK_MODELS to other models."
                        ) from exc
                    if attempt > self.max_retries:
                        if self._switch_model(f"rate limit persisted on '{self.model}'"):
                            attempt = 0
                            continue
                        raise LLMError("Gemini rate limit (429) persisted after several retries; try again in a minute.") from exc
                    delay = min(max(_retry_delay(message) or 0, 5 * attempt) + 1, 70)
                    self._log(f"[llm] rate limited (429); waiting {delay:.0f}s (retry {attempt}/{self.max_retries})")
                    self._sleep(delay)
                    continue
                if code is None or code >= 500 or "timed out" in lowered or "timeout" in lowered or "connect" in lowered:
                    if attempt > self.max_retries:
                        raise LLMError(f"Gemini request failed after {self.max_retries} retries: {message[:200]}") from exc
                    delay = min(2**attempt, 30)
                    self._log(f"[llm] transient error ({code or 'network'}); retrying in {delay}s")
                    self._sleep(delay)
                    continue
                raise LLMError(f"Gemini request failed ({code}): {message[:300]}") from exc
