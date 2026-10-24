"""The agent loop: observe -> reason (LLM) -> select tool(s) -> execute -> interpret -> report.

The LLM decides every tool call, including follow-ups. This module only enforces
guard-rails: tool allow-list, step/time budgets, the "open every flagged file before
finishing" gate, and the evidence check on the final report. No agent framework.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from llm import LLM
from prompts import FIRST_STEP_HINT, SYSTEM_PROMPT, render_state
from tools import TOOL_SPECS, MAX_TRACE_TEXT, RepositoryTools, ToolError, is_credential_like, redact_secrets
from validation import validate_violations

MAX_CALLS_PER_STEP = 4
MAX_GATE_REJECTIONS = 3
MAX_BAD_OUTPUTS = 4
FINAL_GRACE_STEPS = 2
RECENT_FULL_TURNS = 2
STEP_OUTPUT_CHARS = 12_000


class AuditError(ToolError):
    """Fatal audit failure (exit code 1)."""


def decode_json_object(text: str) -> dict[str, Any]:
    """Extract the first JSON object from model text (tolerates code fences / chatter)."""
    if not text or not text.strip():
        raise ValueError("empty response")
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found")
    try:
        data, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError("response must be a JSON object")
    return data


def _ranges(lines: set[int]) -> str:
    if not lines:
        return "binary/unreadable"
    ordered = sorted(lines)
    spans, begin, prev = [], ordered[0], ordered[0]
    for n in ordered[1:]:
        if n != prev + 1:
            spans.append((begin, prev))
            begin = n
        prev = n
    spans.append((begin, prev))
    return ",".join(f"{a}-{b}" if a != b else str(a) for a, b in spans[:4])


def _wrap_untrusted(text: str) -> str:
    safe = text.replace("REPO_CONTENT>>>", "REPO_CONTENT> > >").replace("<<<REPO_CONTENT", "< < <REPO_CONTENT")
    return f"<<<REPO_CONTENT\n{safe}\nREPO_CONTENT>>>"


@dataclass
class Turn:
    step: int
    summary: str
    output: str


@dataclass
class Auditor:
    tools: RepositoryTools
    llm: LLM
    max_steps: int = 16
    deadline_seconds: float = 900.0
    verbose: bool = False
    clock: Callable[[], float] = time.monotonic
    log: Callable[[str], None] = field(default=lambda msg: print(msg, file=sys.stderr))
    trace: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=lambda: {"steps": 0, "tool_calls": 0, "gate_rejections": 0, "rejected_findings": 0})

    # ------------------------------------------------------------------ #
    def _say(self, message: str) -> None:
        if self.verbose:
            self.log(message)

    def _prompt(self, step: int, history: list[Turn], notes: str, feedback: list[str], forced: bool, calls: dict[str, int]) -> str:
        opened = {path: _ranges(lines) for path, lines in self.tools.opened_files.items()}
        parts = [render_state(step, self.max_steps, opened, self.tools.unread_mandatory(), notes, calls)]
        older, recent = history[:-RECENT_FULL_TURNS], history[-RECENT_FULL_TURNS:]
        if older:
            parts.append("EARLIER STEPS (outputs trimmed; re-read a file if you need its text):")
            parts += [f"- step {t.step}: {t.summary} -> {' '.join(t.output.split())[:140]}" for t in older[-12:]]
        for turn in recent:
            parts.append(f"STEP {turn.step} RESULT of {turn.summary}:\n{_wrap_untrusted(turn.output)}")
        if feedback:
            parts.append("HARNESS FEEDBACK:\n" + "\n".join(f"- {m}" for m in feedback))
        if step == 1 and not history:
            parts.append(FIRST_STEP_HINT)
        if forced:
            parts.append('FINAL STEP: your investigation budget is used up. Reply now with {"action":"final","violations":[...]} using only evidence you opened.')
        parts.append("Reply with one JSON object only.")
        return "\n\n".join(parts)

    def _record(self, entry: dict[str, Any]) -> None:
        self.trace.append(entry)

    def _execute(self, step: int, call: dict[str, Any], limit: int) -> Turn:
        tool, arguments = call.get("tool"), call.get("arguments", {})
        reason = redact_secrets(str(call.get("reason", "")))[:300]
        summary = f"{tool}({json.dumps(arguments, ensure_ascii=False)[:150]})"
        try:
            if tool not in TOOL_SPECS:
                raise ToolError(f"unknown tool '{tool}'; valid tools: {', '.join(TOOL_SPECS)}")
            if not isinstance(arguments, dict):
                raise ToolError("arguments must be an object")
            output = self.tools.execute(tool, arguments)
            self.stats["tool_calls"] += 1
        except ToolError as exc:
            output = f"TOOL ERROR: {exc}"
        if len(output) > limit:
            output = output[:limit] + "\n[output truncated by harness]"
        self._record(
            {"step": step, "type": "tool_call", "tool": tool, "arguments": arguments, "reason": reason, "output": output[:MAX_TRACE_TEXT]}
        )
        self._say(f"[step {step}] {summary} ({len(output)} chars)")
        return Turn(step, summary, output)

    # ------------------------------------------------------------------ #
    def run(self) -> dict[str, Any]:
        started = self.clock()
        history: list[Turn] = []
        feedback: list[str] = []
        notes = ""
        tool_counts: dict[str, int] = {}
        bad_outputs = gate_rejections = repairs = 0
        step = 0

        while step < self.max_steps + FINAL_GRACE_STEPS:
            step += 1
            out_of_time = self.clock() - started > self.deadline_seconds
            forced = step >= self.max_steps or out_of_time
            self.stats["steps"] = step
            prompt = self._prompt(min(step, self.max_steps), history, notes, feedback, forced, tool_counts)
            feedback = []

            raw = self.llm.generate(SYSTEM_PROMPT, prompt)
            try:
                decision = decode_json_object(raw)
                bad_outputs = 0
            except ValueError as exc:
                bad_outputs += 1
                self._record({"step": step, "type": "invalid_model_output", "error": str(exc)})
                if bad_outputs >= MAX_BAD_OUTPUTS:
                    raise AuditError(f"the model returned invalid output {bad_outputs} times in a row ({exc})") from exc
                feedback.append(f"Your last reply was not usable ({exc}). Reply with one JSON object in the required format.")
                continue

            if isinstance(decision.get("notes"), (str, list, dict)):
                note_text = decision["notes"] if isinstance(decision["notes"], str) else json.dumps(decision["notes"])
                notes = redact_secrets(note_text)[:2500] or notes

            action = decision.get("action")
            if action == "final":
                status, accepted = self._handle_final(decision, forced, step, gate_rejections, repairs, feedback)
                if status == "accepted":
                    return {"repository": self.tools.repo_url, "violations": accepted}
                if status == "gate":
                    gate_rejections += 1
                else:
                    repairs += 1
                continue

            calls = self._normalise_calls(decision)
            if not calls:
                feedback.append('Invalid action. Reply with {"action":"tool","calls":[...]} or {"action":"final","violations":[...]}.')
                continue
            if forced:
                feedback.append("The investigation budget is exhausted: you must reply with action=final now.")
                continue
            if len(calls) > MAX_CALLS_PER_STEP:
                feedback.append(f"Only the first {MAX_CALLS_PER_STEP} calls were executed; request the rest in the next step.")
                calls = calls[:MAX_CALLS_PER_STEP]
            limit = max(3_000, STEP_OUTPUT_CHARS // len(calls))
            for call in calls:
                turn = self._execute(step, call, limit)
                history.append(turn)
                tool_counts[str(call.get("tool"))] = tool_counts.get(str(call.get("tool")), 0) + 1

        raise AuditError("the model did not produce a final report within the step budget")

    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalise_calls(decision: dict[str, Any]) -> list[dict[str, Any]]:
        if decision.get("action") != "tool":
            return []
        if isinstance(decision.get("calls"), list):
            return [c for c in decision["calls"] if isinstance(c, dict)]
        if "tool" in decision:
            return [decision]
        return []

    def _handle_final(self, decision: dict[str, Any], forced: bool, step: int, gate_rejections: int, repairs: int, feedback: list[str]) -> tuple[str, list[dict[str, Any]]]:
        """Return ("accepted", findings), or ("gate"|"repair", []) after appending harness feedback."""
        if not forced and gate_rejections < MAX_GATE_REJECTIONS:
            unread = self.tools.unread_mandatory()
            if not self.tools.listed:
                self.stats["gate_rejections"] += 1
                feedback.append("Mandatory step skipped: call list_files first.")
                self._record({"step": step, "type": "gate_rejection", "reason": "list_files never called"})
                return "gate", []
            if unread:
                self.stats["gate_rejections"] += 1
                shown = ", ".join(unread[:12]) + (f" (+{len(unread) - 12} more)" if len(unread) > 12 else "")
                feedback.append(f"Mandatory files not yet opened ({len(unread)}): {shown}. Open them (read_files accepts up to 12 paths) before finishing.")
                self._record({"step": step, "type": "gate_rejection", "reason": "unread tagged files", "unread": unread[:40]})
                return "gate", []
        valid, rejected = validate_violations(decision.get("violations"), self.tools)
        self.stats["rejected_findings"] += len(rejected)
        self._record({"step": step, "type": "final", "accepted": len(valid), "rejected": rejected})
        reported = {v.get("file") for v in valid}
        uncovered = [p for p in self.tools.opened_files if is_credential_like(p) and p not in reported]
        if (rejected or uncovered) and not forced and repairs < 1:
            parts = []
            if rejected:
                lines = "; ".join(f"{r['finding']}: {r['reason']}" for r in rejected[:8])
                parts.append(f"Evidence check rejected {len(rejected)} finding(s): {lines}. Open the needed files/lines or drop unsupported findings.")
            if uncovered:
                shown = ", ".join(uncovered[:25]) + (f" (+{len(uncovered) - 25} more)" if len(uncovered) > 25 else "")
                parts.append(f"You opened these credential-like files but reported nothing for them: {shown}. For each one that holds a real-looking credential or key (masked values count), add one finding per file; drop only files that are clearly empty or placeholders.")
            feedback.append(" ".join(parts) + " Resubmit the COMPLETE corrected final list.")
            self._say(f"[step {step}] gate: {len(rejected)} rejected, {len(uncovered)} uncovered; giving the agent one repair round")
            return "repair", []
        return "accepted", valid
