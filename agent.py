"""CLI entry point: python agent.py --repo <github_url> --output report.json"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from auditor import Auditor
from llm import DEFAULT_MODELS, LLM, GeminiLLM
from tools import RepositoryTools, ToolError, redact_secrets, validate_github_url

DEFAULT_MAX_STEPS = 16
DEFAULT_DEADLINE = 900


def run_audit(
    repo_url: str, llm: LLM, *, max_steps: int = DEFAULT_MAX_STEPS, deadline: float = DEFAULT_DEADLINE, verbose: bool = False,
    tools: RepositoryTools | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Clone the repository, run the agent loop, always clean up. Returns (report, trace, stats)."""
    own_tools = tools is None
    tools = tools or RepositoryTools(validate_github_url(repo_url))
    try:
        if own_tools:
            if verbose:
                print(f"[agent] cloning {tools.repo_url} (Git LFS files are skipped)...", file=sys.stderr)
            tools.prepare()
            if verbose:
                print("[agent] clone finished; starting audit", file=sys.stderr)
        auditor = Auditor(tools=tools, llm=llm, max_steps=max_steps, deadline_seconds=deadline, verbose=verbose)
        report = auditor.run()
        return report, auditor.trace, auditor.stats
    finally:
        if own_tools:
            tools.close()


def _write_json_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp") as handle:
        handle.write(text)
        temp = Path(handle.name)
    temp.replace(path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evidence-first DevOps repository auditing agent")
    parser.add_argument("--repo", required=True, help="Public https://github.com/owner/repository URL")
    parser.add_argument("--output", required=True, help="Path for the JSON report")
    parser.add_argument("--trace", help="Path for the JSONL tool-call trace (default: <output>.trace.jsonl)")
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_STEPS, help="Maximum LLM steps (default %(default)s)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_DEADLINE, help="Wall-clock budget in seconds before the agent must finish")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log each step to stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    try:
        repo_url = validate_github_url(args.repo)
    except ToolError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    api_key = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
    if not api_key:
        print("Error: GEMINI_API_KEY (or GOOGLE_API_KEY) is not set (copy .env.example to .env and add a key from Google AI Studio).", file=sys.stderr)
        return 2
    if args.max_turns < 3:
        print("Error: --max-turns must be at least 3", file=sys.stderr)
        return 2

    models = [os.environ.get("GEMINI_MODEL", "").strip() or DEFAULT_MODELS[0]]
    models += [m.strip() for m in os.environ.get("GEMINI_FALLBACK_MODELS", ",".join(DEFAULT_MODELS[1:])).split(",") if m.strip()]
    try:
        interval = float(os.environ.get("GEMINI_MIN_INTERVAL_SEC", "4.5"))
    except ValueError:
        interval = 4.5

    output = Path(args.output)
    trace_path = Path(args.trace) if args.trace else output.with_suffix(output.suffix + ".trace.jsonl") if output.suffix else Path(str(output) + ".trace.jsonl")
    try:
        llm = GeminiLLM(api_key, models, min_interval=interval, log=lambda m: print(m, file=sys.stderr))
        report, trace, stats = run_audit(repo_url, llm, max_steps=args.max_turns, deadline=args.timeout, verbose=args.verbose)
        _write_json_atomic(output, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        _write_json_atomic(trace_path, "\n".join(redact_secrets(json.dumps(t, ensure_ascii=False)) for t in trace) + "\n")
    except ToolError as exc:
        print(f"Fatal: {redact_secrets(str(exc))}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"Fatal: could not write output: {exc}", file=sys.stderr)
        return 1

    print(
        f"Audit complete: {len(report['violations'])} violation(s) -> {output} "
        f"[{stats['steps']} steps, {stats['tool_calls']} tool calls, {llm.calls} LLM calls, ~{llm.total_tokens} tokens, model {llm.model}]",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
