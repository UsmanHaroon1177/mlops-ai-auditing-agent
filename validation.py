"""Evidence gate: a model finding only reaches the report if the tool output supports it."""

from __future__ import annotations

import re
from typing import Any

from tools import RepositoryTools, redact_secrets

ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_ALIASES = {
    "severe": "high", "major": "high", "moderate": "medium", "minor": "low", "info": "low", "informational": "low",
    "warning": "medium", "error": "high",
}
_CATEGORY_KEYWORDS = [
    ("security", ("secur", "secret", "credential", "vulnerab")),
    ("ci", ("ci", "action", "workflow", "pipeline")),
    ("testing", ("test",)),
    ("dependencies", ("depend", "lock", "package")),
    ("code_quality", ("quality", "lint", "format", "maintain")),
    ("configuration", ("config", "environment", "settings")),
    ("collaboration", ("collab", "review", "pull")),
    ("build_release", ("build", "release", "deploy", "publish")),
    ("hygiene", ("hygiene", "repo", "gitignore", "readme")),
]
_PREFIX = {
    "security": "SEC", "ci": "CI", "testing": "TEST", "dependencies": "DEP", "code_quality": "QUAL",
    "configuration": "CFG", "collaboration": "COL", "build_release": "BLD", "hygiene": "HYG",
}
_REMOTE_SETTING_RE = re.compile(r"branch[\s_-]*protection|required (status checks|reviewers?)|secret scanning (is )?(disabled|not enabled)", re.I)
REQUIRED = ("rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation")
_LIMITS = {"description": 300, "evidence": 500, "recommendation": 400}


def normalize_category(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if text in _PREFIX:
        return text
    for category, needles in _CATEGORY_KEYWORDS:
        if any(n in text for n in needles):
            return category
    return text or "configuration"


def _coerce_line(value: Any) -> int | None | str:
    if value is None or (isinstance(value, str) and value.strip().lower() in {"", "null", "none", "n/a"}):
        return None
    if isinstance(value, bool):
        return "invalid"
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return "invalid"


def _normalize_path(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().replace("\\", "/")
    if text.lower() in {"", "null", "none", "n/a"}:
        return None
    return text[2:] if text.startswith("./") else text


def _reject(rejected: list[dict[str, str]], item: Any, label: str, reason: str) -> None:
    ref = f"{item.get('file')}:{item.get('line')}" if isinstance(item, dict) else "-"
    rejected.append({"finding": f"{label} ({ref})", "reason": reason})


def validate_violations(raw: Any, tools: RepositoryTools) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return (accepted findings, rejected findings with reasons)."""
    if not isinstance(raw, list):
        return [], [{"finding": "final.violations", "reason": "violations must be a JSON array"}]
    tracked = set(tools.tracked_files())
    valid: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    seen_ids: set[tuple[Any, ...]] = set()
    seen_text: set[tuple[Any, ...]] = set()
    counters: dict[str, int] = {}

    for index, item in enumerate(raw):
        label = f"#{index + 1}"

        if not isinstance(item, dict):
            _reject(rejected, item, label, "not an object")
            continue
        missing = [key for key in REQUIRED if key not in item]
        if missing:
            _reject(rejected, item, label, "missing fields: " + ", ".join(missing))
            continue
        file = _normalize_path(item["file"])
        line = _coerce_line(item["line"])
        if line == "invalid":
            _reject(rejected, item, label, "line must be an integer or null")
            continue
        severity = str(item["severity"]).strip().lower()
        severity = _SEVERITY_ALIASES.get(severity, severity)
        if severity not in ALLOWED_SEVERITIES:
            _reject(rejected, item, label, "severity must be critical, high, medium or low")
            continue
        texts = {k: " ".join(redact_secrets(str(item[k])).split())[: _LIMITS[k]] for k in _LIMITS}
        if not all(texts.values()):
            _reject(rejected, item, label, "description, evidence and recommendation must be non-empty")
            continue
        if _REMOTE_SETTING_RE.search(texts["description"] + " " + texts["evidence"]):
            _reject(rejected, item, label, "remote GitHub settings (branch protection, required reviews) cannot be inferred from repository files")
            continue

        if file is None:
            if line is not None:
                _reject(rejected, item, label, "line must be null when file is null")
                continue
            if not tools.listed:
                _reject(rejected, item, label, "no file listing was observed; call list_files before reporting repository-level absences")
                continue
        else:
            if file not in tracked:
                _reject(rejected, item, label, f"'{file}' is not a tracked file of this repository")
                continue
            if file not in tools.opened_files:
                _reject(rejected, item, label, f"'{file}' was never opened with read_file/read_files; read it first")
                continue
            if line is not None and line not in tools.opened_files[file]:
                _reject(rejected, item, label, f"line {line} of '{file}' was not in any tool output you received; cite a line number you actually read")
                continue

        category = normalize_category(item["category"])
        rule_id = re.sub(r"\s+", "", str(item["rule_id"]).upper())
        if not re.fullmatch(r"[A-Z]{2,6}-\d{1,4}", rule_id):
            prefix = _PREFIX.get(category, "GEN")
            counters[prefix] = counters.get(prefix, 0) + 1
            rule_id = f"{prefix}-{counters[prefix]:03d}"

        id_key = (file, line, rule_id)
        text_key = (file, line, category, texts["description"].lower()[:60])
        if id_key in seen_ids or text_key in seen_text:
            _reject(rejected, item, label, "duplicate finding")
            continue
        seen_ids.add(id_key)
        seen_text.add(text_key)
        valid.append(
            {
                "rule_id": rule_id, "category": category, "severity": severity, "file": file, "line": line,
                "description": texts["description"], "evidence": texts["evidence"], "recommendation": texts["recommendation"],
            }
        )
    # Report-friendly ids: keep the model's prefix, but make them unique and sequential per prefix.
    sequence: dict[str, int] = {}
    for finding in valid:
        prefix = finding["rule_id"].split("-")[0]
        sequence[prefix] = sequence.get(prefix, 0) + 1
        finding["rule_id"] = f"{prefix}-{sequence[prefix]:03d}"
    return valid, rejected
