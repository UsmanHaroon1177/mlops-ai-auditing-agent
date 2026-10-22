"""Safe, read-only inspection tools for a cloned public GitHub repository."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

MAX_FILE_BYTES = 300_000
MAX_TOOL_TEXT = 18_000
MAX_SEARCH_RESULTS = 80
CREDENTIAL_FILE_RE = re.compile(r"(^|/)(\.env(?:\..*)?|id_(rsa|dsa|ecdsa|ed25519)|.*\.(pem|key|p12|pfx))$", re.I)
WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.(ya?ml)$", re.I)
SECRET_VALUE_RE = re.compile(
    r"(?i)(AIza[0-9A-Za-z_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{16,}|-----BEGIN [A-Z ]+ PRIVATE KEY-----)"
)
ASSIGNMENT_SECRET_RE = re.compile(
    r"(?im)^(\s*(?:\d+:\s+)?(?:export\s+)?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*\s*[:=]\s*)([^\s#]+)"
)


class ToolError(RuntimeError):
    """A recoverable inspection-tool failure."""


def redact_secrets(text: str) -> str:
    """Keep evidence useful while never returning credential material to the model/report."""
    text = SECRET_VALUE_RE.sub("[REDACTED_SECRET]", text)
    return ASSIGNMENT_SECRET_RE.sub(r"\1[REDACTED_SECRET]", text)


def validate_github_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ToolError("--repo must be an HTTPS URL for a public github.com repository")
    pieces = [part for part in parsed.path.strip("/").split("/") if part]
    if len(pieces) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in pieces):
        raise ToolError("--repo must look like https://github.com/owner/repository")
    return f"https://github.com/{pieces[0]}/{pieces[1]}"


@dataclass
class RepositoryTools:
    """Tool collection. It only reads an isolated temporary clone of the target."""

    repo_url: str
    root: Path | None = None
    _temporary_directory: tempfile.TemporaryDirectory[str] | None = field(default=None, repr=False)
    opened_files: dict[str, set[int]] = field(default_factory=dict)
    traces: list[dict[str, Any]] = field(default_factory=list)

    def prepare(self) -> None:
        self.repo_url = validate_github_url(self.repo_url)
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="devops-audit-")
        self.root = Path(self._temporary_directory.name) / "repository"
        self._run(["git", "clone", "--depth", "100", "--no-tags", self.repo_url, str(self.root)], timeout=90)

    def close(self) -> None:
        if self._temporary_directory:
            self._temporary_directory.cleanup()
            self._temporary_directory = None

    def _require_root(self) -> Path:
        if self.root is None:
            raise ToolError("repository has not been prepared")
        return self.root

    def _run(self, command: list[str], timeout: int = 30) -> str:
        try:
            result = subprocess.run(
                command, cwd=self.root if self.root and self.root.exists() else None, text=True, capture_output=True, timeout=timeout,
                check=False, env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"},
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"command timed out after {timeout}s") from exc
        if result.returncode != 0:
            message = (result.stderr or result.stdout).strip()
            raise ToolError(f"command failed: {message[:500]}")
        return result.stdout

    def _safe_path(self, path: str) -> tuple[str, Path]:
        root = self._require_root().resolve()
        normalized = PurePosixPath(path).as_posix().lstrip("/")
        if not normalized or normalized.startswith("../") or "/../" in normalized:
            raise ToolError("path must stay inside the repository")
        target = (root / normalized).resolve()
        if root not in target.parents and target != root:
            raise ToolError("path must stay inside the repository")
        if not target.is_file():
            raise ToolError(f"not a tracked regular file: {normalized}")
        return normalized, target

    def _record(self, name: str, arguments: dict[str, Any], output: str) -> str:
        clean = redact_secrets(output)
        self.traces.append({"tool": name, "arguments": arguments, "output": clean})
        return clean[:MAX_TOOL_TEXT]

    def list_files(self) -> str:
        files = self._run(["git", "ls-files"])
        items: list[str] = []
        for path in files.splitlines():
            flags: list[str] = []
            if CREDENTIAL_FILE_RE.search(path):
                flags.append("CREDENTIAL-LIKE: MUST READ")
            if WORKFLOW_RE.search(path):
                flags.append("WORKFLOW: MUST READ")
            label = f" [{'; '.join(flags)}]" if flags else ""
            items.append(f"{path}{label}")
        if not items:
            raise ToolError("repository has no tracked files")
        return self._record("list_files", {}, "\n".join(items))

    def mandatory_files(self) -> set[str]:
        """Return tagged files directly, without relying on a truncated model-facing listing."""
        return {
            path for path in self._run(["git", "ls-files"]).splitlines()
            if CREDENTIAL_FILE_RE.search(path) or WORKFLOW_RE.search(path)
        }

    def read_file(self, path: str, start_line: int = 1, end_line: int = 250) -> str:
        if start_line < 1 or end_line < start_line or end_line - start_line > 600:
            raise ToolError("invalid line range")
        normalized, target = self._safe_path(path)
        if target.stat().st_size > MAX_FILE_BYTES:
            raise ToolError(f"file is too large to inspect safely ({target.stat().st_size} bytes)")
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise ToolError(f"could not read file: {exc}") from exc
        selected = lines[start_line - 1 : end_line]
        self.opened_files.setdefault(normalized, set()).update(range(start_line, start_line + len(selected)))
        body = "\n".join(f"{line_no}: {line}" for line_no, line in enumerate(selected, start=start_line))
        return self._record("read_file", {"path": normalized, "start_line": start_line, "end_line": end_line}, body or "[empty file]")

    def search_code(self, pattern: str) -> str:
        if not pattern or len(pattern) > 180:
            raise ToolError("pattern must contain 1-180 characters")
        try:
            expression = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ToolError(f"invalid regular expression: {exc}") from exc
        matches: list[str] = []
        for relative in self._run(["git", "ls-files"]).splitlines():
            try:
                normalized, target = self._safe_path(relative)
            except ToolError:
                continue
            if target.stat().st_size > MAX_FILE_BYTES:
                continue
            text = target.read_text(encoding="utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if expression.search(line):
                    matches.append(f"{normalized}:{line_no}: {line}")
                    if len(matches) >= MAX_SEARCH_RESULTS:
                        break
            if len(matches) >= MAX_SEARCH_RESULTS:
                break
        output = "\n".join(matches) if matches else "[no matches]"
        return self._record("search_code", {"pattern": pattern}, output)

    def git_log(self, limit: int = 30) -> str:
        if not 1 <= limit <= 100:
            raise ToolError("limit must be between 1 and 100")
        output = self._run(["git", "log", f"--max-count={limit}", "--pretty=format:%h %ad %s", "--date=short"])
        return self._record("git_log", {"limit": limit}, output or "[no commits]")

    def execute(self, tool: str, arguments: dict[str, Any]) -> str:
        methods = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "git_log": self.git_log,
        }
        if tool not in methods:
            raise ToolError(f"unknown tool: {tool}")
        try:
            return methods[tool](**arguments)
        except TypeError as exc:
            raise ToolError(f"invalid arguments for {tool}: {exc}") from exc

