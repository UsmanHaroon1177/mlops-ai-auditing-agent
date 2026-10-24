"""Safe, read-only inspection tools for a cloned public GitHub repository.

Nothing in the target repository is ever executed. Every tool returns text that is
redacted (no credential values) and size-capped so it is cheap to send to an LLM.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlparse

MAX_FILE_BYTES = 300_000
MAX_TOOL_TEXT = 8_000  # characters returned to the model per tool call
MAX_TRACE_TEXT = 20_000  # characters kept per call in the trace file
MAX_SEARCH_RESULTS = 60
MAX_MATCHES_PER_FILE = 6
MAX_BATCH_FILES = 12
MAX_MANDATORY_FILES = 40
FULL_LISTING_LIMIT = 120
REDACTED = "[REDACTED_SECRET]"
REDACTED_KEY = "[REDACTED_KEY_MATERIAL]"


class ToolError(RuntimeError):
    """A recoverable inspection-tool failure (also used for fatal audit errors)."""


# --------------------------------------------------------------------------- #
# File classification
# --------------------------------------------------------------------------- #
_TEMPLATE_SUFFIX_RE = re.compile(r"\.(example|sample|template|dist|tpl|defaults?)$", re.I)
_CRED_NAME_RE = re.compile(
    r"^(\.env(\..+)?|.+\.env|id_(rsa|dsa|ecdsa|ed25519)|\.netrc|_netrc|\.npmrc|\.pypirc|\.git-credentials|"
    r"\.htpasswd|htpasswd|\.pgpass|\.my\.cnf|\.s3cfg|\.dockercfg|\.credentials|credentials|credentials\.\w+|"
    r"master\.key|secrets?\.(ya?ml|json|toml|ini|txt)|.+\.tfvars|terraform\.tfstate(\.backup)?|"
    r"service[-_]?account.*\.json|wp-config\.php|sftp-config\.json|\.ftpconfig|\.remote-sync\.json|"
    r"\.esmtprc|shadow|passwd|proftpdpasswd|logins\.json|\.tugboat|filezilla\.xml|recentservers\.xml|"
    r".+\.(pem|key|p12|pfx|ppk|jks|keystore|kdbx))$",
    re.I,
)
_CRED_DIR_RE = re.compile(r"(^|/)\.(ssh|aws|gnupg|kube)/", re.I)
_PUBLIC_KEY_RE = re.compile(r"\.pub$", re.I)
_KEY_MATERIAL_NAME_RE = re.compile(
    r"^(id_(rsa|dsa|ecdsa|ed25519)|master\.key|.+\.(pem|key|ppk|p12|pfx|jks|keystore))$", re.I
)
_WORKFLOW_RE = re.compile(r"^\.github/(workflows/.+\.ya?ml|actions/.+/action\.ya?ml)$", re.I)
_OTHER_CI_RE = re.compile(
    r"(^|/)(\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines\.ya?ml|\.circleci/config\.yml|\.travis\.yml|bitbucket-pipelines\.yml)$"
)
_ARTIFACT_RE = re.compile(
    r"(^|/)(__pycache__|node_modules|\.venv|venv|\.idea|\.vscode|\.pytest_cache|\.mypy_cache|\.ruff_cache|"
    r"\.DS_Store|Thumbs\.db|dist|build|\.tox|\.gradle|target/classes)(/|$)|\.(pyc|pyo|log|tmp|swp|bak|orig|egg-info)$",
    re.I,
)
_LOCKFILES = {
    "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock", "requirements.lock", "conda-lock.yml", "bun.lockb",
}
_MANIFESTS = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "package.json", "Cargo.toml",
    "go.mod", "Gemfile", "composer.json", "pom.xml", "build.gradle", "environment.yml", "tox.ini",
}
_LINT_CONFIGS = {
    "ruff.toml", ".ruff.toml", ".flake8", ".pylintrc", "pylintrc", ".pre-commit-config.yaml", ".eslintrc",
    ".eslintrc.js", ".eslintrc.json", ".eslintrc.yml", "eslint.config.js", "eslint.config.mjs", ".prettierrc",
    "mypy.ini", ".editorconfig", "tox.ini", "noxfile.py", "Makefile", ".golangci.yml", "rustfmt.toml", ".rubocop.yml",
}


def is_credential_like(path: str) -> bool:
    name = PurePosixPath(path).name
    if _PUBLIC_KEY_RE.search(name):
        return False
    if _TEMPLATE_SUFFIX_RE.search(name):
        return False
    return bool(_CRED_NAME_RE.match(name) or _CRED_DIR_RE.search(path))


def is_env_template(path: str) -> bool:
    name = PurePosixPath(path).name
    return bool(_TEMPLATE_SUFFIX_RE.search(name)) and name.lower().startswith((".env", "env"))


def is_workflow(path: str) -> bool:
    return bool(_WORKFLOW_RE.match(path))


def is_key_material(path: str) -> bool:
    return bool(_KEY_MATERIAL_NAME_RE.match(PurePosixPath(path).name))


def tags_for(path: str) -> list[str]:
    tags: list[str] = []
    if is_credential_like(path):
        tags.append("CREDENTIAL-LIKE: MUST READ")
    if is_workflow(path):
        tags.append("WORKFLOW: MUST READ")
    if is_env_template(path):
        tags.append("ENV-TEMPLATE")
    if _OTHER_CI_RE.search(path):
        tags.append("CI-CONFIG")
    if _ARTIFACT_RE.search(path):
        tags.append("TRACKED-ARTIFACT?")
    return tags


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
_TOKEN_RES = [
    re.compile(p)
    for p in (
        r"AIza[0-9A-Za-z_-]{20,}",
        r"gh[pousr]_[A-Za-z0-9_]{16,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"glpat-[A-Za-z0-9_-]{16,}",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        r"sk-[A-Za-z0-9_-]{16,}",
        r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{12,}",
        r"xox[abprs]-[A-Za-z0-9-]{10,}",
        r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
        r"npm_[A-Za-z0-9]{30,}",
        r"pypi-[A-Za-z0-9_-]{30,}",
        r"dckr_pat_[A-Za-z0-9_-]{8,}",
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}",
    )
]
_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_PEM_END_RE = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_URL_CRED_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s/]*?:)([^\s/]+)(@[^@\s/]+)(?=[/\s]|$)")
_RC_PASSWORD_RE = re.compile(r"(?i)((?:^\s*(?:\d+: )?|\bmachine\s+\S+.*?\b)(?:password|passwd|pass|secret|token)\s+)(?![=:])([\"']?)([^\s\"']+)")
_STANDALONE_TOKEN_RE = re.compile(r"^(\s*(?:\d+: )?)[A-Za-z0-9+/=_-]{32,}\s*$")
_ASSIGN_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
        ["']?[\w.-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|
        auth(?:orization)?|credential|passwd|pwd|webhook|passphrase|
        (?:app|secret|encryption|master|session|jwt|crypt|license|ssh|aws|signing|client|service|salt|hmac)[_-]?(?:key|salt))[\w.-]*["']?
        \s*[:=]\s*
    )
    (?P<q1>["']?)
    (?P<value>[^\s"',;#]+)
    (?P<q2>["']?)
    """
)
_REFERENCE_PREFIXES = (
    "${", "$(", "$", "%", "<", "{{", "os.environ", "os.getenv", "getenv", "process.env", "env.", "env(",
    "secrets.", "vars.", "config.", "settings.", "input(", "getpass", "null", "none", "true", "false",
    "nil", "[redacted", "***", "xxx", "...", "changeme", "change-me", "change_me", "your",
    "example", "dummy", "placeholder", "replace", "todo", "fixme",
)


# Dependency version specifiers (package.json, requirements, Cargo) are not secrets even when the
# package name contains words like "token" or "secret" (e.g. "jsonwebtoken": "^9.0.3").
_VERSION_RE = re.compile(r"^[~^<>=!]*v?\d+(?:\.[\dxX*]+)+(?:[-+][0-9A-Za-z.+-]+)?$")
_VERSION_WORDS = ("latest", "next", "*", "workspace:", "file:", "link:", "npm:", "git+", "github:", "portal:")


def _is_reference_or_placeholder(value: str) -> bool:
    v = value.strip().lower()
    looks_like_call = v.endswith(")") and "(" in v
    is_version = bool(_VERSION_RE.match(v)) or v.startswith(_VERSION_WORDS)
    return not v or v.startswith(_REFERENCE_PREFIXES) or looks_like_call or is_version


_LABEL_WORDS = {"password", "passwd", "secret", "token", "apikey", "api_key", "username", "email", "key", "none", "string", "text"}
_CODE_HINT_RE = re.compile(r"[(\[{]|=>|\bawait\b|\bnew\b|^[A-Za-z_$][\w$]*\.[A-Za-z_$]")


def _looks_like_code_or_label(match: re.Match[str]) -> bool:
    """True for assignments whose value is source code, a number/flag, prose or a UI label, not a credential."""
    value, q1, q2 = match.group("value"), match.group("q1"), match.group("q2")
    v = value.strip()
    if q1 and not q2:  # opening quote but the value continues past a space: prose such as "Confirm Password"
        return True
    if not q1:
        if re.fullmatch(r"-?\d+(?:\.\d+)?", v):  # bare number: port, token id, count
            return True
        if _CODE_HINT_RE.search(v) or v.startswith(("[", "{", "(", "`", "/", "'", '"')):
            return True
    if v.lower().rstrip(":") in _LABEL_WORDS:
        return True
    return False


def _redact_assignment(match: re.Match[str]) -> str:
    if _is_reference_or_placeholder(match.group("value")) or _looks_like_code_or_label(match):
        return match.group(0)
    return f"{match.group('prefix')}{match.group('q1')}{REDACTED}{match.group('q2')}"


def redact_line(line: str, *, prose: bool = False) -> str:
    """Redact credential material inside a single line (no cross-line state)."""
    for pattern in _TOKEN_RES:
        line = pattern.sub(REDACTED, line)
    line = _URL_CRED_RE.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", line)
    if not prose:  # netrc-style "password <value>" lines; in prose it would eat ordinary words
        line = _RC_PASSWORD_RE.sub(
            lambda m: m.group(0) if _is_reference_or_placeholder(m.group(3)) else f"{m.group(1)}{m.group(2)}{REDACTED}", line
        )
    line = _ASSIGN_RE.sub(_redact_assignment, line)
    if _STANDALONE_TOKEN_RE.match(line) and REDACTED not in line:
        line = _STANDALONE_TOKEN_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", line)
    return line


def redact_lines(lines: Iterable[str], *, key_file: bool = False, prose: bool = False) -> list[str]:
    """Redact lines while preserving line numbering; PEM bodies are blanked completely."""
    result: list[str] = []
    in_pem = False
    for line in lines:
        if in_pem:
            if _PEM_END_RE.search(line):
                in_pem = False
                result.append(line.strip())
            else:
                result.append(REDACTED_KEY)
            continue
        if _PEM_BEGIN_RE.search(line):
            in_pem = not _PEM_END_RE.search(line)
            result.append(line.strip()[:80])
            continue
        if key_file and line.strip() and not line.lstrip().startswith(("#", ";", "//")) and "BEGIN" not in line:
            result.append(REDACTED_KEY)
            continue
        result.append(redact_line(line, prose=prose))
    return result


def redact_secrets(text: str) -> str:
    """Redact an arbitrary block of text (used for model output and report fields)."""
    return "\n".join(redact_lines(text.split("\n"), prose=True))


# --------------------------------------------------------------------------- #
# URL validation
# --------------------------------------------------------------------------- #
def validate_github_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ToolError("--repo must be an HTTPS URL for a public github.com repository")
    if parsed.params or parsed.username or parsed.password or any(c.isspace() for c in url.strip()):
        raise ToolError("--repo must look like https://github.com/owner/repository")
    pieces = [part for part in parsed.path.strip("/").split("/") if part]
    if len(pieces) >= 2 and pieces[1].endswith(".git"):
        pieces[1] = pieces[1][:-4]
    if len(pieces) < 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in pieces[:2]):
        raise ToolError("--repo must look like https://github.com/owner/repository")
    if len(pieces) > 2 and pieces[2] not in {"tree", "blob"}:
        raise ToolError("--repo must look like https://github.com/owner/repository")
    return f"https://github.com/{pieces[0]}/{pieces[1]}"


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
TOOL_SPECS = {
    "list_files": 'list_files(path="") - repo facts + tracked files (directory summary for big repos). path filters to a directory.',
    "read_file": "read_file(path, start_line=1, end_line=250) - numbered lines of one tracked file (max 600 lines).",
    "read_files": f"read_files(paths=[...], max_lines_each=80) - read up to {MAX_BATCH_FILES} files in one call (cheapest way to open many files).",
    "search_code": 'search_code(pattern, path_glob=None) - case-insensitive regex over tracked text files, e.g. path_glob=".github/workflows/*".',
    "git_log": "git_log(limit=30, path=None, files=False) - recent commits; path limits to one file; files=True lists changed files.",
}


@dataclass
class RepositoryTools:
    """Tool collection. It only reads an isolated temporary clone of the target."""

    repo_url: str
    root: Path | None = None
    clone_timeout: int = 120
    _temporary_directory: tempfile.TemporaryDirectory[str] | None = field(default=None, repr=False)
    opened_files: dict[str, set[int]] = field(default_factory=dict)
    listed: bool = False
    _tracked: list[str] | None = field(default=None, repr=False)
    _tracked_set: frozenset[str] = field(default_factory=frozenset, repr=False)

    # -- lifecycle ---------------------------------------------------------- #
    def prepare(self) -> None:
        self.repo_url = validate_github_url(self.repo_url)
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="devops-audit-")
        self.root = Path(self._temporary_directory.name) / "repository"
        self._run(
            [
                "git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
                "-c", "filter.lfs.required=false", "clone", "--depth", "100", "--no-tags",
                "--no-recurse-submodules", "--quiet", self.repo_url, str(self.root),
            ],
            timeout=self.clone_timeout,
        )

    def close(self) -> None:
        if self._temporary_directory:
            self._temporary_directory.cleanup()
            self._temporary_directory = None

    # -- helpers ------------------------------------------------------------ #
    def _require_root(self) -> Path:
        if self.root is None:
            raise ToolError("repository has not been prepared")
        return self.root

    def _run(self, command: list[str], timeout: int = 30) -> str:
        env = {
            **os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_ALLOW_PROTOCOL": "https",
            "LC_ALL": "C.UTF-8",
            "GIT_LFS_SKIP_SMUDGE": "1",  # never download Git LFS model/data files; the auditor only reads text
        }
        try:
            result = subprocess.run(
                command, cwd=self.root if self.root and self.root.exists() else None, text=True, encoding="utf-8",
                errors="replace", capture_output=True, timeout=timeout, check=False, env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"command timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise ToolError("git is not installed or not on PATH") from exc
        if result.returncode != 0:
            message = redact_secrets((result.stderr or result.stdout).strip())
            if "clone" in command:
                message = f"could not clone {self.repo_url} (is it public and spelled correctly?): {message[:300]}"
            raise ToolError(f"command failed: {message[:500]}")
        return result.stdout

    def tracked_files(self) -> list[str]:
        if self._tracked is None:
            raw = self._run(["git", "-c", "core.quotepath=false", "ls-files"])
            self._tracked = [line for line in raw.splitlines() if line]
            self._tracked_set = frozenset(self._tracked)
        return self._tracked

    def _safe_path(self, path: str) -> tuple[str, Path]:
        root = self._require_root().resolve()
        normalized = PurePosixPath(str(path).replace("\\", "/")).as_posix().lstrip("/")
        if normalized.startswith("./"):
            normalized = normalized[2:]
        if not normalized or normalized == "." or normalized.startswith("../") or "/../" in normalized:
            raise ToolError("path must stay inside the repository")
        self.tracked_files()
        if normalized not in self._tracked_set:
            raise ToolError(f"not a tracked file: {normalized} (use list_files to see valid paths)")
        target = (root / normalized).resolve()
        if root not in target.parents:
            raise ToolError("path must stay inside the repository")
        if not target.is_file():
            raise ToolError(f"not a regular file: {normalized}")
        return normalized, target

    @staticmethod
    def _is_binary(target: Path) -> bool:
        try:
            with target.open("rb") as handle:
                return b"\0" in handle.read(4096)
        except OSError:
            return True

    def mandatory_files(self) -> list[str]:
        """Files the agent must open before it may finish (workflows first, capped for quota)."""
        files = self.tracked_files()
        workflows = sorted(f for f in files if is_workflow(f))
        creds = sorted((f for f in files if is_credential_like(f)), key=lambda f: (not is_key_material(f), f))
        return (workflows + creds)[:MAX_MANDATORY_FILES]

    def unread_mandatory(self) -> list[str]:
        return [f for f in self.mandatory_files() if f not in self.opened_files]

    # -- tools -------------------------------------------------------------- #
    def list_files(self, path: str = "") -> str:
        files = self.tracked_files()
        if not files:
            raise ToolError("repository has no tracked files")
        prefix = str(path or "").replace("\\", "/").strip("/")
        out: list[str] = []
        if prefix:
            subset = [f for f in files if f == prefix or f.startswith(prefix + "/")]
            if not subset:
                raise ToolError(f"no tracked files under '{prefix}'")
            out.append(f"{len(subset)} tracked files under {prefix}/")
            out.extend(self._format_paths(subset))
        else:
            self.listed = True
            out.extend(self._facts(files))
            flagged = [f for f in files if tags_for(f)]
            if len(files) <= FULL_LISTING_LIMIT:
                out.append(f"\nALL TRACKED FILES ({len(files)}):")
                out.extend(self._format_paths(files))
            else:
                out.append(f"\nFLAGGED FILES ({len(flagged)}):")
                out.extend(self._format_paths(flagged[:80]))
                if len(flagged) > 80:
                    out.append(f"... {len(flagged) - 80} more flagged files; use list_files(path=...) to drill down")
                out.append(f"\nDIRECTORY SUMMARY ({len(files)} files; call list_files(path='dir') to expand):")
                out.extend(self._dir_summary(files))
        return "\n".join(out)

    @staticmethod
    def _format_paths(paths: list[str]) -> list[str]:
        lines = []
        for p in paths:
            tags = tags_for(p)
            lines.append(f"{p} [{'; '.join(tags)}]" if tags else p)
        return lines

    @staticmethod
    def _dir_summary(files: list[str]) -> list[str]:
        counts: Counter[str] = Counter()
        for f in files:
            parts = f.split("/")
            counts["/".join(parts[:2]) + "/" if len(parts) > 2 else (parts[0] + "/" if len(parts) == 2 else "(root)")] += 1
        return [f"{name} ({n} files)" for name, n in sorted(counts.items())][:80]

    @staticmethod
    def _facts(files: list[str]) -> list[str]:
        names = {PurePosixPath(f).name for f in files}

        def find(predicate) -> list[str]:
            return [f for f in files if predicate(f)][:8]

        ext = Counter(PurePosixPath(f).suffix.lower() for f in files if PurePosixPath(f).suffix)
        tests = find(lambda f: re.search(r"(^|/)(tests?|__tests__|spec)(/|$)|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$", f))
        out = [
            "REPO FACTS (deterministic hints from file names only; not findings, open files to verify):",
            f"- tracked files: {len(files)}; top extensions: " + ", ".join(f"{e}:{n}" for e, n in ext.most_common(6)),
            f"- README: {find(lambda f: PurePosixPath(f).name.lower().startswith('readme')) or 'none found'}",
            f"- LICENSE: {find(lambda f: PurePosixPath(f).name.lower().startswith(('license', 'copying'))) or 'none found'}",
            f"- .gitignore: {'yes' if '.gitignore' in names else 'none found'}",
            f"- dependency manifests: {sorted(n for n in names if n in _MANIFESTS) or 'none found'}; "
            f"lockfiles: {sorted(n for n in names if n in _LOCKFILES) or 'none found'}",
            f"- lint/format/task config files: {sorted(n for n in names if n in _LINT_CONFIGS) or 'none found'} "
            "(pyproject.toml/setup.cfg/package.json may also hold tool sections)",
            f"- test files/dirs: {tests or 'none found'}",
            f"- CI: workflows={len([f for f in files if is_workflow(f)])}; other CI config={find(lambda f: bool(_OTHER_CI_RE.search(f))) or 'none'}",
            f"- containers: {find(lambda f: PurePosixPath(f).name.lower().startswith(('dockerfile', 'docker-compose', 'compose.'))) or 'none'}",
            f"- possibly tracked generated/local artifacts: {find(lambda f: bool(_ARTIFACT_RE.search(f))) or 'none'}",
        ]
        return out

    def _read_one(self, path: str, start_line: int, end_line: int, char_budget: int = MAX_TOOL_TEXT) -> tuple[str, str]:
        """Read a window of a file. Only lines that fit the budget are shown AND recorded as opened."""
        normalized, target = self._safe_path(path)
        if target.stat().st_size > MAX_FILE_BYTES:
            self.opened_files.setdefault(normalized, set())
            return normalized, f"[file too large to inspect safely: {target.stat().st_size} bytes]"
        if self._is_binary(target):
            self.opened_files.setdefault(normalized, set())
            return normalized, f"[binary file, {target.stat().st_size} bytes - contents not shown]"
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise ToolError(f"could not read file: {exc}") from exc
        total = len(lines)
        window = redact_lines(lines[start_line - 1 : end_line], key_file=is_key_material(normalized))
        shown: list[str] = []
        used = 0
        for number, text in enumerate(window, start=start_line):
            text = text if len(text) <= 400 else text[:400] + " [line truncated]"
            entry = f"{number}: {text}"
            if used + len(entry) + 1 > char_budget and shown:
                break
            shown.append(entry)
            used += len(entry) + 1
        opened = self.opened_files.setdefault(normalized, set())
        opened.update(range(start_line, start_line + len(shown)))
        body = "\n".join(shown) or "[empty or past end of file]"
        last_shown = start_line + len(shown) - 1
        if shown and last_shown < total:
            body += f"\n[... {total - last_shown} more lines; call read_file(path, start_line={last_shown + 1})]"
        return normalized, body

    def read_file(self, path: str, start_line: int = 1, end_line: int = 250) -> str:
        start_line, end_line = int(start_line), int(end_line)
        if start_line < 1 or end_line < start_line or end_line - start_line >= 600:
            raise ToolError("invalid line range (1-600 lines per call)")
        _, body = self._read_one(path, start_line, end_line)
        return body

    def read_files(self, paths: list[str], max_lines_each: int = 80) -> str:
        if not isinstance(paths, list) or not paths:
            raise ToolError("paths must be a non-empty list of file paths")
        max_lines_each = max(5, min(int(max_lines_each), 300))
        batch = paths[:MAX_BATCH_FILES]
        budget = max(600, MAX_TOOL_TEXT // len(batch))
        chunks: list[str] = []
        for path in batch:
            try:
                normalized, body = self._read_one(str(path), 1, max_lines_each, budget)
                chunks.append(f"===== {normalized} =====\n{body}")
            except ToolError as exc:
                chunks.append(f"===== {path} =====\nTOOL ERROR: {exc}")
        if len(paths) > MAX_BATCH_FILES:
            chunks.append(f"[only the first {MAX_BATCH_FILES} paths were read; call read_files again for the rest]")
        return "\n".join(chunks)

    def search_code(self, pattern: str, path_glob: str | None = None) -> str:
        if not isinstance(pattern, str) or not pattern or len(pattern) > 180:
            raise ToolError("pattern must contain 1-180 characters")
        try:
            expression = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ToolError(f"invalid regular expression: {exc}") from exc
        matches: list[str] = []
        files_matched = 0
        for relative in self.tracked_files():
            if path_glob and not PurePosixPath(relative).match(path_glob) and not PurePosixPath("/" + relative).match(path_glob):
                continue
            try:
                normalized, target = self._safe_path(relative)
            except ToolError:
                continue
            if target.stat().st_size > MAX_FILE_BYTES or self._is_binary(target):
                continue
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
            redacted = None
            hits = 0
            for line_no, line in enumerate(lines, start=1):
                if expression.search(line):
                    if redacted is None:
                        redacted = redact_lines(lines, key_file=is_key_material(normalized))
                    matches.append(f"{normalized}:{line_no}: {redacted[line_no - 1].strip()[:240]}")
                    hits += 1
                    if hits >= MAX_MATCHES_PER_FILE or len(matches) >= MAX_SEARCH_RESULTS:
                        break
            files_matched += 1 if hits else 0
            if len(matches) >= MAX_SEARCH_RESULTS:
                matches.append("[result limit reached; narrow the pattern or use path_glob]")
                break
        if not matches:
            return "[no matches]"
        return f"{files_matched} file(s) matched (leads only; open the file with read_file before reporting):\n" + "\n".join(matches)

    def git_log(self, limit: int = 30, path: str | None = None, files: bool = False) -> str:
        limit = int(limit)
        if not 1 <= limit <= 100:
            raise ToolError("limit must be between 1 and 100")
        command = ["git", "log", f"--max-count={limit}", "--date=short", "--pretty=format:%h %ad %an: %s"]
        if files:
            command.append("--name-status")
        if path:
            normalized = PurePosixPath(str(path).replace("\\", "/")).as_posix().lstrip("/")
            if normalized.startswith("../") or "/../" in normalized:
                raise ToolError("path must stay inside the repository")
            command += ["--", normalized]
        output = self._run(command)
        return redact_secrets(output) or "[no commits]"

    # -- dispatch ----------------------------------------------------------- #
    def execute(self, tool: str, arguments: dict[str, Any]) -> str:
        methods = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "read_files": self.read_files,
            "search_code": self.search_code,
            "git_log": self.git_log,
        }
        if tool not in methods:
            raise ToolError(f"unknown tool: {tool}")
        try:
            raw = methods[tool](**arguments)
        except TypeError as exc:
            raise ToolError(f"invalid arguments for {tool}: {exc}") from exc
        except ValueError as exc:
            raise ToolError(f"invalid argument value for {tool}: {exc}") from exc
        return raw
