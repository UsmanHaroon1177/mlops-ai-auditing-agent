# DevOps Repository Auditing Agent

A Python agent that audits a **public GitHub repository** for DevOps problems and writes an evidence-based JSON report. It covers secrets and credentials, unsafe GitHub Actions workflows, missing tests or linting, weak dependency management, repository hygiene, and risky release automation.

The agent implements its own **observe → reason → select tool → execute → interpret → report** loop. **No agent framework is used** (no LangChain, LangGraph or n8n). The only dependencies are the Google Gemini SDK, `python-dotenv` and `pytest`. The model decides which tool to call next; the code never runs a fixed checklist.

## Quick start (for evaluators)

**You need:** Python 3.10 or newer, `git`, internet access, and a Gemini API key (a free key from https://aistudio.google.com/app/apikey works).

```bash
# 1. get the code and install
git clone https://github.com/UsmanHaroon1177/mlops-ai-auditing-agent.git && cd mlops-ai-auditing-agent
python -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. provide your own key (choose ONE)
export GEMINI_API_KEY="your-key"     # Windows PowerShell: $env:GEMINI_API_KEY="your-key"
#    or: cp .env.example .env   (Windows: copy .env.example .env)  and put the key in .env

# 3. audit any public repository
python agent.py --repo https://github.com/owner/repository --output report.json
```

- `agent.py` is the single entry point; the other modules are imported by it.
- The key can come from the real environment or from a `.env` file. A variable already set in the environment always takes priority over `.env`. `GOOGLE_API_KEY` is accepted as an alternative name.
- No key and no model are stored in this repository. The model defaults to `gemini-flash-lite-latest`; set `GEMINI_MODEL` to use a different Gemini model.
- Runs unattended and prints nothing on success unless `-v` is given. The last line on stderr summarises steps, LLM calls, tokens and the model used.
- Options: `--trace PATH` (default `<output>.trace.jsonl`), `--max-turns N` (default 16), `--timeout SECONDS` (default 900), `-v` (log every step to stderr).
- Exit codes: `0` report written (an empty `violations` list is a valid result) · `1` fatal error (clone failed, key rejected, quota exhausted, no usable model answer) · `2` bad arguments or configuration. On a fatal error **no report is written**; nothing is invented.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | none | required |
| `GEMINI_MODEL` | `gemini-flash-lite-latest` | primary model; any Gemini model the key can use |
| `GEMINI_FALLBACK_MODELS` | `gemini-flash-latest` | comma-separated models tried if the primary's daily quota is gone or the model is unavailable |
| `GEMINI_MIN_INTERVAL_SEC` | `4.5` | minimum seconds between LLM calls (keeps free-tier requests per minute low) |

Notes on the model:
- `-latest` is a Google alias that always resolves but may point to a newer model over time, so results can differ between dates. The sample report was produced with the default model.
- The agent supports the Gemini API only; other LLM providers are not supported.
- The last stderr line shows which model produced a run.

## Output

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential",
      "evidence": "Credential assigned directly in source code",
      "recommendation": "Use a secrets manager or environment variable"
    }
  ]
}
```

- `severity` is one of `critical | high | medium | low`.
- `rule_id` keeps the model's prefix (`SEC`, `CI`, `DEP`, `TEST`, `HYG`, `CFG`, `QUAL`, `BLD`, `COL`) and is numbered uniquely and sequentially per prefix.
- Findings about something that is *absent* (no tests, no CI test step) use `"file": null, "line": null`.
- Credential values are masked before the model sees them (best-effort redaction), so they should not appear in the report or the trace.
- `sample_report.json` is real, unedited output of this agent (see "Sample report").

### Inspection areas covered

| Category | What the agent looks for |
|---|---|
| `hygiene` | missing README, unsuitable `.gitignore`, tracked temporary or generated files |
| `dependencies` | inconsistent specifications, absent lockfiles where required, weak version constraints |
| `code_quality` | missing linting or formatting, obvious maintainability problems |
| `testing` | missing tests, no CI test execution |
| `ci` | incorrect triggers, ineffective gates, skipped validation, deprecated commands |
| `security` | exposed credentials, unsafe workflow permissions, script injection, secrets in logs or artifacts |
| `configuration` | machine-specific paths, committed local settings, poor environment separation |
| `collaboration` | unsafe pull-request automation, lack of review guidance where relevant |
| `build_release` | missing build validation, risky release or deployment automation |

The model is told what counts as a real defect and what does not (for example a lockfile is not required for a library, and a linter configured in `pyproject.toml` counts). Because the agent never executes code, it cannot detect tests that fail when run.

## How it works

Each step the harness shows the model a compact state: files opened so far, must-read files still unread, the model's own running notes, the last two tool results in full, and one line per older step. The model replies with a JSON action: one to four tool calls, or its final list of findings.

### Tools (all read-only, on a fresh temporary clone that is deleted afterwards)

| Tool | Purpose |
|---|---|
| `list_files(path="")` | Repo facts (README, LICENSE, `.gitignore`, manifests vs lockfiles, lint config, tests, CI, containers) plus tracked files tagged `CREDENTIAL-LIKE`, `WORKFLOW`, `ENV-TEMPLATE`, `CI-CONFIG`, `TRACKED-ARTIFACT?`. Large repos get a directory summary; `path` drills down. |
| `read_file(path, start_line, end_line)` | Numbered lines of one tracked file. |
| `read_files(paths, max_lines_each)` | Up to 12 files per call. |
| `search_code(pattern, path_glob)` | Case-insensitive regex over tracked text files; results are leads, not proof. |
| `git_log(limit, path, files)` | Commit history, optionally for one file, optionally with changed files. |

### Guard-rails

1. **Repository content is untrusted.** The system prompt states that README files, docs, comments and commit messages are evidence, not instructions. Claims such as "these secrets are fake" or "this workflow is disabled" never remove a finding. Tool output is fenced in `<<<REPO_CONTENT ... REPO_CONTENT>>>` and the fence cannot be forged from inside the repository.
2. **The real files must be opened.** Credential-like files and workflow files are tagged in the listing. The agent's first "I'm done" is refused while any tagged file (capped at 40, workflows first) is unread, or if `list_files` was never called. After 3 refusals it is let through so a stubborn model cannot loop forever.
3. **Every finding needs proof.** A finding that names a file is kept only if that file was opened and the line number appears in a tool output the model actually received. Hallucinated paths, unopened files and claims about remote settings (branch protection) are dropped.
4. **One repair round.** If findings are rejected, or credential-like files were opened but nothing was reported for them, the model gets one chance to read more and resubmit.
5. **Budgets.** At most 16 steps (`--max-turns`), 900 seconds (`--timeout`) and four tool calls per step; when a budget runs out the agent must give its final answer.

### Safety

- Repository code is **never executed**: no tests, scripts, hooks or package managers. The clone uses `core.hooksPath=/dev/null`, no submodules, HTTPS only, no credential prompts, and a timeout on every subprocess.
- Git LFS files are not downloaded; only small pointer files are seen, so large model or data files cannot stall a run.
- Paths must be tracked files that resolve inside the clone (blocks `../`, absolute paths, symlink escapes and `.git/`). Files over 300 kB and binaries are not displayed.
- The inspected repository is never modified.
- **Redaction** happens inside the tools. Token formats (AWS, GitHub, Google, Slack, Stripe, npm, PyPI, JWT and others), literal credential assignments, URL passwords, netrc-style passwords, PEM blocks and key files are masked. References and placeholders (`${{ secrets.X }}`, `os.environ[...]`, `changeme`) and ordinary code, version numbers and UI labels are left visible, so the model can tell a leak from a reference.

### Free-tier friendliness

Compact state instead of re-sending the transcript, trimmed old tool output, batch `read_files`, no thinking tokens requested, temperature 0 with a fixed seed. Calls are paced; a 429 waits for the server-suggested delay; when a daily quota is exhausted the agent switches to `GEMINI_FALLBACK_MODELS` and only then fails with a clear message. Typical runs used 3 to 12 LLM calls and roughly 10k to 50k tokens.

## Repository layout

```
.
├── agent.py            CLI entry point (python agent.py --repo URL --output FILE)
├── auditor.py          the agent loop and its guard-rails
├── llm.py              Gemini wrapper (pacing, retries, quota handling, model fallback)
├── prompts.py          system prompt for the model
├── tools.py            read-only inspection tools and secret redaction
├── validation.py       evidence gate and rule-id numbering for the final report
├── tests/              offline test suite (scripted fake model, no API calls)
├── sample_report.json  real output of this agent (see "Sample report")
├── requirements.txt    dependencies
├── .env.example        template for the key and model settings (copy to .env)
└── README.md
```

`.env` (a real key), `.venv/`, `out/`, `reports/`, `traces/` and `*.trace.jsonl` are git-ignored and must never be committed.

## Sample report

`sample_report.json` was produced by:

```bash
python agent.py --repo https://github.com/paastha1/cicd-test-repo --output sample_report.json
```

`cicd-test-repo` is a deliberately vulnerable repository of GitHub Actions workflows (hardcoded secrets in `env:` blocks, secrets echoed to logs, `set -x` and `curl -v` leaking tokens, secrets as command-line arguments, unsafe artifact uploads) plus one clean workflow that must not be flagged. The trace written next to it (`sample_report.json.trace.jsonl`) lists every tool call the model chose and why. To regenerate it, run the command above with your own key.

## Validation performed

Five repositories were used for validation, and each finding was checked against the repository's source:

| Repository | Kind | Observed result |
|---|---|---|
| `pypa/sampleproject` | well-maintained, should be clean | 0 findings, or one low-severity note about unpinned actions |
| `paastha1/cicd-test-repo` | vulnerable workflows plus one clean one | 9 to 12 correct findings; the clean workflow is never flagged |
| `Grafter-labs/grafter-lab-injection` | injection and permission patterns plus a safe control | 4 to 7 correct findings; the safe control is never flagged |
| `Plazmaz/leaky-repo` | many committed credential files | about 25 of roughly 40 credential files reported, no secret values in the output |
| `m-ayan-asif/AI-Optimization-for-Low-Resource-Devices` | large, well-kept project with Git LFS | 0 findings (secrets come from environment references, CI runs the tests) |

The harness guarantees evidence and safety, not completeness: subtle items (for example secrets passed as `--password` arguments) are sometimes missed.

## Tests

```bash
pytest
```

About 160 offline tests with a scripted fake model and no API calls, so they cost no quota. They cover tool behaviour and safety (path traversal, symlinks, binaries, redaction, budgets), the evidence gate and rule-id numbering, the agent loop (gate refusal, repair round, forced finish, bad JSON, prompt-injection fencing, no secret leakage, bounded prompt size), the Gemini wrapper (429, daily quota, fallback, 5xx, bad key) and the CLI contract.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `GEMINI_API_KEY (or GOOGLE_API_KEY) is not set` | Set the variable or create `.env` from `.env.example`. |
| `could not clone ... could not read Username` | The URL is wrong or the repository is private. Only public `https://github.com/owner/repo` URLs work. |
| Nothing prints for a while after the command | Use `-v` to see progress. The clone of a large repository can take time. |
| `rate limited (429); waiting` | Normal on free keys; the agent waits and retries. |
| `daily quota` error | The key's daily limit is used up. Wait for the reset or set `GEMINI_FALLBACK_MODELS`. |
| `did not produce a final report within the step budget` | Re-run with a larger `--max-turns` (for example 30). |
| One test is skipped on Windows | The symlink test needs administrator rights or Developer Mode; it skips itself. The protection it checks is still in the code. |
| PowerShell blocks `Activate.ps1` | Run `Set-ExecutionPolicy -Scope Process Bypass` once, then activate again. |

## Run-to-run variation

LLM output is not fully deterministic, even at temperature 0. Running the same repository twice can change the number of findings, their severity, or which low-impact items are mentioned. The evidence gate guarantees every reported finding cites a file that was opened and a real line number; it does not guarantee identical output or complete coverage.

## Limitations

- Public `github.com` repositories only; clone depth is 100 commits.
- Remote-only controls (branch protection, required reviews, secret scanning) cannot be seen from files and are never reported.
- Code is never executed, so failing tests and runtime behaviour cannot be detected.
- Findings are only as good as the chosen Gemini model. Flash-Lite is fast and cheap but can miss subtle issues; set `GEMINI_MODEL` to a stronger model if your quota allows.
- Redaction is best-effort: a credential in an unusual format could reach the model unmasked.
- Absence-type problems (no tests, no CI, loose dependency bounds) are the least reliable category: on small repositories where these are the only issues, the model may report nothing.
