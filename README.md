# Evidence-First DevOps Repository Auditing Agent

A Python agent that audits a public GitHub repository for defensible DevOps issues. It implements its own observe -> reason -> choose tool -> execute -> interpret loop; no agent framework is used.

## Setup

Requires Python 3.10+ and Git.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Create a free Gemini API key in [Google AI Studio](https://aistudio.google.com/app/apikey), then put it in `.env` or set it in your shell:

```powershell
$env:GEMINI_API_KEY = "your-key"
python agent.py --repo https://github.com/owner/repository --output report.json
```

`GEMINI_MODEL` is optional and defaults to `gemini-3.6-flash`. Availability and quotas are determined by Google; the agent does not require a paid Gemini plan.

## What the agent does

The agent clones the public target to a fresh temporary directory, reads it only, and removes that temporary clone at the end. It never runs repository code, test suites, package scripts, or Git hooks.

It provides four inspection tools:

- `list_files()` discovers tracked files and labels credential-like files (`.env`, `id_rsa`, `*.pem`, etc.) and GitHub Action workflow files.
- `read_file(path)` returns numbered source lines and records exactly what the agent opened.
- `search_code(pattern)` finds leads across tracked text files.
- `git_log()` reads recent commit history.

Gemini receives the tool observations and chooses each next tool. Results from search are only leads, not proof.

## Evidence safeguards

- Repository text, including READMEs, documentation, and comments, is explicitly treated as untrusted evidence rather than instructions.
- The agent is not allowed to finish until every tagged credential-like and workflow file has been opened.
- A final finding is discarded unless its file was opened with `read_file` and its line number exists in that numbered tool output.
- Sensitive values are redacted from tool observations and JSON reports. The raw secret is never placed in the report.
- The reporter rejects duplicate findings and unsupported or malformed model output.

The output always follows the required contract:

```json
{
  "repository": "https://github.com/owner/repository",
  "violations": []
}
```

See `sample_report.json` for an empty-report example.

## Tests

```bash
pytest -q
```

The tests verify mandatory-file tagging, redaction, line-level proof enforcement, and path traversal protection.

## Limitations and safe behavior

The repository must be public and must use an HTTPS `github.com/owner/repository` URL. A failed clone, invalid URL, API error, or exhausted agent step limit exits nonzero without writing a fabricated report. The agent does not infer remote-only controls such as GitHub branch protection from repository files.

