import json

import pytest

import agent
from tools import ToolError
from validation import ALLOWED_SEVERITIES

REPORT = {"repository": "https://github.com/o/r", "violations": []}
STATS = {"steps": 3, "tool_calls": 2, "gate_rejections": 0, "rejected_findings": 0}


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch, tmp_path):
    import dotenv

    monkeypatch.setattr(dotenv, "load_dotenv", lambda *a, **k: False)  # never read a developer's real .env during tests
    monkeypatch.chdir(tmp_path)
    for var in ("GEMINI_API_KEY", "GEMINI_MODEL", "GEMINI_FALLBACK_MODELS", "GEMINI_MIN_INTERVAL_SEC"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def stub(monkeypatch):
    class StubLLM:
        calls, total_tokens, model = 1, 5, "stub"

        def __init__(self, *a, **k): ...

    monkeypatch.setattr(agent, "GeminiLLM", StubLLM)
    return StubLLM


def test_invalid_url_exits_2_without_calling_anything(capsys):
    assert agent.main(["--repo", "https://gitlab.com/o/r", "--output", "r.json"]) == 2
    assert "github.com" in capsys.readouterr().err


def test_missing_api_key_exits_2(monkeypatch, capsys):
    assert agent.main(["--repo", "https://github.com/o/r", "--output", "r.json"]) == 2
    assert "GEMINI_API_KEY" in capsys.readouterr().err


def test_success_writes_valid_json_and_trace(monkeypatch, tmp_path, stub):
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    monkeypatch.setattr(agent, "run_audit", lambda *a, **k: (REPORT, [{"step": 1, "type": "tool_call", "tool": "list_files"}], STATS))
    out = tmp_path / "sub" / "report.json"
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(out)]) == 0
    assert json.loads(out.read_text()) == REPORT
    assert json.loads((tmp_path / "sub" / "report.json.trace.jsonl").read_text().splitlines()[0])["tool"] == "list_files"


def test_fatal_error_exits_nonzero_and_writes_no_report(monkeypatch, tmp_path, stub, capsys):
    monkeypatch.setenv("GEMINI_API_KEY", "x")

    def boom(*a, **k):
        raise ToolError("could not clone https://github.com/o/r")

    monkeypatch.setattr(agent, "run_audit", boom)
    out = tmp_path / "report.json"
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(out)]) == 1
    assert not out.exists() and "could not clone" in capsys.readouterr().err


def test_model_env_and_fallbacks_are_honoured(monkeypatch, tmp_path):
    seen = {}

    class Spy:
        calls, total_tokens, model = 0, 0, "spy"

        def __init__(self, key, models, **kw):
            seen["models"], seen["interval"] = models, kw["min_interval"]

    monkeypatch.setattr(agent, "GeminiLLM", Spy)
    monkeypatch.setattr(agent, "run_audit", lambda *a, **k: (REPORT, [], STATS))
    monkeypatch.setenv("GEMINI_API_KEY", "x"); monkeypatch.setenv("GEMINI_MODEL", "my-model"); monkeypatch.setenv("GEMINI_MIN_INTERVAL_SEC", "7")
    agent.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json")])
    assert seen["models"][0] == "my-model" and len(seen["models"]) >= 2 and seen["interval"] == 7.0


def test_run_audit_closes_its_own_clone_even_when_the_audit_fails(monkeypatch, repo_path):
    from auditor import AuditError
    from conftest import FakeLLM
    from tools import RepositoryTools

    closed = []

    class FakeClone(RepositoryTools):
        def prepare(self):
            self.root = repo_path

        def close(self):
            closed.append(True)

    monkeypatch.setattr(agent, "RepositoryTools", FakeClone)
    with pytest.raises(AuditError):
        agent.run_audit("https://github.com/o/r", FakeLLM(policy=lambda prompt, n: "garbage"))
    assert closed == [True]


def test_report_contract_fields_and_severity_values():
    from validation import REQUIRED

    assert set(REQUIRED) == {"rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"}
    assert ALLOWED_SEVERITIES == ("critical", "high", "medium", "low")
