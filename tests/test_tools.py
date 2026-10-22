import subprocess
from pathlib import Path

import pytest

from agent import validate_violations
from tools import RepositoryTools, ToolError


@pytest.fixture()
def repository(tmp_path: Path) -> RepositoryTools:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".env").write_text("TOKEN=AIzaThisIsASecretValueLongEnough12345\nPASSWORD=ordinary-secret-value\n")
    (root / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: [push]\n")
    (root / "app.py").write_text("API_KEY = 'sk-abcdefghijklmnopqrstuvwxyz'\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True)
    return RepositoryTools("https://github.com/example/repo", root=root)


def test_listing_tags_credential_and_workflow_files(repository: RepositoryTools) -> None:
    listing = repository.list_files()
    assert ".env [CREDENTIAL-LIKE: MUST READ]" in listing
    assert ".github/workflows/ci.yml [WORKFLOW: MUST READ]" in listing
    assert repository.mandatory_files() == {".env", ".github/workflows/ci.yml"}


def test_reading_redacts_and_records_exact_lines(repository: RepositoryTools) -> None:
    output = repository.read_file(".env")
    assert "[REDACTED_SECRET]" in output
    assert "AIzaThis" not in output
    assert "ordinary-secret-value" not in output
    assert repository.opened_files[".env"] == {1, 2}


def test_report_rejects_a_finding_without_opened_evidence(repository: RepositoryTools) -> None:
    finding = {
        "rule_id": "SEC-001", "category": "security", "severity": "critical",
        "file": "app.py", "line": 1, "description": "Hardcoded credential",
        "evidence": "Credential assignment", "recommendation": "Use an environment variable",
    }
    assert validate_violations([finding], repository) == []
    repository.read_file("app.py")
    assert validate_violations([finding], repository) == [finding]


def test_path_escape_is_rejected(repository: RepositoryTools) -> None:
    with pytest.raises(ToolError):
        repository.read_file("../outside.txt")

