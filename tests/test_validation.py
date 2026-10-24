import pytest

from conftest import finding
from validation import normalize_category, validate_violations

REQUIRED = {"rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"}


@pytest.fixture()
def opened(tools):
    tools.list_files()
    tools.read_file("app.py")
    return tools


def test_supported_finding_is_accepted_with_all_fields(opened):
    valid, rejected = validate_violations([finding()], opened)
    assert rejected == [] and len(valid) == 1 and set(valid[0]) == REQUIRED


def test_file_never_opened_is_rejected(tools):
    tools.list_files()
    valid, rejected = validate_violations([finding()], tools)
    assert valid == [] and "never opened" in rejected[0]["reason"]


def test_line_must_come_from_tool_output(opened):
    valid, rejected = validate_violations([finding(line=99)], opened)
    assert valid == [] and "not in any tool output" in rejected[0]["reason"]


def test_hallucinated_path_rejected(opened):
    _, rejected = validate_violations([finding(file="src/ghost.py")], opened)
    assert "not a tracked file" in rejected[0]["reason"]


def test_absence_findings_use_null_file_and_line(opened):
    valid, _ = validate_violations([finding(rule_id="TEST-001", category="testing", file=None, line=None, description="No tests")], opened)
    assert valid[0]["file"] is None and valid[0]["line"] is None


def test_absence_finding_needs_a_listing_first(tools):
    _, rejected = validate_violations([finding(file=None, line=None)], tools)
    assert "list_files" in rejected[0]["reason"]


def test_null_line_allowed_for_opened_file(opened):
    valid, _ = validate_violations([finding(line=None)], opened)
    assert len(valid) == 1


def test_line_with_null_file_rejected(opened):
    _, rejected = validate_violations([finding(file=None, line=3)], opened)
    assert rejected


@pytest.mark.parametrize("field", sorted(REQUIRED))
def test_missing_field_rejected(opened, field):
    item = finding(); item.pop(field)
    valid, rejected = validate_violations([item], opened)
    assert valid == [] and "missing" in rejected[0]["reason"]


def test_bad_severity_rejected_aliases_mapped(opened):
    assert validate_violations([finding(severity="catastrophic")], opened)[0] == []
    assert validate_violations([finding(severity="Major")], opened)[0][0]["severity"] == "high"


def test_string_line_is_coerced_and_bad_line_rejected(opened):
    assert validate_violations([finding(line="3")], opened)[0][0]["line"] == 3
    assert validate_violations([finding(line="three")], opened)[0] == []
    assert validate_violations([finding(line=True)], opened)[0] == []


def test_duplicates_collapse(opened):
    valid, rejected = validate_violations([finding(), finding(), finding(rule_id="CFG-009")], opened)
    assert len(valid) == 1 and len(rejected) == 2


def test_same_description_on_different_lines_is_not_a_duplicate(tools):
    tools.list_files(); tools.read_file("app.py")
    valid, _ = validate_violations([finding(line=1), finding(line=3)], tools)
    assert len(valid) == 2


def test_secret_values_are_scrubbed_from_report_fields(opened):
    leaky = finding(evidence="PASSWORD = 'correct-horse-battery-staple' and ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2")
    out = validate_violations([leaky], opened)[0][0]["evidence"]
    assert "correct-horse" not in out and "A1b2C3d4" not in out


def test_remote_branch_protection_claims_rejected(opened):
    _, rejected = validate_violations([finding(file=None, line=None, description="Branch protection is not enabled on main")], opened)
    assert "cannot be inferred" in rejected[0]["reason"]


def test_malformed_rule_id_is_replaced(opened):
    assert validate_violations([finding(rule_id="hardcoded creds")], opened)[0][0]["rule_id"] == "SEC-001"


def test_non_list_and_non_dict_inputs(opened):
    assert validate_violations("oops", opened)[0] == []
    assert validate_violations(["x", 3, None], opened)[0] == []


@pytest.mark.parametrize("raw,expected", [("Security", "security"), ("GitHub Actions", "ci"), ("CI/CD", "ci"), ("Repository hygiene", "hygiene"), ("dependency management", "dependencies"), ("Build and release", "build_release"), ("testing", "testing")])
def test_category_normalisation(raw, expected):
    assert normalize_category(raw) == expected
