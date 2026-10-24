import subprocess
import pytest

import tools as tools_module
from conftest import make_repo
from tools import (
    REDACTED, RepositoryTools, ToolError, is_credential_like, redact_line, redact_lines, tags_for, validate_github_url,
)


# ---------------------------------------------------------------- classification
def test_listing_tags_credentials_workflows_and_templates(tools):
    listing = tools.list_files()
    assert ".env [CREDENTIAL-LIKE: MUST READ]" in listing
    assert ".ssh/id_rsa [CREDENTIAL-LIKE: MUST READ]" in listing
    assert ".github/workflows/ci.yml [WORKFLOW: MUST READ]" in listing
    assert ".env.example [ENV-TEMPLATE]" in listing
    assert ".ssh/id_rsa.pub" in listing and "id_rsa.pub [CRED" not in listing
    assert tools.listed is True


def test_mandatory_files_exclude_templates_and_public_keys(tools):
    assert set(tools.mandatory_files()) == {".github/workflows/ci.yml", ".env", ".ssh/id_rsa"}


@pytest.mark.parametrize("path", [".env", ".env.production", "a/b/id_ed25519", "x.pem", "cloud/.s3cfg", ".netrc", "web/ruby/config/master.key", "terraform.tfstate", "sftp-config.json"])
def test_credential_like_names(path):
    assert is_credential_like(path)


@pytest.mark.parametrize("path", [".env.example", ".env.sample", "id_rsa.pub", "src/main.py", "README.md", "docs/keyboard.md"])
def test_not_credential_like(path):
    assert not is_credential_like(path)


def test_tracked_artifacts_are_hinted():
    assert "TRACKED-ARTIFACT?" in tags_for("pkg/__pycache__/x.cpython-311.pyc")
    assert "TRACKED-ARTIFACT?" in tags_for(".idea/workspace.xml")


def test_mandatory_list_is_capped_for_quota(tmp_path):
    root = make_repo(tmp_path / "many", {f"keys/k{i}.pem": "x\n" for i in range(80)} | {".github/workflows/a.yml": "on: push\n"})
    t = RepositoryTools("https://github.com/e/r", root=root)
    mandatory = t.mandatory_files()
    assert len(mandatory) == tools_module.MAX_MANDATORY_FILES
    assert mandatory[0] == ".github/workflows/a.yml"  # workflows first


def test_big_repo_listing_is_summarised_with_drilldown(tmp_path):
    files = {f"src/pkg{i % 7}/m{i}.py": "x = 1\n" for i in range(200)} | {".env": "A=1\n"}
    t = RepositoryTools("https://github.com/e/r", root=make_repo(tmp_path / "big", files))
    out = t.list_files()
    assert "DIRECTORY SUMMARY" in out and ".env [CREDENTIAL-LIKE" in out
    assert len(out) < tools_module.MAX_TOOL_TEXT
    sub = t.list_files("src/pkg1")
    assert "tracked files under src/pkg1/" in sub
    with pytest.raises(ToolError):
        t.list_files("nope")


def test_repo_facts_detect_equivalents(tmp_path):
    root = make_repo(tmp_path / "p", {"README.md": "x", "pyproject.toml": "[tool.ruff]\n", "uv.lock": "", "tests/test_a.py": "def test(): pass\n", ".gitignore": "x"})
    out = RepositoryTools("https://github.com/e/r", root=root).list_files()
    assert "lockfiles: ['uv.lock']" in out and "tests/test_a.py" in out


# ---------------------------------------------------------------------- redaction
@pytest.mark.parametrize(
    "line,secret",
    [
        ("API_TOKEN=sk-abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnop"),
        ("DATABASE_PASSWORD: super_secret_prod_password_2024", "super_secret"),
        ("AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
        ("APP_KEY=base64:4StV8PVvCLC6gkJXgGdkYdlWW0suqjb2sj0QvDHx3Hsn", "4StV8PV"),
        ("machine imap.gmail.com login me password pass123", "pass123"),
        ("https://user@example.com:password!#@498@github.com", "498"),
        ("postgres://admin:s3cret@db:5432/app", "s3cret"),
        ('"auth": "dXNlcjpwYXNzd29yZA=="', "dXNlcjpwYXN"),
        ("GH_TOKEN: ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2", "a1B2c3D4"),
    ],
)
def test_secret_values_are_redacted(line, secret):
    assert secret not in redact_line(line)
    assert REDACTED in redact_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "token: ${{ secrets.NPM_TOKEN }}",
        "api_key = os.environ['API_KEY']",
        "password = getpass.getpass()",
        "DB_PASSWORD=changeme",
        "API_TOKEN=",
        "key: pip-cache-v1",
        "uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab",
        "# the password must be rotated every 90 days",
    ],
)
def test_references_and_placeholders_are_not_redacted(line):
    assert redact_line(line) == line


def test_pem_body_is_blanked_but_line_numbers_survive():
    lines = ["a", "-----BEGIN PRIVATE KEY-----", "AAAA", "BBBB", "-----END PRIVATE KEY-----", "b"]
    out = redact_lines(lines)
    assert len(out) == len(lines)
    assert out[2] == out[3] == tools_module.REDACTED_KEY and out[5] == "b"


def test_read_file_never_returns_secret_values(tools):
    out = tools.read_file(".env") + tools.read_file(".ssh/id_rsa") + tools.read_file("app.py")
    for secret in ("abcdefghijklmnop", "hunter2hunter2", "MIIEogIBAAKC", "correct-horse"):
        assert secret not in out


# --------------------------------------------------------------------- read tools
def test_read_records_exact_lines_shown(tools):
    out = tools.read_file("app.py", 2, 3)
    assert out.splitlines()[0].startswith("2: ")
    assert tools.opened_files["app.py"] == {2, 3}


def test_read_budget_only_records_displayed_lines(tmp_path):
    root = make_repo(tmp_path / "wide", {"big.txt": "\n".join(f"line {i} " + "x" * 200 for i in range(1, 300))})
    t = RepositoryTools("https://github.com/e/r", root=root)
    out = t.read_file("big.txt", 1, 250)
    shown = [int(l.split(":")[0]) for l in out.splitlines() if l[:1].isdigit()]
    assert t.opened_files["big.txt"] == set(shown) and max(shown) < 250
    assert "more lines; call read_file" in out


def test_binary_file_is_opened_but_not_shown(tools):
    assert "binary file" in tools.read_file("blob.bin")
    assert "blob.bin" in tools.opened_files and tools.opened_files["blob.bin"] == set()


@pytest.mark.parametrize("bad", ["../outside.txt", "/etc/passwd", "a/../../etc/passwd", "", "untracked.txt", ".git/config"])
def test_path_escape_and_untracked_rejected(tools, bad):
    with pytest.raises(ToolError):
        tools.read_file(bad)


def test_symlink_escape_is_rejected(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("TOP SECRET")
    root = tmp_path / "linked"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    try:
        (root / "link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks need admin rights or Developer Mode on Windows")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@e.com", "commit", "-q", "-m", "x"], cwd=root, check=True)
    t = RepositoryTools("https://github.com/e/r", root=root)
    with pytest.raises(ToolError):
        t.read_file("link.txt")


def test_invalid_line_range(tools):
    with pytest.raises(ToolError):
        tools.read_file("app.py", 5, 2)
    with pytest.raises(ToolError):
        tools.read_file("app.py", 1, 900)


def test_read_files_batches_and_reports_per_file_errors(tools):
    out = tools.read_files([".env", "missing.txt", "app.py"])
    assert "===== .env =====" in out and "TOOL ERROR" in out and "===== app.py =====" in out
    assert {".env", "app.py"} <= set(tools.opened_files)
    with pytest.raises(ToolError):
        tools.read_files([])


# -------------------------------------------------------------------- search / git
def test_search_is_redacted_glob_filtered_and_labelled_as_lead(tools):
    out = tools.search_code("password", path_glob="*.py")
    assert "app.py:3:" in out and "correct-horse" not in out and "leads only" in out
    assert ".env:" not in out
    assert tools.search_code("zzzz_no_such") == "[no matches]"
    with pytest.raises(ToolError):
        tools.search_code("(")
    assert tools.opened_files == {}  # searching never counts as opening


def test_search_caps_matches_per_file(tmp_path):
    root = make_repo(tmp_path / "s", {"a.txt": "\n".join("needle" for _ in range(50))})
    out = RepositoryTools("https://github.com/e/r", root=root).search_code("needle")
    assert out.count("a.txt:") == tools_module.MAX_MATCHES_PER_FILE


def test_git_log_and_path_filter(tools):
    assert "initial fixture" in tools.git_log()
    assert "initial fixture" in tools.git_log(limit=5, path="app.py", files=True)
    with pytest.raises(ToolError):
        tools.git_log(limit=0)
    with pytest.raises(ToolError):
        tools.git_log(path="../x")


def test_execute_rejects_unknown_tool_and_bad_arguments(tools):
    with pytest.raises(ToolError):
        tools.execute("rm_rf", {})
    with pytest.raises(ToolError):
        tools.execute("read_file", {"wrong": 1})


def test_tools_never_modify_the_repository(tools, repo_path):
    before = subprocess.run(["git", "status", "--porcelain"], cwd=repo_path, capture_output=True, text=True).stdout
    tools.list_files(); tools.read_files([".env", "app.py"]); tools.search_code("x"); tools.git_log()
    after = subprocess.run(["git", "status", "--porcelain"], cwd=repo_path, capture_output=True, text=True).stdout
    assert before == after == ""


# ------------------------------------------------------------------------- urls
@pytest.mark.parametrize("url,expected", [
    ("https://github.com/octocat/Hello-World", "https://github.com/octocat/Hello-World"),
    ("https://github.com/octocat/Hello-World.git", "https://github.com/octocat/Hello-World"),
    ("https://github.com/octocat/Hello-World/", "https://github.com/octocat/Hello-World"),
    ("https://www.github.com/o/r/tree/main", "https://github.com/o/r"),
])
def test_valid_urls(url, expected):
    assert validate_github_url(url) == expected


@pytest.mark.parametrize("url", ["http://github.com/o/r", "https://gitlab.com/o/r", "https://github.com/o", "git@github.com:o/r.git", "file:///etc", "https://github.com/o/r;rm -rf", "not a url", ""])
def test_invalid_urls(url):
    with pytest.raises(ToolError):
        validate_github_url(url)


def test_clone_failure_is_a_clear_error():
    t = RepositoryTools("https://github.com/definitely-not-a-user-zzz/none-existent-repo-zzz", clone_timeout=30)
    try:
        with pytest.raises(ToolError, match="clone|timed out|git"):
            t.prepare()
    finally:
        t.close()


def test_prose_is_not_mangled_but_netrc_lines_in_files_still_are():
    from tools import redact_lines, redact_secrets
    assert redact_secrets("Password hashes stored in file") == "Password hashes stored in file"
    assert redact_secrets("Pass only trusted input via env") == "Pass only trusted input via env"
    assert "hunter2xyz" not in redact_lines(["password hunter2xyz"])[0]


def test_clone_never_downloads_git_lfs_files(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"], seen["env"] = command, kwargs["env"]

        class R:
            returncode, stdout, stderr = 0, "", ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    RepositoryTools("https://github.com/o/r").prepare()
    assert seen["env"]["GIT_LFS_SKIP_SMUDGE"] == "1" and "filter.lfs.smudge=" in seen["command"]


@pytest.mark.parametrize("line", [
    '"jsonwebtoken": "^9.0.3",', '"passport-jwt": "~4.0.1"', '"csrf-token": ">=1.2.3 <2"'.split(" <")[0] + '"',
    '"secret-store": "file:../x"', '"auth-lib": "latest"', '"token-lib": "1.2.3-beta.1"',
])
def test_dependency_versions_are_not_masked_as_secrets(line):
    from tools import redact_line
    assert "REDACTED" not in redact_line(line)


def test_real_credentials_are_still_masked_next_to_version_rule():
    from tools import redact_line
    for line in ['"password": "hunter2hunter2"', 'API_TOKEN=sk-abcdefghijklmnopqrstuvwxyz123456', 'secret = "12345678"']:
        assert "REDACTED" in redact_line(line)


@pytest.mark.parametrize("line", [
    "const token = req.headers.authorization;", '"bos_token_id": 50257,', '"password": "Password",',
    '"confirmPassword": "Confirm Password",', "const passwordHash = await bcrypt.hash(password, 12);",
    '"added_tokens": [',
])
def test_ordinary_code_and_labels_are_not_masked(line):
    from tools import redact_line
    assert "REDACTED" not in redact_line(line)


@pytest.mark.parametrize("line", ["JWT_SECRET=hunter2hunter2xyz", 'password: "S3cretPass99",', "DB_PASSWORD=Sup3rS3cret"])
def test_literal_credentials_are_still_masked(line):
    from tools import redact_line
    assert "REDACTED" in redact_line(line)


def test_rule_ids_are_made_unique_and_sequential_per_prefix(tools):
    from validation import validate_violations
    tools.listed = True
    tools.read_file("app.py")
    items = [
        dict(rule_id="SEC-001", category="security", severity="high", file="app.py", line=i + 1, description=f"Issue {i}", evidence="e", recommendation="r")
        for i in range(3)
    ] + [dict(rule_id="CI-007", category="ci", severity="low", file=None, line=None, description="No lint step", evidence="e", recommendation="r")]
    valid, _ = validate_violations(items, tools)
    assert [v["rule_id"] for v in valid] == ["SEC-001", "SEC-002", "SEC-003", "CI-001"]
