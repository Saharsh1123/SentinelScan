import json
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"
AWS_REASON = "value matched AKIA-prefixed AWS access key pattern"

SUPPORTED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
SUPPORTED_SEVERITY = {"LOW", "MEDIUM", "HIGH"}


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAIN_FILE = PROJECT_ROOT / "main.py"


def _default_cli_cwd():
    """
    Create an isolated working directory for CLI subprocess tests.

    The repository root may contain a developer sentinelscan.json. Running
    default-behavior subprocess tests from the repo root would accidentally
    apply that config to every test. A temporary cwd keeps tests independent
    while still allowing individual tests to opt into a cwd config explicitly.
    """
    return Path(tempfile.mkdtemp(prefix="sentinelscan-cli-"))


def run_cli(*args, cwd=None):
    """
    Run the SentinelScan CLI with the provided arguments.

    Uses the current Python interpreter and an absolute main.py path so tests
    work even when the subprocess runs from a temporary directory.
    """
    return subprocess.run(
        [sys.executable, str(MAIN_FILE), *map(str, args)],
        capture_output=True,
        text=True,
        cwd=cwd or _default_cli_cwd(),
        timeout=30,
    )


def assert_success(result):
    """
    Assert that a CLI command completed successfully.

    Includes stdout/stderr in the failure message to make CLI failures easier
    to debug.
    """
    assert result.returncode == 0, (
        f"Expected CLI command to succeed.\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )


def parse_json_output(result):
    """
    Parse CLI stdout as JSON.
    """
    return json.loads(result.stdout)


def write_python_file(root_path, relative_path, content):
    """
    Write a Python fixture file under a temporary test directory.
    """
    file_path = root_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return file_path


def write_ignore_file(root_path, content):
    """
    Write a .sentinelscanignore file under a temporary test directory.
    """
    ignore_file = root_path / ".sentinelscanignore"
    ignore_file.write_text(content, encoding="utf-8")
    return ignore_file


def make_confidence_fixture(tmp_path):
    """
    Create one file with LOW, MEDIUM, and HIGH confidence findings.
    """
    return write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
    )


def make_severity_fixture(tmp_path):
    """
    Create one file with HIGH and MEDIUM severity findings.
    """
    return write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n' 'token = "abc1234567890j"\n',
    )


def make_combined_filter_fixture(tmp_path):
    """
    Create one file with findings that exercise severity and confidence filters.
    """
    return write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n'
        'token = "abc1234567890j"\n'
        'random_var = "AKIAEXAMPLE123456789"\n',
    )


def get_entropy(finding):
    """
    Return entropy from a JSON finding.

    Supports either `entropy` or `entropy_score` if the output field name
    changes during refactoring.
    """
    if "entropy" in finding:
        return finding["entropy"]

    if "entropy_score" in finding:
        return finding["entropy_score"]

    raise AssertionError("JSON finding is missing entropy metadata")


def assert_entropy_metadata(finding):
    """
    Assert that a JSON finding includes usable entropy metadata.
    """
    entropy = get_entropy(finding)

    assert isinstance(entropy, (int, float))
    assert entropy >= 0


def assert_json_finding(
    finding,
    *,
    line,
    file,
    var_name,
    rule_id,
    rule,
    severity,
    value,
    reason,
    confidence=None,
):
    """
    Assert stable JSON finding fields while allowing extra future fields.
    """
    assert finding["line"] == line
    assert finding["file"] == str(file)
    assert finding["var_name"] == var_name
    assert finding["rule_id"] == rule_id
    assert finding["rule"] == rule
    assert finding["severity"] == severity
    assert finding["value"] == value
    assert finding["reason"] == reason

    if confidence is None:
        assert finding["confidence"] in SUPPORTED_CONFIDENCE
    else:
        assert finding["confidence"] == confidence

    assert_entropy_metadata(finding)


def assert_single_json_finding(data, **expected):
    """
    Assert that JSON output contains exactly one expected finding.
    """
    assert len(data) == 1
    assert_json_finding(data[0], **expected)


def assert_pure_json_output(result):
    """
    Assert that JSON mode emits only JSON and no human-readable text.
    """
    assert "Scanning" not in result.stdout
    assert "--- Findings ---" not in result.stdout
    assert "Total findings" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout
    assert "Entropy:" not in result.stdout
