import json
import subprocess
import sys

import pytest

from scanner import line_has_inline_ignore, scan


PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"

SUPPORTED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


def run_cli(*args):
    """
    Run the SentinelScan CLI with the current Python interpreter.
    """
    return subprocess.run(
        [sys.executable, "main.py", *map(str, args)],
        capture_output=True,
        text=True,
    )


def assert_success(result):
    """
    Assert that a CLI command succeeded and show useful output if it did not.
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


def get_entropy(finding):
    """
    Return entropy metadata from a JSON finding.
    """
    if "entropy" in finding:
        return finding["entropy"]

    if "entropy_score" in finding:
        return finding["entropy_score"]

    raise AssertionError("JSON finding is missing entropy metadata")


def assert_entropy_metadata(finding):
    """
    Assert that entropy metadata exists and is numeric.
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


# -------------------------
# Inline ignore marker unit tests
# -------------------------


@pytest.mark.parametrize(
    "line",
    [
        'password = "abcdef"  # sentinelscan: ignore',
        'password = "abcdef" # sentinelscan: ignore',
        'password = "abcdef"  # sentinelscan: ignore because this is fake',
        "    token = 'abcdef'  # sentinelscan: ignore",
    ],
)
def test_line_has_inline_ignore_returns_true_for_valid_marker(line):
    assert line_has_inline_ignore(line) is True


@pytest.mark.parametrize(
    "line",
    [
        'password = "abcdef"',
        'password = "abcdef"  # unrelated comment',
        'password = "abcdef"  # sentinel scan ignore',
        'password = "abcdef"  # sentinelscan ignore',
        'password = "abcdef"  # ignore',
    ],
)
def test_line_has_inline_ignore_returns_false_without_valid_marker(line):
    assert line_has_inline_ignore(line) is False


def test_line_has_inline_ignore_does_not_match_marker_inside_string_literal():
    line = 'note = "sentinelscan: ignore"'

    assert line_has_inline_ignore(line) is False


# -------------------------
# Scanner-level inline ignore behavior
# -------------------------


def test_scan_suppresses_single_inline_ignored_finding(tmp_path):
    ignored_file = write_python_file(
        tmp_path,
        "ignored.py",
        'password = "abcdef"  # sentinelscan: ignore\n',
    )

    result = scan([ignored_file])

    assert result == []


def test_scan_keeps_finding_without_inline_ignore(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'password = "abcdef"\n',
    )

    result = scan([vulnerable_file])

    assert len(result) == 1

    finding = result[0]

    assert finding.file_path == str(vulnerable_file)
    assert finding.line_number == 1
    assert finding.var_name == "password"
    assert finding.value == "abcdef"
    assert finding.rule_id == "PASSWORD"
    assert finding.rule_name == "Password"
    assert finding.severity == "HIGH"
    assert finding.reason == PASSWORD_REASON
    assert finding.confidence == "LOW"


def test_scan_unrelated_comment_does_not_suppress_finding(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'password = "abcdef"  # this is a normal comment\n',
    )

    result = scan([vulnerable_file])

    assert len(result) == 1
    assert result[0].rule_id == "PASSWORD"
    assert result[0].value == "abcdef"


def test_scan_inline_ignore_only_suppresses_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n'
        'token = "abc1234567890j"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1

    finding = result[0]

    assert finding.line_number == 2
    assert finding.var_name == "token"
    assert finding.rule_id == "TOKEN"
    assert finding.value == "abc1234567890j"


def test_scan_inline_ignore_on_previous_line_does_not_suppress_next_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        "# sentinelscan: ignore\n"
        'password = "abcdef"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].line_number == 2
    assert result[0].rule_id == "PASSWORD"


def test_scan_inline_ignore_suppresses_multiple_findings_on_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore\n',
    )

    result = scan([findings_file])

    assert result == []


def test_scan_inline_ignore_suppresses_multiple_sensitive_targets_on_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = token = "abcdef"  # sentinelscan: ignore\n',
    )

    result = scan([findings_file])

    assert result == []


def test_scan_inline_ignore_in_string_literal_does_not_suppress_finding(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "sentinelscan: ignore"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].rule_id == "PASSWORD"
    assert result[0].value == "sentinelscan: ignore"