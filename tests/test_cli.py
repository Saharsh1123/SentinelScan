import json
import subprocess
import sys

import pytest


PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"
AWS_REASON = "value matched AKIA-prefixed AWS access key pattern"

SUPPORTED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}
SUPPORTED_SEVERITY = {"LOW", "MEDIUM", "HIGH"}


def run_cli(*args):
    """
    Run the SentinelScan CLI with the provided arguments.

    Uses the current Python interpreter so tests work locally and in CI.
    """
    return subprocess.run(
        [sys.executable, "main.py", *map(str, args)],
        capture_output=True,
        text=True,
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
        'password = "abcdef"\n'
        'token = "abc1234567890j"\n',
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


# -------------------------
# JSON output behavior
# -------------------------


def test_cli_json_output_is_valid_json(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert len(data) > 0


def test_cli_json_output_is_pure_json(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    assert_pure_json_output(result)

    data = parse_json_output(result)
    assert isinstance(data, list)


def test_cli_json_schema(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    required_keys = {
        "line",
        "file",
        "var_name",
        "rule_id",
        "rule",
        "severity",
        "value",
        "reason",
        "confidence",
    }

    assert len(data) > 0

    for finding in data:
        assert required_keys.issubset(finding.keys())
        assert "entropy" in finding or "entropy_score" in finding


def test_cli_json_field_types(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) > 0

    for finding in data:
        assert isinstance(finding["line"], int)
        assert isinstance(finding["file"], str)
        assert isinstance(finding["var_name"], str)
        assert isinstance(finding["rule_id"], str)
        assert isinstance(finding["rule"], str)
        assert isinstance(finding["severity"], str)
        assert isinstance(finding["value"], str)
        assert isinstance(finding["reason"], str)
        assert isinstance(finding["confidence"], str)
        assert finding["confidence"] in SUPPORTED_CONFIDENCE
        assert finding["severity"] in SUPPORTED_SEVERITY
        assert_entropy_metadata(finding)


def test_cli_json_entropy_values_are_numeric(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(get_entropy(finding) >= 0 for finding in data)


def test_cli_json_detects_secret_in_temp_directory(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'password = "abcdef"\n',
    )

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=vulnerable_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="abcdef",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_no_findings_json_output(tmp_path):
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_empty_directory_json_output_is_empty_list(tmp_path):
    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


# -------------------------
# Text output behavior
# -------------------------


def test_cli_text_output_contains_expected_sections(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path)
    assert_success(result)

    assert "Scanning" in result.stdout
    assert "--- Findings ---" in result.stdout
    assert "Total findings" in result.stdout


def test_cli_text_output_contains_finding_details(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path)
    assert_success(result)

    assert "[HIGH]" in result.stdout
    assert "→" in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_no_findings_text_output(tmp_path):
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path)
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "--- Findings ---" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


def test_cli_empty_directory_text_output_has_no_findings(tmp_path):
    result = run_cli(tmp_path)
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "--- Findings ---" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


# -------------------------
# Severity filtering
# -------------------------


@pytest.mark.parametrize("severity", ["HIGH", "MEDIUM"])
def test_cli_json_severity_filter_keeps_only_matching_severity(tmp_path, severity):
    make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--severity", severity)
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["severity"] == severity for finding in data)
    assert all("confidence" in finding for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


def test_cli_json_severity_high_filter_exact_result(tmp_path):
    findings_file = make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--severity", "HIGH")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=findings_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="abcdef",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_json_severity_medium_filter_exact_result(tmp_path):
    findings_file = make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--severity", "MEDIUM")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=2,
        file=findings_file,
        var_name="token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="abc1234567890j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_cli_text_severity_high_filter(tmp_path):
    make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--severity", "HIGH")
    assert_success(result)

    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" not in result.stdout
    assert "abcdef" in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_text_severity_medium_filter(tmp_path):
    make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--severity", "MEDIUM")
    assert_success(result)

    assert "[MEDIUM]" in result.stdout
    assert "[HIGH]" not in result.stdout
    assert "abc1234567890j" in result.stdout
    assert "abcdef" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_json_severity_filter_with_no_matching_findings(tmp_path):
    write_python_file(tmp_path, "medium.py", 'token = "abcdef"\n')

    result = run_cli(tmp_path, "--json", "--severity", "HIGH")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_text_severity_filter_with_no_matching_findings(tmp_path):
    write_python_file(tmp_path, "medium.py", 'token = "abcdef"\n')

    result = run_cli(tmp_path, "--severity", "HIGH")
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


# -------------------------
# Confidence filtering
# -------------------------


@pytest.mark.parametrize("confidence", ["LOW", "MEDIUM", "HIGH"])
def test_cli_json_confidence_filter_keeps_only_matching_confidence(
    tmp_path,
    confidence,
):
    make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--confidence", confidence)
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["confidence"] == confidence for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


def test_cli_json_confidence_low_filter_exact_result(tmp_path):
    findings_file = make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--confidence", "LOW")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=findings_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="abcdef",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_json_confidence_medium_filter_exact_result(tmp_path):
    findings_file = make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--confidence", "MEDIUM")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=2,
        file=findings_file,
        var_name="token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="xyzttttggfdddf",
        reason=TOKEN_REASON,
        confidence="MEDIUM",
    )


def test_cli_json_confidence_high_filter_exact_result(tmp_path):
    findings_file = make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--json", "--confidence", "HIGH")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=3,
        file=findings_file,
        var_name="api_token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="abc1234567890j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_cli_text_confidence_low_filter(tmp_path):
    make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--confidence", "LOW")
    assert_success(result)

    assert "abcdef" in result.stdout
    assert "xyzttttggfdddf" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_text_confidence_medium_filter(tmp_path):
    make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--confidence", "MEDIUM")
    assert_success(result)

    assert "xyzttttggfdddf" in result.stdout
    assert "abcdef" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_text_confidence_high_filter(tmp_path):
    make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--confidence", "HIGH")
    assert_success(result)

    assert "abc1234567890j" in result.stdout
    assert "abcdef" not in result.stdout
    assert "xyzttttggfdddf" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_json_confidence_filter_with_no_matching_findings(tmp_path):
    write_python_file(tmp_path, "low.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json", "--confidence", "HIGH")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_text_confidence_filter_with_no_matching_findings(tmp_path):
    write_python_file(tmp_path, "low.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--confidence", "HIGH")
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


# -------------------------
# Combined filters
# -------------------------


def test_cli_json_severity_and_confidence_combined(tmp_path):
    findings_file = make_combined_filter_fixture(tmp_path)

    result = run_cli(
        tmp_path,
        "--json",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=3,
        file=findings_file,
        var_name="random_var",
        rule_id="AWS_ACCESS_KEY",
        rule="AWS Access Key",
        severity="HIGH",
        value="AKIAEXAMPLE123456789",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_cli_text_severity_and_confidence_combined(tmp_path):
    make_combined_filter_fixture(tmp_path)

    result = run_cli(tmp_path, "--severity", "HIGH", "--confidence", "HIGH")
    assert_success(result)

    assert "AWS Access Key" in result.stdout
    assert "AKIAEXAMPLE123456789" in result.stdout
    assert "abcdef" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_json_severity_and_confidence_no_matches(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n'
        'token = "abc1234567890j"\n',
    )

    result = run_cli(
        tmp_path,
        "--json",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


# -------------------------
# Redaction behavior
# -------------------------


def test_cli_text_output_is_unredacted_by_default(tmp_path):
    write_python_file(tmp_path, "password_file.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path)
    assert_success(result)

    assert "abcdef" in result.stdout
    assert "a****f" not in result.stdout
    assert "[REDACTED]" not in result.stdout
    assert "Confidence:" in result.stdout


def test_cli_text_redact_masks_secret_value(tmp_path):
    write_python_file(tmp_path, "password_file.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--redact")
    assert_success(result)

    assert "a****f" in result.stdout
    assert "abcdef" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout
    assert "Password" in result.stdout


def test_cli_json_output_is_unredacted_by_default(tmp_path):
    password_file = write_python_file(
        tmp_path,
        "password_file.py",
        'password = "abcdef"\n',
    )

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=password_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="abcdef",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_json_redact_masks_secret_value(tmp_path):
    password_file = write_python_file(
        tmp_path,
        "password_file.py",
        'password = "abcdef"\n',
    )

    result = run_cli(tmp_path, "--json", "--redact")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=password_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="a****f",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_json_redact_output_is_pure_json(tmp_path):
    write_python_file(tmp_path, "password_file.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--json", "--redact")
    assert_success(result)

    assert_pure_json_output(result)

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert data[0]["value"] == "a****f"
    assert data[0]["confidence"] == "LOW"
    assert_entropy_metadata(data[0])


def test_cli_json_redact_short_boundary_value(tmp_path):
    password_file = write_python_file(
        tmp_path,
        "password_file.py",
        'password = "abcd"\n',
    )

    result = run_cli(tmp_path, "--json", "--redact")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=password_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="[REDACTED]",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_json_redact_long_value(tmp_path):
    password_file = write_python_file(
        tmp_path,
        "password_file.py",
        'password = "abc_def-123#$%^&*()"\n',
    )

    result = run_cli(tmp_path, "--json", "--redact")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=password_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="ab***************()",
        reason=PASSWORD_REASON,
        confidence="HIGH",
    )


def test_cli_json_redact_aws_access_key(tmp_path):
    aws_file = write_python_file(
        tmp_path,
        "aws_file.py",
        'random_var = "AKIAEXAMPLE123456789"\n',
    )

    result = run_cli(tmp_path, "--json", "--redact")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=aws_file,
        var_name="random_var",
        rule_id="AWS_ACCESS_KEY",
        rule="AWS Access Key",
        severity="HIGH",
        value="AK****************89",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_cli_json_confidence_and_redact_combined(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n'
        'api_token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--json", "--confidence", "HIGH", "--redact")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=2,
        file=findings_file,
        var_name="api_token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="ab**********0j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_cli_text_confidence_and_redact_combined(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n'
        'api_token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--confidence", "HIGH", "--redact")
    assert_success(result)

    assert "ab**********0j" in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "abcdef" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_json_severity_confidence_and_redact_combined(tmp_path):
    findings_file = make_combined_filter_fixture(tmp_path)

    result = run_cli(
        tmp_path,
        "--json",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
        "--redact",
    )
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=3,
        file=findings_file,
        var_name="random_var",
        rule_id="AWS_ACCESS_KEY",
        rule="AWS Access Key",
        severity="HIGH",
        value="AK****************89",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_cli_no_findings_json_with_redact(tmp_path):
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path, "--json", "--redact")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_no_findings_text_with_redact(tmp_path):
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path, "--redact")
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "[REDACTED]" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


# -------------------------
# .sentinelscanignore integration
# -------------------------


def test_cli_json_respects_sentinelscanignore_file(tmp_path):
    write_python_file(tmp_path, "ignored.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')
    write_ignore_file(tmp_path, "ignored.py\n")

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_text_respects_sentinelscanignore_file(tmp_path):
    write_python_file(tmp_path, "ignored.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')
    write_ignore_file(tmp_path, "ignored.py\n")

    result = run_cli(tmp_path)
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "ignored.py" not in result.stdout
    assert "abcdef" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


def test_cli_json_respects_ignored_directory(tmp_path):
    write_python_file(tmp_path, "fixtures/vulnerable.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')
    write_ignore_file(tmp_path, "fixtures/\n")

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_respects_ignore_glob_pattern(tmp_path):
    write_python_file(tmp_path, "bundle.min.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')
    write_ignore_file(tmp_path, "*.min.py\n")

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_still_scans_non_ignored_files(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'token = "abc1234567890j"\n',
    )
    write_python_file(tmp_path, "ignored.py", 'password = "abcdef"\n')
    write_ignore_file(tmp_path, "ignored.py\n")

    result = run_cli(tmp_path, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=vulnerable_file,
        var_name="token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="abc1234567890j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_cli_json_parent_sentinelscanignore_applies_to_child_scan_path(tmp_path):
    project_dir = tmp_path / "project"

    write_python_file(project_dir, "ignored.py", 'password = "abcdef"\n')
    safe_file = write_python_file(project_dir, "safe.py", 'token = "abc1234567890j"\n')
    write_ignore_file(tmp_path, "project/ignored.py\n")

    result = run_cli(project_dir, "--json")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=safe_file,
        var_name="token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="abc1234567890j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


# -------------------------
# Invalid CLI input
# -------------------------


@pytest.mark.parametrize(
    ("args", "expected_error"),
    [
        (("--severity", "CRITICAL"), "invalid choice"),
        (("--confidence", "VERY_HIGH"), "invalid choice"),
    ],
)
def test_cli_invalid_choice_fails(args, expected_error):
    result = run_cli("test_dirs", *args)

    assert result.returncode != 0
    assert expected_error in result.stderr


def test_cli_invalid_path_prints_error():
    result = run_cli("does_not_exist")

    assert "[ERROR]" in result.stdout or "[ERROR]" in result.stderr