import json
import subprocess
import sys


PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"
AWS_REASON = "value matched AKIA-prefixed AWS access key pattern"


def run_cli(*args):
    """
    Run the SentinelScan CLI with the provided arguments.

    Uses the current Python interpreter so tests work locally and in CI.
    """
    return subprocess.run(
        [sys.executable, "main.py", *args],
        capture_output=True,
        text=True,
    )


def parse_json_output(result):
    """
    Parse CLI stdout as JSON.
    """
    return json.loads(result.stdout)


# Ensure JSON mode runs successfully and returns valid JSON
def test_cli_json_output_is_valid_json():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert len(data) > 0


# Ensure JSON findings use the expected schema
def test_cli_json_schema():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert len(data) > 0

    required_keys = {
        "line",
        "file",
        "var_name",
        "rule_id",
        "rule",
        "severity",
        "value",
        "reason",
    }

    for finding in data:
        assert required_keys.issubset(finding.keys())


# Ensure JSON finding fields have the expected data types
def test_cli_json_field_types():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

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


# Ensure JSON mode does not include human-readable CLI text
def test_cli_json_output_is_pure_json():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

    assert "Scanning" not in result.stdout
    assert "--- Findings ---" not in result.stdout
    assert "Total findings" not in result.stdout
    assert "Reason:" not in result.stdout

    data = parse_json_output(result)
    assert isinstance(data, list)


# Ensure normal CLI mode prints human-readable scan output
def test_cli_text_output_contains_expected_sections():
    result = run_cli("test_dirs")

    assert result.returncode == 0

    assert "Scanning" in result.stdout
    assert "--- Findings ---" in result.stdout
    assert "Total findings" in result.stdout


# Ensure normal CLI output contains finding details and reasons
def test_cli_text_output_contains_finding_details():
    result = run_cli("test_dirs")

    assert result.returncode == 0

    assert "[HIGH]" in result.stdout
    assert "→" in result.stdout
    assert "Reason:" in result.stdout


# Ensure HIGH severity filtering works in JSON mode
def test_cli_json_severity_high_filter():
    result = run_cli("test_dirs", "--json", "--severity", "HIGH")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["severity"] == "HIGH" for finding in data)
    assert all("var_name" in finding for finding in data)
    assert all("reason" in finding for finding in data)
    assert all("rule_id" in finding for finding in data)


# Ensure MEDIUM severity filtering works in JSON mode
def test_cli_json_severity_medium_filter():
    result = run_cli("test_dirs", "--json", "--severity", "MEDIUM")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["severity"] == "MEDIUM" for finding in data)
    assert all("var_name" in finding for finding in data)
    assert all("reason" in finding for finding in data)
    assert all("rule_id" in finding for finding in data)


# Ensure HIGH severity filtering works in text mode
def test_cli_text_severity_high_filter():
    result = run_cli("test_dirs", "--severity", "HIGH")

    assert result.returncode == 0

    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" not in result.stdout
    assert "Reason:" in result.stdout


# Ensure MEDIUM severity filtering works in text mode
def test_cli_text_severity_medium_filter():
    result = run_cli("test_dirs", "--severity", "MEDIUM")

    assert result.returncode == 0

    assert "[MEDIUM]" in result.stdout
    assert "[HIGH]" not in result.stdout
    assert "Reason:" in result.stdout


# Ensure JSON output and severity filtering work together
def test_cli_json_and_severity_combined():
    result = run_cli("test_dirs", "--json", "--severity", "HIGH")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["severity"] == "HIGH" for finding in data)
    assert all("var_name" in finding for finding in data)
    assert all("reason" in finding for finding in data)
    assert all("rule_id" in finding for finding in data)


# Ensure invalid severity values are rejected by argparse
def test_cli_invalid_severity_fails():
    result = run_cli("test_dirs", "--severity", "CRITICAL")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


# Ensure invalid paths are handled gracefully
def test_cli_invalid_path_prints_error():
    result = run_cli("does_not_exist")

    assert "[ERROR]" in result.stdout or "[ERROR]" in result.stderr


# Ensure benign Python files produce no findings in text mode
def test_cli_no_findings_text_output(tmp_path):
    benign_file = tmp_path / "safe.py"
    benign_file.write_text('username = "notsecret"\n', encoding="utf-8")

    result = run_cli(str(tmp_path))

    assert result.returncode == 0

    assert "No vulnerabilities found." in result.stdout
    assert "Reason:" not in result.stdout


# Ensure benign Python files produce an empty JSON list
def test_cli_no_findings_json_output(tmp_path):
    benign_file = tmp_path / "safe.py"
    benign_file.write_text('username = "notsecret"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == []


# Ensure CLI can scan temporary directories, not just checked-in fixtures
def test_cli_detects_secret_in_temp_directory(tmp_path):
    vulnerable_file = tmp_path / "vulnerable.py"
    vulnerable_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(vulnerable_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "abcdef",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure JSON output can be parsed after severity filtering removes all findings
def test_cli_json_filter_with_no_matching_findings(tmp_path):
    medium_file = tmp_path / "medium.py"
    medium_file.write_text('token = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--severity", "HIGH")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == []


# Ensure text output handles severity filters with no matching findings
def test_cli_text_filter_with_no_matching_findings(tmp_path):
    medium_file = tmp_path / "medium.py"
    medium_file.write_text('token = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--severity", "HIGH")

    assert result.returncode == 0

    assert "No vulnerabilities found." in result.stdout
    assert "Reason:" not in result.stdout


# Ensure JSON output preserves rule metadata for token findings
def test_cli_json_token_finding_includes_rule_id_and_reason(tmp_path):
    token_file = tmp_path / "token_file.py"
    token_file.write_text('token = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(token_file),
            "var_name": "token",
            "rule_id": "TOKEN",
            "rule": "Token",
            "severity": "MEDIUM",
            "value": "abcdef",
            "reason": TOKEN_REASON,
        }
    ]


# Ensure JSON severity filtering preserves full finding schema
def test_cli_json_severity_filter_preserves_schema(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--severity", "HIGH")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(password_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "abcdef",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure normal text output shows original values when --redact is not used
def test_cli_text_output_is_unredacted_by_default(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path))

    assert result.returncode == 0

    assert "abcdef" in result.stdout
    assert "a****f" not in result.stdout
    assert "[REDACTED]" not in result.stdout


# Ensure text output redacts detected values when --redact is used
def test_cli_text_redact_masks_secret_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--redact")

    assert result.returncode == 0

    assert "a****f" in result.stdout
    assert "abcdef" not in result.stdout
    assert "Reason:" in result.stdout
    assert "Password" in result.stdout


# Ensure JSON output shows original values when --redact is not used
def test_cli_json_output_is_unredacted_by_default(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(password_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "abcdef",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure JSON output redacts values when --redact is used
def test_cli_json_redact_masks_secret_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(password_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "a****f",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure JSON redaction keeps output machine-readable and pure JSON
def test_cli_json_redact_output_is_pure_json(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

    assert "Scanning" not in result.stdout
    assert "--- Findings ---" not in result.stdout
    assert "Total findings" not in result.stdout
    assert "Reason:" not in result.stdout

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert data[0]["value"] == "a****f"


# Ensure --json, --severity, and --redact work together
def test_cli_json_severity_and_redact_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "qwerty123"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--severity", "HIGH", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(findings_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "a****f",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure text severity filtering and redaction work together
def test_cli_text_severity_and_redact_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "qwerty123"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--severity", "HIGH", "--redact")

    assert result.returncode == 0

    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" not in result.stdout
    assert "a****f" in result.stdout
    assert "abcdef" not in result.stdout
    assert "qwerty123" not in result.stdout


# Ensure short detected values are fully redacted
def test_cli_json_redact_short_boundary_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcd"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(password_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "[REDACTED]",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure longer detected values preserve only limited prefix/suffix context
def test_cli_json_redact_long_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abc_def-123#$%^&*()"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(password_file),
            "var_name": "password",
            "rule_id": "PASSWORD",
            "rule": "Password",
            "severity": "HIGH",
            "value": "ab***************()",
            "reason": PASSWORD_REASON,
        }
    ]


# Ensure AWS access key values are redacted in JSON output
def test_cli_json_redact_aws_access_key(tmp_path):
    aws_file = tmp_path / "aws_file.py"
    aws_file.write_text(
        'random_var = "AKIAEXAMPLE123456789"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == [
        {
            "line": 1,
            "file": str(aws_file),
            "var_name": "random_var",
            "rule_id": "AWS_ACCESS_KEY",
            "rule": "AWS Access Key",
            "severity": "HIGH",
            "value": "AK****************89",
            "reason": AWS_REASON,
        }
    ]


# Ensure no-finding JSON output remains an empty list even with --redact
def test_cli_no_findings_json_with_redact(tmp_path):
    benign_file = tmp_path / "safe.py"
    benign_file.write_text('username = "notsecret"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == []


# Ensure no-finding text output does not print redaction artifacts
def test_cli_no_findings_text_with_redact(tmp_path):
    benign_file = tmp_path / "safe.py"
    benign_file.write_text('username = "notsecret"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--redact")

    assert result.returncode == 0

    assert "No vulnerabilities found." in result.stdout
    assert "[REDACTED]" not in result.stdout
    assert "Reason:" not in result.stdout
