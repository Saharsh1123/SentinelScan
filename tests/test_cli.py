import json
import subprocess
import sys


PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"
AWS_REASON = "value matched AKIA-prefixed AWS access key pattern"

SUPPORTED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


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
    assert len(data) == 1
    assert_json_finding(data[0], **expected)


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
        "confidence",
    }

    for finding in data:
        assert required_keys.issubset(finding.keys())
        assert "entropy" in finding or "entropy_score" in finding


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
        assert isinstance(finding["confidence"], str)
        assert_entropy_metadata(finding)


# Ensure JSON confidence values use supported labels
def test_cli_json_confidence_values_are_supported():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["confidence"] in SUPPORTED_CONFIDENCE for finding in data)


# Ensure JSON entropy values are numeric and non-negative
def test_cli_json_entropy_values_are_numeric():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(get_entropy(finding) >= 0 for finding in data)


# Ensure JSON mode does not include human-readable CLI text
def test_cli_json_output_is_pure_json():
    result = run_cli("test_dirs", "--json")

    assert result.returncode == 0

    assert "Scanning" not in result.stdout
    assert "--- Findings ---" not in result.stdout
    assert "Total findings" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout
    assert "Entropy:" not in result.stdout

    data = parse_json_output(result)
    assert isinstance(data, list)


# Ensure normal CLI mode prints human-readable scan output
def test_cli_text_output_contains_expected_sections():
    result = run_cli("test_dirs")

    assert result.returncode == 0

    assert "Scanning" in result.stdout
    assert "--- Findings ---" in result.stdout
    assert "Total findings" in result.stdout


# Ensure normal CLI output contains finding details, confidence, and reasons
def test_cli_text_output_contains_finding_details():
    result = run_cli("test_dirs")

    assert result.returncode == 0

    assert "[HIGH]" in result.stdout
    assert "→" in result.stdout
    assert "Confidence:" in result.stdout
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
    assert all("confidence" in finding for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


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
    assert all("confidence" in finding for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


# Ensure HIGH severity filtering works in text mode
def test_cli_text_severity_high_filter():
    result = run_cli("test_dirs", "--severity", "HIGH")

    assert result.returncode == 0

    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


# Ensure MEDIUM severity filtering works in text mode
def test_cli_text_severity_medium_filter():
    result = run_cli("test_dirs", "--severity", "MEDIUM")

    assert result.returncode == 0

    assert "[MEDIUM]" in result.stdout
    assert "[HIGH]" not in result.stdout
    assert "Confidence:" in result.stdout
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
    assert all("confidence" in finding for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


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
    assert "Confidence:" not in result.stdout


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
    assert "Confidence:" not in result.stdout


# Ensure JSON output preserves rule metadata for token findings
def test_cli_json_token_finding_includes_rule_id_reason_and_confidence(tmp_path):
    token_file = tmp_path / "token_file.py"
    token_file.write_text('token = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=token_file,
        var_name="token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="abcdef",
        reason=TOKEN_REASON,
        confidence="LOW",
    )


# Ensure JSON severity filtering preserves full finding schema
def test_cli_json_severity_filter_preserves_schema(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--severity", "HIGH")

    assert result.returncode == 0

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


# Ensure normal text output shows original values when --redact is not used
def test_cli_text_output_is_unredacted_by_default(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path))

    assert result.returncode == 0

    assert "abcdef" in result.stdout
    assert "a****f" not in result.stdout
    assert "[REDACTED]" not in result.stdout
    assert "Confidence:" in result.stdout


# Ensure text output redacts detected values when --redact is used
def test_cli_text_redact_masks_secret_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--redact")

    assert result.returncode == 0

    assert "a****f" in result.stdout
    assert "abcdef" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout
    assert "Password" in result.stdout


# Ensure JSON output shows original values when --redact is not used
def test_cli_json_output_is_unredacted_by_default(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

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


# Ensure JSON output redacts values when --redact is used
def test_cli_json_redact_masks_secret_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

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
    assert "Confidence:" not in result.stdout

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert data[0]["value"] == "a****f"
    assert data[0]["confidence"] == "LOW"
    assert_entropy_metadata(data[0])


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

    assert_single_json_finding(
        data,
        line=1,
        file=findings_file,
        var_name="password",
        rule_id="PASSWORD",
        rule="Password",
        severity="HIGH",
        value="a****f",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


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
    assert "Confidence:" in result.stdout


# Ensure short detected values are fully redacted
def test_cli_json_redact_short_boundary_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abcd"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

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


# Ensure longer detected values preserve only limited prefix/suffix context
def test_cli_json_redact_long_value(tmp_path):
    password_file = tmp_path / "password_file.py"
    password_file.write_text('password = "abc_def-123#$%^&*()"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--redact")

    assert result.returncode == 0

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


# Ensure AWS access key confidence is HIGH in JSON output
def test_cli_json_aws_access_key_confidence_is_high(tmp_path):
    aws_file = tmp_path / "aws_file.py"
    aws_file.write_text(
        'random_var = "AKIAEXAMPLE123456789"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data[0]["rule_id"] == "AWS_ACCESS_KEY"
    assert data[0]["confidence"] == "HIGH"
    assert_entropy_metadata(data[0])


# Ensure high-randomness token values are HIGH confidence in JSON output
def test_cli_json_high_confidence_token(tmp_path):
    token_file = tmp_path / "token_file.py"
    token_file.write_text('token = "abc1234567890j"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=token_file,
        var_name="token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="abc1234567890j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


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
    assert "Confidence:" not in result.stdout


# Ensure LOW confidence filtering works in JSON mode
def test_cli_json_confidence_low_filter(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--confidence", "LOW")

    assert result.returncode == 0

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


# Ensure MEDIUM confidence filtering works in JSON mode
def test_cli_json_confidence_medium_filter(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--confidence", "MEDIUM")

    assert result.returncode == 0

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


# Ensure HIGH confidence filtering works in JSON mode
def test_cli_json_confidence_high_filter(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--confidence", "HIGH")

    assert result.returncode == 0

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


# Ensure confidence filtering keeps only matching confidence values in JSON
def test_cli_json_confidence_filter_keeps_only_matching_confidence(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--confidence", "HIGH")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["confidence"] == "HIGH" for finding in data)
    assert all(finding["confidence"] != "LOW" for finding in data)
    assert all(finding["confidence"] != "MEDIUM" for finding in data)


# Ensure LOW confidence filtering works in text mode
def test_cli_text_confidence_low_filter(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--confidence", "LOW")

    assert result.returncode == 0

    assert "abcdef" in result.stdout
    assert "xyzttttggfdddf" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


# Ensure MEDIUM confidence filtering works in text mode
def test_cli_text_confidence_medium_filter(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--confidence", "MEDIUM")

    assert result.returncode == 0

    assert "xyzttttggfdddf" in result.stdout
    assert "abcdef" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


# Ensure HIGH confidence filtering works in text mode
def test_cli_text_confidence_high_filter(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "xyzttttggfdddf"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--confidence", "HIGH")

    assert result.returncode == 0

    assert "abc1234567890j" in result.stdout
    assert "abcdef" not in result.stdout
    assert "xyzttttggfdddf" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


# Ensure severity and confidence filtering work together in JSON mode
def test_cli_json_severity_and_confidence_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "abc1234567890j"\n'
        'random_var = "AKIAEXAMPLE123456789"\n',
        encoding="utf-8",
    )

    result = run_cli(
        str(tmp_path),
        "--json",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )

    assert result.returncode == 0

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


# Ensure severity and confidence filtering can return no matches in JSON mode
def test_cli_json_severity_and_confidence_no_matches(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(
        str(tmp_path),
        "--json",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == []


# Ensure severity and confidence filtering work together in text mode
def test_cli_text_severity_and_confidence_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'token = "abc1234567890j"\n'
        'random_var = "AKIAEXAMPLE123456789"\n',
        encoding="utf-8",
    )

    result = run_cli(
        str(tmp_path),
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )

    assert result.returncode == 0

    assert "AWS Access Key" in result.stdout
    assert "AKIAEXAMPLE123456789" in result.stdout
    assert "abcdef" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


# Ensure confidence filtering works with redaction in JSON mode
def test_cli_json_confidence_and_redact_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--confidence", "HIGH", "--redact")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=2,
        file=findings_file,
        var_name="api_token",
        rule_id="TOKEN",
        rule="Token",
        severity="MEDIUM",
        value="ab***********0j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


# Ensure confidence filtering works with redaction in JSON mode
def test_cli_json_confidence_and_redact_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--json", "--confidence", "HIGH", "--redact")

    assert result.returncode == 0

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


# Ensure confidence filtering works with redaction in text mode
def test_cli_text_confidence_and_redact_combined(tmp_path):
    findings_file = tmp_path / "findings.py"
    findings_file.write_text(
        'password = "abcdef"\n'
        'api_token = "abc1234567890j"\n',
        encoding="utf-8",
    )

    result = run_cli(str(tmp_path), "--confidence", "HIGH", "--redact")

    assert result.returncode == 0

    assert "ab**********0j" in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "abcdef" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


# Ensure invalid confidence values are rejected by argparse
def test_cli_invalid_confidence_fails():
    result = run_cli("test_dirs", "--confidence", "VERY_HIGH")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr


# Ensure confidence filter with no matching findings returns empty JSON
def test_cli_json_confidence_filter_with_no_matching_findings(tmp_path):
    low_file = tmp_path / "low.py"
    low_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--json", "--confidence", "HIGH")

    assert result.returncode == 0

    data = parse_json_output(result)

    assert data == []


# Ensure confidence filter with no matching findings prints no findings in text mode
def test_cli_text_confidence_filter_with_no_matching_findings(tmp_path):
    low_file = tmp_path / "low.py"
    low_file.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(str(tmp_path), "--confidence", "HIGH")

    assert result.returncode == 0

    assert "No vulnerabilities found." in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout