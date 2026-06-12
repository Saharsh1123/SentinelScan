from tests.helpers import (
    AWS_REASON,
    PASSWORD_REASON,
    TOKEN_REASON,
    assert_entropy_metadata,
    assert_pure_json_output,
    assert_single_json_finding,
    assert_success,
    make_combined_filter_fixture,
    parse_json_output,
    run_cli,
    write_python_file,
)


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

    result = run_cli(tmp_path, "--format", "json")
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

    result = run_cli(tmp_path, "--format", "json", "--redact")
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

    result = run_cli(tmp_path, "--format", "json", "--redact")
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

    result = run_cli(tmp_path, "--format", "json", "--redact")
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

    result = run_cli(tmp_path, "--format", "json", "--redact")
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

    result = run_cli(tmp_path, "--format", "json", "--redact")
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
        'password = "abcdef"\n' 'api_token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--format", "json", "--confidence", "HIGH", "--redact")
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
        'password = "abcdef"\n' 'api_token = "abc1234567890j"\n',
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
        "--format",
        "json",
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

    result = run_cli(tmp_path, "--format", "json", "--redact")
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
