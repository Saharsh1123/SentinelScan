import pytest

from tests.helpers import (
    AWS_REASON,
    PASSWORD_REASON,
    TOKEN_REASON,
    assert_single_json_finding,
    assert_success,
    get_entropy,
    make_combined_filter_fixture,
    make_confidence_fixture,
    make_severity_fixture,
    parse_json_output,
    run_cli,
    write_python_file,
)


@pytest.mark.parametrize("severity", ["HIGH", "MEDIUM"])
def test_cli_json_severity_filter_keeps_only_matching_severity(tmp_path, severity):
    make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--format", "json", "--severity", severity)
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["severity"] == severity for finding in data)
    assert all("confidence" in finding for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


def test_cli_json_severity_high_filter_exact_result(tmp_path):
    findings_file = make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--format", "json", "--severity", "HIGH")
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

    result = run_cli(tmp_path, "--format", "json", "--severity", "MEDIUM")
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

    result = run_cli(tmp_path, "--format", "json", "--severity", "HIGH")
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


@pytest.mark.parametrize("confidence", ["LOW", "MEDIUM", "HIGH"])
def test_cli_json_confidence_filter_keeps_only_matching_confidence(
    tmp_path,
    confidence,
):
    make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--format", "json", "--confidence", confidence)
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) > 0
    assert all(finding["confidence"] == confidence for finding in data)
    assert all(get_entropy(finding) >= 0 for finding in data)


def test_cli_json_confidence_low_filter_exact_result(tmp_path):
    findings_file = make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--format", "json", "--confidence", "LOW")
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

    result = run_cli(tmp_path, "--format", "json", "--confidence", "MEDIUM")
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

    result = run_cli(tmp_path, "--format", "json", "--confidence", "HIGH")
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

    result = run_cli(tmp_path, "--format", "json", "--confidence", "HIGH")
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


def test_cli_json_severity_and_confidence_combined(tmp_path):
    findings_file = make_combined_filter_fixture(tmp_path)

    result = run_cli(
        tmp_path,
        "--format",
        "json",
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
        'password = "abcdef"\n' 'token = "abc1234567890j"\n',
    )

    result = run_cli(
        tmp_path,
        "--format",
        "json",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_multiple_severity_levels_include_exact_matches(tmp_path):
    """
    Multiple severity selections should include only those exact levels.
    """
    make_severity_fixture(tmp_path)

    result = run_cli(tmp_path, "--format", "json", "--severity", "HIGH", "MEDIUM")
    assert_success(result)

    data = parse_json_output(result)

    assert {finding["severity"] for finding in data} == {"HIGH", "MEDIUM"}
    assert all(finding["severity"] in {"HIGH", "MEDIUM"} for finding in data)


def test_cli_json_multiple_confidence_levels_include_exact_matches(tmp_path):
    """
    Multiple confidence selections should include only those exact levels.
    """
    make_confidence_fixture(tmp_path)

    result = run_cli(tmp_path, "--format", "json", "--confidence", "LOW", "HIGH")
    assert_success(result)

    data = parse_json_output(result)

    assert {finding["confidence"] for finding in data} == {"LOW", "HIGH"}
    assert all(finding["confidence"] in {"LOW", "HIGH"} for finding in data)
