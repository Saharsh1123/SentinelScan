from tests.helpers import (
    AWS_REASON,
    PASSWORD_REASON,
    TOKEN_REASON,
    assert_single_json_finding,
    assert_success,
    parse_json_output,
    run_cli,
    write_ignore_file,
    write_python_file,
)


def test_cli_json_inline_ignore_suppresses_finding(tmp_path):
    write_python_file(
        tmp_path,
        "ignored.py",
        'password = "abcdef"  # sentinelscan: ignore\n',
    )

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_inline_ignore_keeps_non_ignored_findings(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--format", "json")
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


def test_cli_json_unrelated_comment_does_not_suppress_finding(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # normal comment\n',
    )

    result = run_cli(tmp_path, "--format", "json")
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


def test_cli_json_inline_ignore_suppresses_multiple_findings_on_same_line(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore\n',
    )

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_inline_ignore_works_with_severity_filter(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n'
        'random_var = "AKIAEXAMPLE123456789"\n',
    )

    result = run_cli(tmp_path, "--format", "json", "--severity", "HIGH")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=2,
        file=findings_file,
        var_name="random_var",
        rule_id="AWS_ACCESS_KEY",
        rule="AWS Access Key",
        severity="HIGH",
        value="AKIAEXAMPLE123456789",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_cli_json_inline_ignore_works_with_confidence_filter(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--format", "json", "--confidence", "HIGH")
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


def test_cli_json_inline_ignore_works_with_redaction(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--format", "json", "--redact")
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
        value="ab**********0j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_cli_json_inline_ignore_and_sentinelscanignore_work_together(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "src/findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )
    write_python_file(
        tmp_path,
        "ignored.py",
        'random_var = "AKIAEXAMPLE123456789"\n',
    )
    write_ignore_file(tmp_path, "ignored.py\n")

    result = run_cli(tmp_path, "--format", "json")
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


def test_cli_text_inline_ignore_suppresses_finding(tmp_path):
    write_python_file(
        tmp_path,
        "ignored.py",
        'password = "abcdef"  # sentinelscan: ignore\n',
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "abcdef" not in result.stdout
    assert "Reason:" not in result.stdout
    assert "Confidence:" not in result.stdout


def test_cli_text_inline_ignore_keeps_non_ignored_findings(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "password" not in result.stdout
    assert "abcdef" not in result.stdout
    assert "Token" in result.stdout
    assert "abc1234567890j" in result.stdout
    assert "Reason:" in result.stdout
    assert "Confidence:" in result.stdout


def test_cli_text_unrelated_comment_does_not_suppress_finding(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # normal comment\n',
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "[HIGH]" in result.stdout
    assert "Password" in result.stdout
    assert "abcdef" in result.stdout
    assert "Reason:" in result.stdout
    assert "Confidence:" in result.stdout


def test_cli_text_inline_ignore_suppresses_multiple_findings_on_same_line(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore\n',
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "AWS Access Key" not in result.stdout
    assert "API Key" not in result.stdout
    assert "AKIAEXAMPLE123456789" not in result.stdout


def test_cli_text_inline_ignore_works_with_redaction(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    result = run_cli(tmp_path, "--redact")
    assert_success(result)

    assert "abcdef" not in result.stdout
    assert "a****f" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "ab**********0j" in result.stdout
    assert "Token" in result.stdout


def test_cli_json_rule_specific_ignore_suppresses_only_matching_rule(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY\n',
    )

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=findings_file,
        var_name="api_key",
        rule_id="API_KEY",
        rule="API Key",
        severity="HIGH",
        value="AKIAEXAMPLE123456789",
        reason="variable name matched api_key/apikey pattern and value met minimum length",
        confidence="HIGH",
    )


def test_cli_json_rule_specific_ignore_can_keep_aws_match(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore API_KEY\n',
    )

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert_single_json_finding(
        data,
        line=1,
        file=findings_file,
        var_name="api_key",
        rule_id="AWS_ACCESS_KEY",
        rule="AWS Access Key",
        severity="HIGH",
        value="AKIAEXAMPLE123456789",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_cli_json_rule_specific_ignore_suppresses_multiple_listed_rules(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  '
        "# sentinelscan: ignore AWS_ACCESS_KEY API_KEY\n",
    )

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_unknown_rule_specific_ignore_does_not_suppress(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore FAKE_RULE\n',
    )

    result = run_cli(tmp_path, "--format", "json")
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


def test_cli_text_rule_specific_ignore_suppresses_only_matching_rule(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY\n',
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "API Key" in result.stdout
    assert "AWS Access Key" not in result.stdout
    assert "AKIAEXAMPLE123456789" in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_text_rule_specific_ignore_can_keep_aws_match(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore API_KEY\n',
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "AWS Access Key" in result.stdout
    assert "API Key" not in result.stdout
    assert "AKIAEXAMPLE123456789" in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_text_rule_specific_ignore_suppresses_multiple_listed_rules(tmp_path):
    write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  '
        "# sentinelscan: ignore AWS_ACCESS_KEY API_KEY\n",
    )

    result = run_cli(tmp_path)
    assert_success(result)

    assert "No vulnerabilities found." in result.stdout
    assert "AWS Access Key" not in result.stdout
    assert "API Key" not in result.stdout
    assert "AKIAEXAMPLE123456789" not in result.stdout


def test_cli_json_rule_specific_ignore_works_with_filters_and_redaction(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore PASSWORD\n'
        'token = "abc1234567890j"\n',
    )

    result = run_cli(
        tmp_path,
        "--format",
        "json",
        "--severity",
        "MEDIUM",
        "--confidence",
        "HIGH",
        "--redact",
    )
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
        value="ab**********0j",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )
