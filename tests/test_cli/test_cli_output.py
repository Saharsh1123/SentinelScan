from tests.helpers import (
    PASSWORD_REASON,
    assert_pure_json_output,
    assert_single_json_finding,
    assert_success,
    parse_json_output,
    run_cli,
    write_python_file,
)


def test_cli_json_output_is_pure_json(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    assert_pure_json_output(result)

    data = parse_json_output(result)
    assert isinstance(data, list)


def test_cli_json_detects_secret_in_temp_directory(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'password = "abcdef"\n',
    )

    result = run_cli(tmp_path, "--format", "json")
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
        value="a****f",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_no_findings_json_output(tmp_path):
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_empty_directory_json_output_is_empty_list(tmp_path):
    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


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
    assert "->" in result.stdout
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
