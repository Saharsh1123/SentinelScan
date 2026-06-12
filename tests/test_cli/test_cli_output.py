from tests.helpers import (
    PASSWORD_REASON,
    SUPPORTED_CONFIDENCE,
    SUPPORTED_SEVERITY,
    assert_entropy_metadata,
    assert_pure_json_output,
    assert_single_json_finding,
    assert_success,
    get_entropy,
    parse_json_output,
    run_cli,
    write_python_file,
)


def test_cli_json_output_is_valid_json(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert isinstance(data, list)
    assert len(data) > 0


def test_cli_json_output_is_pure_json(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    assert_pure_json_output(result)

    data = parse_json_output(result)
    assert isinstance(data, list)


def test_cli_json_schema(tmp_path):
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--format", "json")
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

    result = run_cli(tmp_path, "--format", "json")
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

    result = run_cli(tmp_path, "--format", "json")
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
        value="abcdef",
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
