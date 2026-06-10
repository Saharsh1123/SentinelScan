from tests.helpers import (
    TOKEN_REASON,
    assert_single_json_finding,
    assert_success,
    parse_json_output,
    run_cli,
    write_ignore_file,
    write_python_file,
)


def test_cli_json_respects_sentinelscanignore_file(tmp_path):
    write_python_file(tmp_path, "ignored.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')
    write_ignore_file(tmp_path, "ignored.py\n")

    result = run_cli(tmp_path, "--format", "json")
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

    result = run_cli(tmp_path, "--format", "json")
    assert_success(result)

    data = parse_json_output(result)

    assert data == []


def test_cli_json_respects_ignore_glob_pattern(tmp_path):
    write_python_file(tmp_path, "bundle.min.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')
    write_ignore_file(tmp_path, "*.min.py\n")

    result = run_cli(tmp_path, "--format", "json")
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

    result = run_cli(tmp_path, "--format", "json")
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

    result = run_cli(project_dir, "--format", "json")
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