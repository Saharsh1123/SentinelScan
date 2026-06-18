"""CLI tests for safe-by-default secret rendering."""

from tests.helpers import (
    PASSWORD_REASON,
    assert_pure_json_output,
    assert_single_json_finding,
    assert_success,
    parse_json_output,
    run_cli,
    write_python_file,
)


def test_cli_text_redacts_secret_by_default(tmp_path):
    """Text output should mask secret values unless explicitly overridden."""
    write_python_file(tmp_path, "password_file.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path)
    assert_success(result)

    assert "a****f" in result.stdout
    assert "abcdef" not in result.stdout
    assert "Confidence:" in result.stdout
    assert "Reason:" in result.stdout


def test_cli_text_unsafe_show_secrets_displays_plaintext(tmp_path):
    """The unsafe flag should deliberately expose plaintext in text output."""
    write_python_file(tmp_path, "password_file.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--unsafe-show-secrets")
    assert_success(result)

    assert "abcdef" in result.stdout
    assert "a****f" not in result.stdout


def test_cli_json_redacts_secret_by_default(tmp_path):
    """JSON output should use the same safe default as text output."""
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
        value="a****f",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_cli_json_unsafe_show_secrets_displays_plaintext_and_remains_pure_json(
    tmp_path,
):
    """Unsafe JSON output should expose values without adding non-JSON text."""
    password_file = write_python_file(
        tmp_path,
        "password_file.py",
        'password = "abcdef"\n',
    )

    result = run_cli(
        tmp_path,
        "--format",
        "json",
        "--unsafe-show-secrets",
    )
    assert_success(result)
    assert_pure_json_output(result)

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
