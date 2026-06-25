"""CLI exit-code contract tests."""

import main as main_module
from exit_codes import ExitCode
from tests.helpers import parse_json_output, run_cli, write_python_file


def test_cli_returns_success_for_clean_scan(tmp_path):
    """A completed scan with no findings should return exit code 0."""
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path, "--format", "json")

    assert result.returncode == ExitCode.SUCCESS
    assert parse_json_output(result) == []
    assert result.stderr == ""


def test_cli_returns_findings_and_preserves_json_report(tmp_path):
    """Policy-relevant findings should return 1 without corrupting stdout."""
    write_python_file(tmp_path, "vulnerable.py", 'password = "abcdef"\n')

    result = run_cli(tmp_path, "--format", "json")

    assert result.returncode == ExitCode.FINDINGS
    assert len(parse_json_output(result)) == 1
    assert result.stderr == ""


def test_main_returns_internal_error_for_unexpected_exception(monkeypatch, capsys):
    """Unexpected failures should be mapped to exit code 3 and stderr."""

    def raise_unexpected_error():
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(main_module, "return_args", raise_unexpected_error)

    exit_code = main_module.main()
    captured = capsys.readouterr()

    assert exit_code == ExitCode.INTERNAL_ERROR
    assert captured.out == ""
    assert "[INTERNAL ERROR] simulated failure" in captured.err
    assert "Traceback" not in captured.err
