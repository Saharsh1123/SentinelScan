import pytest

from exit_codes import ExitCode
from tests.helpers import run_cli


@pytest.mark.parametrize(
    ("args", "expected_error"),
    [
        (("--severity", "CRITICAL"), "invalid choice"),
        (("--confidence", "VERY_HIGH"), "invalid choice"),
    ],
)
def test_cli_invalid_choice_returns_invalid_usage(args, expected_error):
    result = run_cli(".", *args)

    assert result.returncode == ExitCode.INVALID_USAGE
    assert result.stdout == ""
    assert expected_error in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_nonexistent_path_returns_invalid_usage():
    result = run_cli("does_not_exist")

    assert result.returncode == ExitCode.INVALID_USAGE
    assert result.stdout == ""
    assert "[ERROR]" in result.stderr
    assert "does not exist or is not a directory" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_file_path_returns_invalid_usage(tmp_path):
    file_path = tmp_path / "not_a_directory.py"
    file_path.write_text('password = "abcdef"\n', encoding="utf-8")

    result = run_cli(file_path)

    assert result.returncode == ExitCode.INVALID_USAGE
    assert result.stdout == ""
    assert "[ERROR]" in result.stderr
    assert "does not exist or is not a directory" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_malformed_config_returns_invalid_usage(tmp_path):
    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text("{ invalid json", encoding="utf-8")

    result = run_cli(tmp_path)

    assert result.returncode == ExitCode.INVALID_USAGE
    assert result.stdout == ""
    assert "[ERROR] Invalid JSON in config" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_unknown_config_key_returns_invalid_usage(tmp_path):
    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text('{"severty_levels": ["HIGH"]}', encoding="utf-8")

    result = run_cli(tmp_path)

    assert result.returncode == ExitCode.INVALID_USAGE
    assert result.stdout == ""
    assert "[ERROR]" in result.stderr
    assert "unknown config keys" in result.stderr
    assert "severty_levels" in result.stderr
    assert "Traceback" not in result.stderr
