import pytest

from tests.helpers import run_cli


@pytest.mark.parametrize(
    ("args", "expected_error"),
    [
        (("--severity", "CRITICAL"), "invalid choice"),
        (("--confidence", "VERY_HIGH"), "invalid choice"),
    ],
)
def test_cli_invalid_choice_fails(args, expected_error):
    result = run_cli(".", *args)

    assert result.returncode != 0
    assert expected_error in result.stderr


def test_cli_invalid_path_prints_error():
    result = run_cli("does_not_exist")

    assert "[ERROR]" in result.stdout or "[ERROR]" in result.stderr
