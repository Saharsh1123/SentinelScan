import pytest

from exceptions import ExpectedUserError
from scanner import check_path, list_python_files, scan, scan_file
from tests.helpers import write_ignore_file, write_python_file


def test_check_path_rejects_nonexistent_path(tmp_path):
    """Missing scan paths should be classified as user-correctable errors."""
    missing_path = tmp_path / "does_not_exist"

    with pytest.raises(ExpectedUserError, match="does not exist or is not a directory"):
        check_path(missing_path)


def test_check_path_rejects_file_path(tmp_path):
    """Existing files should not be accepted as scan directories."""
    file_path = write_python_file(tmp_path, "not_a_directory.py", "pass\n")

    with pytest.raises(ExpectedUserError, match="does not exist or is not a directory"):
        check_path(file_path)


def test_list_python_files_returns_non_ignored_python_files_recursively(tmp_path):
    """File discovery should recurse into directories and apply ignore rules."""
    root_file = write_python_file(tmp_path, "root.py", "pass\n")
    nested_file = write_python_file(tmp_path, "src/nested.py", "pass\n")
    write_python_file(tmp_path, "ignored.py", 'password = "abcdef"\n')
    write_python_file(tmp_path, "ignored_dir/vulnerable.py", 'password = "abcdef"\n')
    (tmp_path / "notes.txt").write_text('password = "abcdef"\n', encoding="utf-8")
    write_ignore_file(tmp_path, "ignored.py\nignored_dir/\n")

    result = list_python_files(tmp_path)

    assert set(result) == {root_file, nested_file}


def test_scan_file_returns_findings_for_single_file(tmp_path):
    """
    scan_file should scan one Python file and return findings with file metadata attached.
    """
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n',
    )

    result = scan_file(findings_file)

    assert len(result) == 1

    finding = result[0]

    assert finding.file_path == str(findings_file)
    assert finding.line_number == 1
    assert finding.var_name == "password"
    assert finding.rule_id == "PASSWORD"
    assert finding.rule_name == "Password"
    assert finding.severity == "HIGH"
    assert finding.value == "abcdef"


def test_scan_file_respects_inline_ignore(tmp_path):
    """
    scan_file should suppress findings marked with sentinelscan inline ignore comments.
    """
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    result = scan_file(findings_file)

    assert len(result) == 1

    finding = result[0]

    assert finding.file_path == str(findings_file)
    assert finding.line_number == 2
    assert finding.var_name == "token"
    assert finding.rule_id == "TOKEN"
    assert finding.rule_name == "Token"
    assert finding.severity == "MEDIUM"
    assert finding.value == "abc1234567890j"


def test_scan_returns_flat_list_across_multiple_files(tmp_path):
    """
    scan should combine findings from multiple files into one flat list.

    This protects against accidentally returning a nested list like:
    [[finding1], [finding2]]
    """
    password_file = write_python_file(
        tmp_path,
        "password_file.py",
        'password = "abcdef"\n',
    )

    token_file = write_python_file(
        tmp_path,
        "token_file.py",
        'token = "abc1234567890j"\n',
    )

    result = scan([password_file, token_file])

    assert len(result) == 2
    assert all(not isinstance(item, list) for item in result)

    assert [finding.rule_id for finding in result] == ["PASSWORD", "TOKEN"]
    assert [finding.file_path for finding in result] == [
        str(password_file),
        str(token_file),
    ]


def test_scan_processes_files_in_sorted_path_order(tmp_path):
    """Scan results should be deterministic even when file input is unsorted."""
    later_file = write_python_file(
        tmp_path,
        "b_token.py",
        'token = "abc1234567890j"\n',
    )
    earlier_file = write_python_file(
        tmp_path,
        "a_password.py",
        'password = "abcdef"\n',
    )

    result = scan([later_file, earlier_file])

    assert [finding.file_path for finding in result] == [
        str(earlier_file),
        str(later_file),
    ]
    assert [finding.rule_id for finding in result] == ["PASSWORD", "TOKEN"]


def test_scan_returns_empty_list_when_no_files():
    """
    scan should return an empty list when given no files.
    """
    assert scan([]) == []
