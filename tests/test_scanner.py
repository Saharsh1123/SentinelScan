import scanner
import pytest

from exceptions import ExpectedUserError
from scanner import check_path, list_python_files, scan, scan_file
from tests.helpers import (
    write_ignore_file,
    write_invalid_ascii_file,
    write_python_file,
)


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


def test_scan_file_returns_findings_and_no_skips_for_valid_file(tmp_path):
    """A readable valid file should return findings with its path attached."""
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"\n',
    )

    findings, skipped_files = scan_file(findings_file)

    assert skipped_files == []
    assert len(findings) == 1

    finding = findings[0]

    assert finding.file_path == str(findings_file)
    assert finding.line_number == 1
    assert finding.var_name == "password"
    assert finding.rule_id == "PASSWORD"
    assert finding.rule_name == "Password"
    assert finding.severity == "HIGH"
    assert finding.value == "abcdef"


def test_scan_file_respects_inline_ignore(tmp_path):
    """Inline suppression should still apply before findings are returned."""
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n' 'token = "abc1234567890j"\n',
    )

    findings, skipped_files = scan_file(findings_file)

    assert skipped_files == []
    assert len(findings) == 1

    finding = findings[0]

    assert finding.file_path == str(findings_file)
    assert finding.line_number == 2
    assert finding.var_name == "token"
    assert finding.rule_id == "TOKEN"
    assert finding.rule_name == "Token"
    assert finding.severity == "MEDIUM"
    assert finding.value == "abc1234567890j"


def test_scan_file_returns_structured_skip_for_invalid_python_syntax(tmp_path):
    """AST syntax failures should become path-enriched skipped-file records."""
    invalid_file = write_python_file(tmp_path, "invalid.py", 'password = "abc\n')

    findings, skipped_files = scan_file(invalid_file)

    assert findings == []
    assert len(skipped_files) == 1

    skipped_file = skipped_files[0]

    assert skipped_file.path == str(invalid_file)
    assert skipped_file.reason == "syntax_error"
    assert skipped_file.message.startswith("syntax error at 1:")


def test_scan_file_returns_structured_skip_for_invalid_encoding(tmp_path):
    """Python decoding failures should become encoding-error skip records."""
    invalid_file = write_invalid_ascii_file(tmp_path)

    findings, skipped_files = scan_file(invalid_file)

    assert findings == []
    assert len(skipped_files) == 1

    skipped_file = skipped_files[0]

    assert skipped_file.path == str(invalid_file)
    assert skipped_file.reason == "encoding_error"
    assert "ascii" in skipped_file.message


def test_scan_file_returns_structured_skip_for_os_error(tmp_path, monkeypatch):
    """Expected file-system read failures should not escape the scan boundary."""
    unreadable_file = write_python_file(tmp_path, "unreadable.py", "pass\n")

    def raise_os_error(_file):
        raise OSError("permission denied")

    monkeypatch.setattr(scanner.tokenize, "open", raise_os_error)

    findings, skipped_files = scan_file(unreadable_file)

    assert findings == []
    assert len(skipped_files) == 1

    skipped_file = skipped_files[0]

    assert skipped_file.path == str(unreadable_file)
    assert skipped_file.reason == "io_error"
    assert skipped_file.message == "permission denied"


def test_scan_returns_flat_findings_across_multiple_files(tmp_path):
    """Scan should aggregate findings into one flat, deterministic list."""
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

    findings, skipped_files = scan([password_file, token_file])

    assert skipped_files == []
    assert len(findings) == 2
    assert all(not isinstance(item, list) for item in findings)
    assert [finding.rule_id for finding in findings] == ["PASSWORD", "TOKEN"]
    assert [finding.file_path for finding in findings] == [
        str(password_file),
        str(token_file),
    ]


def test_scan_continues_after_bad_file_and_aggregates_both_channels(tmp_path):
    """One syntax-invalid file should not block findings from another file."""
    invalid_file = write_python_file(tmp_path, "a_invalid.py", 'password = "abc\n')
    vulnerable_file = write_python_file(
        tmp_path,
        "b_vulnerable.py",
        'password = "abcdef"\n',
    )

    findings, skipped_files = scan([vulnerable_file, invalid_file])

    assert [finding.file_path for finding in findings] == [str(vulnerable_file)]
    assert [finding.rule_id for finding in findings] == ["PASSWORD"]
    assert [skipped_file.path for skipped_file in skipped_files] == [str(invalid_file)]
    assert [skipped_file.reason for skipped_file in skipped_files] == ["syntax_error"]


def test_scan_processes_files_in_sorted_path_order(tmp_path):
    """Findings should be deterministic even when file input is unsorted."""
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

    findings, skipped_files = scan([later_file, earlier_file])

    assert skipped_files == []
    assert [finding.file_path for finding in findings] == [
        str(earlier_file),
        str(later_file),
    ]
    assert [finding.rule_id for finding in findings] == ["PASSWORD", "TOKEN"]


def test_scan_returns_two_empty_lists_when_no_files():
    """An empty scan should return empty finding and skipped-file channels."""
    assert scan([]) == ([], [])
