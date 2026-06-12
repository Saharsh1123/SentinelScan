from scanner import scan, scan_file
from tests.helpers import write_python_file


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


def test_scan_returns_empty_list_when_no_files():
    """
    scan should return an empty list when given no files.
    """
    assert scan([]) == []
