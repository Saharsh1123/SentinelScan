from types import SimpleNamespace

import pytest

from scanner import finding_has_inline_ignore, scan


PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"


def make_finding(rule_id="PASSWORD"):
    """
    Create a minimal finding-like object for inline-ignore helper tests.
    """
    return SimpleNamespace(rule_id=rule_id)


def write_python_file(root_path, relative_path, content):
    """
    Write a Python fixture file under a temporary test directory.
    """
    file_path = root_path / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    return file_path


# -------------------------
# Generic inline ignore helper behavior
# -------------------------


@pytest.mark.parametrize(
    "line",
    [
        'password = "abcdef"  # sentinelscan: ignore',
        'password = "abcdef" # sentinelscan: ignore',
        "    token = 'abcdef'  # sentinelscan: ignore",
    ],
)
def test_finding_has_inline_ignore_returns_true_for_generic_marker(line):
    finding = make_finding("PASSWORD")

    assert finding_has_inline_ignore(line, finding) is True


@pytest.mark.parametrize(
    "line",
    [
        'password = "abcdef"',
        'password = "abcdef"  # unrelated comment',
        'password = "abcdef"  # sentinel scan ignore',
        'password = "abcdef"  # sentinelscan ignore',
        'password = "abcdef"  # ignore',
    ],
)
def test_finding_has_inline_ignore_returns_false_without_valid_marker(line):
    finding = make_finding("PASSWORD")

    assert finding_has_inline_ignore(line, finding) is False


def test_finding_has_inline_ignore_does_not_match_marker_inside_string_literal():
    line = 'note = "sentinelscan: ignore"'
    finding = make_finding("PASSWORD")

    assert finding_has_inline_ignore(line, finding) is False


# -------------------------
# Rule-specific inline ignore helper behavior
# -------------------------


def test_rule_specific_inline_ignore_matches_same_rule_id():
    line = 'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY'
    finding = make_finding("AWS_ACCESS_KEY")

    assert finding_has_inline_ignore(line, finding) is True


def test_rule_specific_inline_ignore_does_not_match_different_rule_id():
    line = 'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY'
    finding = make_finding("API_KEY")

    assert finding_has_inline_ignore(line, finding) is False


def test_rule_specific_inline_ignore_supports_multiple_rule_ids():
    line = (
        'api_key = "AKIAEXAMPLE123456789"  '
        '# sentinelscan: ignore AWS_ACCESS_KEY API_KEY'
    )

    assert finding_has_inline_ignore(line, make_finding("AWS_ACCESS_KEY")) is True
    assert finding_has_inline_ignore(line, make_finding("API_KEY")) is True
    assert finding_has_inline_ignore(line, make_finding("PASSWORD")) is False


def test_rule_specific_inline_ignore_with_unknown_rule_id_does_not_suppress():
    line = 'password = "abcdef"  # sentinelscan: ignore FAKE_RULE'
    finding = make_finding("PASSWORD")

    assert finding_has_inline_ignore(line, finding) is False


def test_rule_specific_inline_ignore_inside_string_literal_does_not_suppress():
    line = 'password = "sentinelscan: ignore PASSWORD"'
    finding = make_finding("PASSWORD")

    assert finding_has_inline_ignore(line, finding) is False


def test_rule_specific_inline_ignore_is_case_sensitive_for_rule_ids():
    line = 'password = "abcdef"  # sentinelscan: ignore password'
    finding = make_finding("PASSWORD")

    assert finding_has_inline_ignore(line, finding) is False


# -------------------------
# Generic scanner-level inline ignore behavior
# -------------------------


def test_scan_suppresses_single_inline_ignored_finding(tmp_path):
    ignored_file = write_python_file(
        tmp_path,
        "ignored.py",
        'password = "abcdef"  # sentinelscan: ignore\n',
    )

    result = scan([ignored_file])

    assert result == []


def test_scan_keeps_finding_without_inline_ignore(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'password = "abcdef"\n',
    )

    result = scan([vulnerable_file])

    assert len(result) == 1

    finding = result[0]

    assert finding.file_path == str(vulnerable_file)
    assert finding.line_number == 1
    assert finding.var_name == "password"
    assert finding.value == "abcdef"
    assert finding.rule_id == "PASSWORD"
    assert finding.rule_name == "Password"
    assert finding.severity == "HIGH"
    assert finding.reason == PASSWORD_REASON
    assert finding.confidence == "LOW"


def test_scan_unrelated_comment_does_not_suppress_finding(tmp_path):
    vulnerable_file = write_python_file(
        tmp_path,
        "vulnerable.py",
        'password = "abcdef"  # this is a normal comment\n',
    )

    result = scan([vulnerable_file])

    assert len(result) == 1
    assert result[0].rule_id == "PASSWORD"
    assert result[0].value == "abcdef"


def test_scan_inline_ignore_only_suppresses_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore\n'
        'token = "abc1234567890j"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1

    finding = result[0]

    assert finding.line_number == 2
    assert finding.var_name == "token"
    assert finding.rule_id == "TOKEN"
    assert finding.value == "abc1234567890j"


def test_scan_inline_ignore_on_previous_line_does_not_suppress_next_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        "# sentinelscan: ignore\n"
        'password = "abcdef"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].line_number == 2
    assert result[0].rule_id == "PASSWORD"


def test_scan_inline_ignore_suppresses_multiple_findings_on_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore\n',
    )

    result = scan([findings_file])

    assert result == []


def test_scan_inline_ignore_suppresses_multiple_sensitive_targets_on_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = token = "abcdef"  # sentinelscan: ignore\n',
    )

    result = scan([findings_file])

    assert result == []


def test_scan_inline_ignore_in_string_literal_does_not_suppress_finding(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "sentinelscan: ignore"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].rule_id == "PASSWORD"
    assert result[0].value == "sentinelscan: ignore"


# -------------------------
# Rule-specific scanner-level inline ignore behavior
# -------------------------


def test_scan_rule_specific_ignore_suppresses_only_matching_rule(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].rule_id == "API_KEY"
    assert result[0].rule_name == "API Key"
    assert result[0].value == "AKIAEXAMPLE123456789"


def test_scan_rule_specific_ignore_can_suppress_api_key_but_keep_aws_match(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore API_KEY\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].rule_id == "AWS_ACCESS_KEY"
    assert result[0].rule_name == "AWS Access Key"
    assert result[0].value == "AKIAEXAMPLE123456789"


def test_scan_rule_specific_ignore_suppresses_multiple_listed_rules(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  '
        '# sentinelscan: ignore AWS_ACCESS_KEY API_KEY\n',
    )

    result = scan([findings_file])

    assert result == []


def test_scan_unknown_rule_specific_ignore_does_not_suppress_finding(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore FAKE_RULE\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].rule_id == "PASSWORD"
    assert result[0].value == "abcdef"


def test_scan_rule_specific_ignore_only_affects_same_line(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'password = "abcdef"  # sentinelscan: ignore PASSWORD\n'
        'token = "abc1234567890j"\n',
    )

    result = scan([findings_file])

    assert len(result) == 1
    assert result[0].line_number == 2
    assert result[0].rule_id == "TOKEN"
    assert result[0].value == "abc1234567890j"


def test_scan_rule_specific_ignore_preserves_remaining_finding_metadata(tmp_path):
    findings_file = write_python_file(
        tmp_path,
        "findings.py",
        'api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY\n',
    )

    result = scan([findings_file])

    assert len(result) == 1

    finding = result[0]

    assert finding.file_path == str(findings_file)
    assert finding.line_number == 1
    assert finding.var_name == "api_key"
    assert finding.rule_id == "API_KEY"
    assert finding.rule_name == "API Key"
    assert finding.severity == "HIGH"
    assert finding.confidence == "HIGH"
    assert finding.entropy >= 0