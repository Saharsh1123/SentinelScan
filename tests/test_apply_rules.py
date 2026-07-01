import re

import pytest

from detectors.models import Candidate, Rule
from detectors.rule_engine import apply_rules

PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
API_KEY_REASON = (
    "variable name matched api_key/apikey pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"
SECRET_REASON = "variable name matched secret pattern and value met minimum length"
AWS_REASON = "value matched AKIA-prefixed AWS access key pattern"

SUPPORTED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


def make_candidate(var_name, value, line_number=1):
    return Candidate(
        line_number=line_number,
        var_name=var_name,
        value=value,
    )


def get_entropy(finding):
    """
    Return the entropy field from a Finding.

    Supports either `entropy` or `entropy_score` if the field name changes
    during refactoring.
    """
    if hasattr(finding, "entropy"):
        return finding.entropy

    if hasattr(finding, "entropy_score"):
        return finding.entropy_score

    raise AssertionError("Finding is missing entropy metadata")


def assert_entropy_metadata(finding):
    entropy = get_entropy(finding)

    assert isinstance(entropy, int | float)
    assert entropy >= 0


def assert_finding(
    finding,
    *,
    line_number=1,
    file_path=None,
    var_name,
    value,
    rule_id,
    rule_name,
    severity,
    reason,
    confidence=None,
):
    assert finding.file_path == file_path
    assert finding.line_number == line_number
    assert finding.var_name == var_name
    assert finding.value == value
    assert finding.rule_id == rule_id
    assert finding.rule_name == rule_name
    assert finding.severity == severity
    assert finding.reason == reason

    if confidence is None:
        assert finding.confidence in SUPPORTED_CONFIDENCE
    else:
        assert finding.confidence == confidence

    assert_entropy_metadata(finding)


def assert_single_finding(result, **expected):
    assert len(result) == 1
    assert_finding(result[0], **expected)


# Detect password variable with valid value length
def test_password_match():
    candidate = make_candidate("password", "abcdef")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


# Detect password alias: pwd
def test_pwd_alias_match():
    candidate = make_candidate("pwd", "abcdef")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="pwd",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


# Detect password alias: passwd
def test_passwd_alias_match():
    candidate = make_candidate("passwd", "abcdef")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="passwd",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_rule_emits_once_when_multiple_var_patterns_match():
    candidate = make_candidate(
        "password_pwd",
        "not-a-placeholder-secret",
    )

    result = apply_rules(candidate)

    assert [finding.rule_id for finding in result] == ["PASSWORD"]


def test_rule_emits_once_when_value_and_var_patterns_match(monkeypatch):
    combined_rule = Rule(
        rule_id="COMBINED",
        rule_name="Combined",
        severity="HIGH",
        reason="matched combined test rule",
        var_patterns=[re.compile(r"token", re.IGNORECASE)],
        value_pattern=re.compile(r"COMBINED-[A-Z0-9]+"),
        min_length=4,
    )

    monkeypatch.setattr(
        "detectors.rule_engine.RULES",
        [combined_rule],
    )

    candidate = make_candidate(
        "token",
        "COMBINED-ABC123",
    )

    result = apply_rules(candidate)

    assert len(result) == 1
    assert result[0].rule_id == "COMBINED"
    assert result[0].confidence == "HIGH"


@pytest.mark.parametrize(
    "var_name",
    [
        "not_password",
        "password_not_set",
        "missing_access_token",
        "token_value_unset",
        "NoApiKey",
    ],
)
def test_explicit_absence_context_suppresses_name_match(var_name):
    candidate = make_candidate(var_name, "K9m2Q7v4L8x1P6r3")

    result = apply_rules(candidate)

    assert result == []


@pytest.mark.parametrize(
    ("var_name", "rule_id"),
    [
        ("notification_password", "PASSWORD"),
        ("password_not_rotated", "PASSWORD"),
        ("not_rotated_access_token", "TOKEN"),
        ("not_password_real_password", "PASSWORD"),
    ],
)
def test_non_absence_context_still_reports(var_name, rule_id):
    candidate = make_candidate(var_name, "K9m2Q7v4L8x1P6r3")

    result = apply_rules(candidate)

    assert [finding.rule_id for finding in result] == [rule_id]


def test_low_confidence_name_context_does_not_suppress():
    candidate = make_candidate("test_password", "K9m2Q7v4L8x1P6r3")

    result = apply_rules(candidate)

    assert len(result) == 1
    assert result[0].rule_id == "PASSWORD"
    assert result[0].confidence == "LOW"


def test_value_pattern_match_is_not_suppressed_by_name_context():
    candidate = make_candidate("not_api_key", "AKIAEXAMPLE123456789")

    result = apply_rules(candidate)

    assert [finding.rule_id for finding in result] == ["AWS_ACCESS_KEY"]


# Ensure similar but unrelated variable names are not flagged
def test_no_match():
    candidate = make_candidate("username", "abcdef")
    result = apply_rules(candidate)

    assert result == []


# Ensure values below minimum length threshold are ignored
def test_short_password_value():
    candidate = make_candidate("password", "abc")
    result = apply_rules(candidate)

    assert result == []


# Ensure values exactly at minimum length are accepted
def test_min_length_boundary_match():
    candidate = make_candidate("password", "abcd")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="password",
        value="abcd",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


# Ensure case-insensitive variable matching
def test_uppercase_variable_match():
    candidate = make_candidate("PASSWORD", "abcdef")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="PASSWORD",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


# Detect API key variable with underscore
def test_api_key_match():
    candidate = make_candidate("api_key", "1234abcd")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="api_key",
        value="1234abcd",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
    )


# Detect API key variable without underscore
def test_apikey_match():
    candidate = make_candidate("apikey", "1234abcd")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="apikey",
        value="1234abcd",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
    )


# Detect token with MEDIUM severity
def test_token_match():
    candidate = make_candidate("token", "qwerty")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="token",
        value="qwerty",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="LOW",
    )


# Detect secret with MEDIUM severity
def test_secret_match():
    candidate = make_candidate("secret", "abcdef")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="secret",
        value="abcdef",
        rule_id="SECRET",
        rule_name="Secret",
        severity="MEDIUM",
        reason=SECRET_REASON,
        confidence="LOW",
    )


# Detect secret when embedded in a longer variable name
def test_secret_embedded_variable_match():
    candidate = make_candidate("client_secret", "abcdef")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="client_secret",
        value="abcdef",
        rule_id="SECRET",
        rule_name="Secret",
        severity="MEDIUM",
        reason=SECRET_REASON,
        confidence="LOW",
    )


# Detect AWS access key by value, regardless of variable name
def test_aws_access_key_value_match():
    candidate = make_candidate("random_var", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="random_var",
        value="AKIAEXAMPLE123456789",
        rule_id="AWS_ACCESS_KEY",
        rule_name="AWS Access Key",
        severity="HIGH",
        reason=AWS_REASON,
        confidence="HIGH",
    )


# Ensure AWS value-pattern matches force HIGH confidence
def test_aws_access_key_confidence_is_high():
    candidate = make_candidate("random_var", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert result[0].rule_id == "AWS_ACCESS_KEY"
    assert result[0].confidence == "HIGH"


# Ensure lowercase AWS-style value does not match case-sensitive AWS pattern
def test_lowercase_aws_access_key_no_match():
    candidate = make_candidate("random_var", "akiaexample123456789")
    result = apply_rules(candidate)

    assert result == []


# Ensure malformed AWS-style value does not match
def test_malformed_aws_access_key_no_match():
    candidate = make_candidate("random_var", "AKIA123")
    result = apply_rules(candidate)

    assert result == []


# Ensure AWS access key can produce multiple classifications when variable also matches
def test_aws_access_key_with_api_key_variable():
    candidate = make_candidate("api_key", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert len(result) == 2

    assert_finding(
        result[0],
        var_name="api_key",
        value="AKIAEXAMPLE123456789",
        rule_id="AWS_ACCESS_KEY",
        rule_name="AWS Access Key",
        severity="HIGH",
        reason=AWS_REASON,
        confidence="HIGH",
    )

    assert_finding(
        result[1],
        var_name="api_key",
        value="AKIAEXAMPLE123456789",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
        confidence="HIGH",
    )


# Ensure multiple matching rules preserve rule order
def test_multiple_matches_preserve_rule_order():
    candidate = make_candidate("api_key", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert [finding.rule_id for finding in result] == [
        "AWS_ACCESS_KEY",
        "API_KEY",
    ]


# Ensure complex values with special characters are preserved
def test_complex_password_value_match():
    candidate = make_candidate("password", "abc_def-123#$%^&*()")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="password",
        value="abc_def-123#$%^&*()",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="HIGH",
    )


# Ensure empty variable name does not trigger variable-based rules
def test_empty_variable_name():
    candidate = make_candidate("", "abcdef")
    result = apply_rules(candidate)

    assert result == []


# Ensure empty value does not trigger length-based rules
def test_empty_value():
    candidate = make_candidate("password", "")
    result = apply_rules(candidate)

    assert result == []


# Ensure candidate line number is preserved in findings
def test_candidate_line_number_is_preserved():
    candidate = make_candidate("password", "abcdef", line_number=42)
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        line_number=42,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


# Ensure low-entropy password-like values receive LOW confidence
def test_low_entropy_value_gets_low_confidence():
    candidate = make_candidate("password", "aaaaaaaaaaaa")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="password",
        value="aaaaaaaaaaaa",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


# Ensure medium-randomness values receive MEDIUM confidence
def test_medium_entropy_value_gets_medium_confidence():
    candidate = make_candidate("token", "xyzttttggfdddf")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="token",
        value="xyzttttggfdddf",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="MEDIUM",
    )


# Ensure high-randomness long values receive HIGH confidence
def test_high_entropy_value_gets_high_confidence():
    candidate = make_candidate("token", "abc1234567890j")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="token",
        value="abc1234567890j",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


# Ensure repetitive token-looking values are not treated as high confidence
def test_repetitive_token_value_not_high_confidence():
    candidate = make_candidate("token", "xyzttttggfdddf")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="token",
        value="xyzttttggfdddf",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="MEDIUM",
    )


# Ensure API key rule can produce LOW confidence for repetitive test-looking values
def test_api_key_repetitive_value_low_confidence():
    candidate = make_candidate("api_key", "12dwdqwdqwdqw3")
    result = apply_rules(candidate)

    assert_single_finding(
        result,
        var_name="api_key",
        value="12dwdqwdqwdqw3",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
        confidence="LOW",
    )


# Ensure all returned findings include supported confidence labels
def test_all_findings_use_supported_confidence_labels():
    candidate = make_candidate("api_key", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert result
    assert all(finding.confidence in SUPPORTED_CONFIDENCE for finding in result)


# Ensure all returned findings include entropy metadata
def test_all_findings_include_entropy_metadata():
    candidate = make_candidate("api_key", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert result
    assert all(get_entropy(finding) >= 0 for finding in result)


# Ensure all finding metadata is populated for a normal match
def test_finding_metadata_is_populated():
    candidate = make_candidate("password", "abcdef")
    result = apply_rules(candidate)

    finding = result[0]

    assert_finding(
        finding,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )
