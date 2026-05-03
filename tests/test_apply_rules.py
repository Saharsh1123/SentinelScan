from detectors.models import Candidate, Finding
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


def make_candidate(var_name, value, line_number=1):
    return Candidate(
        line_number=line_number,
        var_name=var_name,
        value=value,
    )


# Detect password variable with valid value length
def test_password_match():
    candidate = make_candidate("password", "abcdef")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="password",
            value="abcdef",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]


# Detect password alias: pwd
def test_pwd_alias_match():
    candidate = make_candidate("pwd", "abcdef")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="pwd",
            value="abcdef",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]


# Detect password alias: passwd
def test_passwd_alias_match():
    candidate = make_candidate("passwd", "abcdef")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="passwd",
            value="abcdef",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]


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

    assert result == [
        Finding(
            line_number=1,
            var_name="password",
            value="abcd",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]


# Ensure case-insensitive variable matching
def test_uppercase_variable_match():
    candidate = make_candidate("PASSWORD", "abcdef")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="PASSWORD",
            value="abcdef",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]


# Detect API key variable with underscore
def test_api_key_match():
    candidate = make_candidate("api_key", "1234abcd")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="api_key",
            value="1234abcd",
            rule_id="API_KEY",
            rule_name="API Key",
            severity="HIGH",
            reason=API_KEY_REASON,
        )
    ]


# Detect API key variable without underscore
def test_apikey_match():
    candidate = make_candidate("apikey", "1234abcd")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="apikey",
            value="1234abcd",
            rule_id="API_KEY",
            rule_name="API Key",
            severity="HIGH",
            reason=API_KEY_REASON,
        )
    ]


# Detect token with MEDIUM severity
def test_token_match():
    candidate = make_candidate("token", "qwerty")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="token",
            value="qwerty",
            rule_id="TOKEN",
            rule_name="Token",
            severity="MEDIUM",
            reason=TOKEN_REASON,
        )
    ]


# Detect secret with MEDIUM severity
def test_secret_match():
    candidate = make_candidate("secret", "abcdef")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="secret",
            value="abcdef",
            rule_id="SECRET",
            rule_name="Secret",
            severity="MEDIUM",
            reason=SECRET_REASON,
        )
    ]


# Detect secret when embedded in a longer variable name
def test_secret_embedded_variable_match():
    candidate = make_candidate("client_secret", "abcdef")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="client_secret",
            value="abcdef",
            rule_id="SECRET",
            rule_name="Secret",
            severity="MEDIUM",
            reason=SECRET_REASON,
        )
    ]


# Detect AWS access key by value, regardless of variable name
def test_aws_access_key_value_match():
    candidate = make_candidate("random_var", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="random_var",
            value="AKIAEXAMPLE123456789",
            rule_id="AWS_ACCESS_KEY",
            rule_name="AWS Access Key",
            severity="HIGH",
            reason=AWS_REASON,
        )
    ]


# Ensure lowercase AWS-style value does not match case-sensitive AWS pattern
def test_lowercase_aws_access_key_no_match():
    candidate = make_candidate("random_var", "akiaexample123456789")
    result = apply_rules(candidate)

    assert result == []


# Ensure AWS access key can produce multiple classifications when variable also matches
def test_aws_access_key_with_api_key_variable():
    candidate = make_candidate("api_key", "AKIAEXAMPLE123456789")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="api_key",
            value="AKIAEXAMPLE123456789",
            rule_id="AWS_ACCESS_KEY",
            rule_name="AWS Access Key",
            severity="HIGH",
            reason=AWS_REASON,
        ),
        Finding(
            line_number=1,
            var_name="api_key",
            value="AKIAEXAMPLE123456789",
            rule_id="API_KEY",
            rule_name="API Key",
            severity="HIGH",
            reason=API_KEY_REASON,
        ),
    ]


# Ensure complex values with special characters are preserved
def test_complex_password_value_match():
    candidate = make_candidate("password", "abc_def-123#$%^&*()")
    result = apply_rules(candidate)

    assert result == [
        Finding(
            line_number=1,
            var_name="password",
            value="abc_def-123#$%^&*()",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]


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

    assert result == [
        Finding(
            line_number=42,
            var_name="password",
            value="abcdef",
            rule_id="PASSWORD",
            rule_name="Password",
            severity="HIGH",
            reason=PASSWORD_REASON,
        )
    ]
