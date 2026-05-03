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


# Detect password variable with valid value length
def test_password_match():
    result = apply_rules("password", "abcdef")
    assert result == [("Password", "HIGH", "abcdef", PASSWORD_REASON)]


# Detect password alias: pwd
def test_pwd_alias_match():
    result = apply_rules("pwd", "abcdef")
    assert result == [("Password", "HIGH", "abcdef", PASSWORD_REASON)]


# Detect password alias: passwd
def test_passwd_alias_match():
    result = apply_rules("passwd", "abcdef")
    assert result == [("Password", "HIGH", "abcdef", PASSWORD_REASON)]


# Ensure similar but unrelated variable names are not flagged
def test_no_match():
    result = apply_rules("username", "abcdef")
    assert result is None


# Ensure values below minimum length threshold are ignored
def test_short_password_value():
    result = apply_rules("password", "abc")
    assert result is None


# Ensure values exactly at minimum length are accepted
def test_min_length_boundary_match():
    result = apply_rules("password", "abcd")
    assert result == [("Password", "HIGH", "abcd", PASSWORD_REASON)]


# Ensure case-insensitive variable matching
def test_uppercase_variable_match():
    result = apply_rules("PASSWORD", "abcdef")
    assert result == [("Password", "HIGH", "abcdef", PASSWORD_REASON)]


# Detect API key variable with underscore
def test_api_key_match():
    result = apply_rules("api_key", "1234abcd")
    assert result == [("API Key", "HIGH", "1234abcd", API_KEY_REASON)]


# Detect API key variable without underscore
def test_apikey_match():
    result = apply_rules("apikey", "1234abcd")
    assert result == [("API Key", "HIGH", "1234abcd", API_KEY_REASON)]


# Detect token with medium severity
def test_token_match():
    result = apply_rules("token", "qwerty")
    assert result == [("Token", "MEDIUM", "qwerty", TOKEN_REASON)]


# Detect secret with medium severity
def test_secret_match():
    result = apply_rules("secret", "abcdef")
    assert result == [("Secret", "MEDIUM", "abcdef", SECRET_REASON)]


# Detect secret when embedded in a longer variable name
def test_secret_embedded_variable_match():
    result = apply_rules("client_secret", "abcdef")
    assert result == [("Secret", "MEDIUM", "abcdef", SECRET_REASON)]


# Detect AWS access key by value, regardless of variable name
def test_aws_access_key_value_match():
    result = apply_rules("random_var", "AKIAEXAMPLE123456789")
    assert result == [("AWS Access Key", "HIGH", "AKIAEXAMPLE123456789", AWS_REASON)]


# Ensure lowercase AWS-style value does not match case-sensitive AWS pattern
def test_lowercase_aws_access_key_no_match():
    result = apply_rules("random_var", "akiaexample123456789")
    assert result is None


# Ensure AWS access key can produce multiple classifications when variable also matches
def test_aws_access_key_with_api_key_variable():
    result = apply_rules("api_key", "AKIAEXAMPLE123456789")
    assert result == [
        ("AWS Access Key", "HIGH", "AKIAEXAMPLE123456789", AWS_REASON),
        ("API Key", "HIGH", "AKIAEXAMPLE123456789", API_KEY_REASON),
    ]


# Ensure complex values with special characters are preserved
def test_complex_password_value_match():
    result = apply_rules("password", "abc_def-123#$%^&*()")
    assert result == [
        ("Password", "HIGH", "abc_def-123#$%^&*()", PASSWORD_REASON)
    ]


# Ensure empty variable name does not trigger variable-based rules
def test_empty_variable_name():
    result = apply_rules("", "abcdef")
    assert result is None


# Ensure empty value does not trigger length-based rules
def test_empty_value():
    result = apply_rules("password", "")
    assert result is None
