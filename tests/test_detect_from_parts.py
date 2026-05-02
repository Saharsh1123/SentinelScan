from detectors.find_secrets import detect_from_parts


# Detect password variable with valid value length
def test_password_match():
    result = detect_from_parts("password", "abcdef")
    assert result == [("Password", "HIGH", "abcdef")]


# Detect password alias: pwd
def test_pwd_alias_match():
    result = detect_from_parts("pwd", "abcdef")
    assert result == [("Password", "HIGH", "abcdef")]


# Detect password alias: passwd
def test_passwd_alias_match():
    result = detect_from_parts("passwd", "abcdef")
    assert result == [("Password", "HIGH", "abcdef")]


# Ensure similar but unrelated variable names are not flagged
def test_no_match():
    result = detect_from_parts("username", "abcdef")
    assert result is None


# Ensure values below minimum length threshold are ignored
def test_short_password_value():
    result = detect_from_parts("password", "abc")
    assert result is None


# Ensure values exactly at minimum length are accepted
def test_min_length_boundary_match():
    result = detect_from_parts("password", "abcd")
    assert result == [("Password", "HIGH", "abcd")]


# Ensure case-insensitive variable matching
def test_uppercase_variable_match():
    result = detect_from_parts("PASSWORD", "abcdef")
    assert result == [("Password", "HIGH", "abcdef")]


# Detect API key variable with underscore
def test_api_key_match():
    result = detect_from_parts("api_key", "1234abcd")
    assert result == [("API Key", "HIGH", "1234abcd")]


# Detect API key variable without underscore
def test_apikey_match():
    result = detect_from_parts("apikey", "1234abcd")
    assert result == [("API Key", "HIGH", "1234abcd")]


# Detect token with medium severity
def test_token_match():
    result = detect_from_parts("token", "qwerty")
    assert result == [("Token", "MEDIUM", "qwerty")]


# Detect secret with medium severity
def test_secret_match():
    result = detect_from_parts("secret", "abcdef")
    assert result == [("Secret", "MEDIUM", "abcdef")]


# Detect secret when embedded in a longer variable name
def test_secret_embedded_variable_match():
    result = detect_from_parts("client_secret", "abcdef")
    assert result == [("Secret", "MEDIUM", "abcdef")]


# Detect AWS access key by value, regardless of variable name
def test_aws_access_key_value_match():
    result = detect_from_parts("random_var", "AKIAEXAMPLE123456789")
    assert result == [("AWS Access Key", "HIGH", "AKIAEXAMPLE123456789")]


# Ensure lowercase AWS-style value does not match case-sensitive AWS pattern
def test_lowercase_aws_access_key_no_match():
    result = detect_from_parts("random_var", "akiaexample123456789")
    assert result is None


# Ensure AWS access key can produce multiple classifications when variable also matches
def test_aws_access_key_with_api_key_variable():
    result = detect_from_parts("api_key", "AKIAEXAMPLE123456789")
    assert result == [
        ("AWS Access Key", "HIGH", "AKIAEXAMPLE123456789"),
        ("API Key", "HIGH", "AKIAEXAMPLE123456789"),
    ]


# Ensure complex values with special characters are preserved
def test_complex_password_value_match():
    result = detect_from_parts("password", "abc_def-123#$%^&*()")
    assert result == [("Password", "HIGH", "abc_def-123#$%^&*()")]


# Ensure empty variable name does not trigger variable-based rules
def test_empty_variable_name():
    result = detect_from_parts("", "abcdef")
    assert result is None


# Ensure empty value does not trigger length-based rules
def test_empty_value():
    result = detect_from_parts("password", "")
    assert result is None
