from detectors.find_secrets import detect_ast_secrets


# Detect a basic hardcoded password assignment
def test_ast_basic_password():
    code = 'password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Detect password assigned through a simple object attribute
def test_ast_attribute_password():
    code = 'self.password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Detect API key assigned through an attribute
def test_ast_api_key():
    code = 'config.api_key = "12345678"'
    result = detect_ast_secrets(code)

    assert result == [(1, "API Key", "HIGH", "12345678")]


# Detect token with correct MEDIUM severity
def test_ast_token():
    code = 'user.token = "qwerty123"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Token", "MEDIUM", "qwerty123")]


# Detect generic secret assignment
def test_ast_secret():
    code = 'client_secret = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Secret", "MEDIUM", "abcdef")]


# Detect AWS access key by value, regardless of variable name
def test_ast_aws_access_key_value():
    code = 'random_var = "AKIAEXAMPLE123456789"'
    result = detect_ast_secrets(code)

    assert result == [(1, "AWS Access Key", "HIGH", "AKIAEXAMPLE123456789")]


# Detect multiple classifications when both value and variable name match
def test_ast_aws_access_key_with_api_key_variable():
    code = 'api_key = "AKIAEXAMPLE123456789"'
    result = detect_ast_secrets(code)

    assert result == [
        (1, "AWS Access Key", "HIGH", "AKIAEXAMPLE123456789"),
        (1, "API Key", "HIGH", "AKIAEXAMPLE123456789"),
    ]


# Ignore non-string assignments
def test_ast_non_string():
    code = "password = 123456"
    result = detect_ast_secrets(code)

    assert result == []


# Ignore unrelated variable names with string values
def test_ast_irrelevant_variable():
    code = 'username = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


# Ignore short values below the rule threshold
def test_ast_short_value():
    code = 'password = "abc"'
    result = detect_ast_secrets(code)

    assert result == []


# Validate multiple assignments and correct line numbers
def test_ast_multiple_assignments():
    code = """
    password = "abcdef"
    api_key = "12345678"
    token = "qwerty123"
    """
    result = detect_ast_secrets(code)

    assert result == [
        (2, "Password", "HIGH", "abcdef"),
        (3, "API Key", "HIGH", "12345678"),
        (4, "Token", "MEDIUM", "qwerty123"),
    ]


# Handle syntax errors gracefully without crashing
def test_ast_syntax_error():
    code = 'password = "abc'
    result = detect_ast_secrets(code)

    assert result == []


# Detect uppercase variable names through case-insensitive rules
def test_ast_uppercase_variable():
    code = 'PASSWORD = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Process multiple assignment targets correctly
def test_ast_multiple_targets():
    code = 'a = password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Process multiple sensitive targets assigned the same value
def test_ast_multiple_sensitive_targets():
    code = 'password = token = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [
        (1, "Password", "HIGH", "abcdef"),
        (1, "Token", "MEDIUM", "abcdef"),
    ]


# Detect secrets in deeply nested attribute chains
def test_ast_nested_attribute():
    code = 'self.config.db.password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Detect API keys in deeply nested attribute chains
def test_ast_deep_nested_api_key():
    code = 'settings.auth.credentials.api_key = "12345678"'
    result = detect_ast_secrets(code)

    assert result == [(1, "API Key", "HIGH", "12345678")]


# Ignore unsupported assignment targets such as subscript assignments
def test_ast_unsupported_subscript_target():
    code = 'config["password"] = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


# Preserve complex string values with special characters
def test_ast_complex_password_value():
    code = 'password = "abc_def-123#$%^&*()"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abc_def-123#$%^&*()")]


# Handle indented multiline code by normalizing indentation
def test_ast_dedented_multiline_code():
    code = """
        password = "abcdef"
        username = "notsecret"
    """
    result = detect_ast_secrets(code)

    assert result == [(2, "Password", "HIGH", "abcdef")]
