from detectors.find_secrets import detect_ast_secrets

# Basic detection of a simple variable assignment
def test_ast_basic_password():
    code = 'password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Detect secrets assigned via object attributes (e.g., self.password)
def test_ast_attribute_password():
    code = 'self.password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Detect API key pattern from attribute-based assignment
def test_ast_api_key():
    code = 'config.api_key = "12345678"'
    result = detect_ast_secrets(code)

    assert result == [(1, "API Key", "HIGH", "12345678")]


# Detect token with correct severity classification
def test_ast_token():
    code = 'user.token = "qwerty123"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Token", "MEDIUM", "qwerty123")]


# Ensure non-string assignments are ignored
def test_ast_non_string():
    code = 'password = 123456'
    result = detect_ast_secrets(code)

    assert result == []


# Ensure unrelated variable names are not flagged
def test_ast_irrelevant_variable():
    code = 'username = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


# Validate detection across multiple assignments with correct line numbers
def test_ast_multiple_assignments():
    code = '''
    password = "abcdef"
    api_key = "12345678"
    token = "qwerty123"
    '''
    result = detect_ast_secrets(code)

    assert result == [
        (2, "Password", "HIGH", "abcdef"),
        (3, "API Key", "HIGH", "12345678"),
        (4, "Token", "MEDIUM", "qwerty123")
    ]


# Ensure syntax errors are handled gracefully without crashing
def test_ast_syntax_error():
    code = 'password = "abc'  
    result = detect_ast_secrets(code)

    assert result == []


# Ensure case-insensitive variable matching
def test_ast_uppercase_variable():
    code = 'PASSWORD = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Ensure multiple assignment targets are handled correctly
def test_ast_multiple_targets():
    code = 'a = password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]


# Validate detection within deeply nested attribute chains
def test_ast_nested_attribute():
    code = 'self.config.db.password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == [(1, "Password", "HIGH", "abcdef")]