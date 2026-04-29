from detectors.find_secrets import detect_secrets


# Basic detection of a valid password assignment
def test_match():
    result = detect_secrets('password = "abcdef"')
    assert result == [("Password", "HIGH", "abcdef")]


# Ensure similar but incorrect variable names are not flagged
def test_no_match():
    result = detect_secrets('passwo = "abcdef"')
    assert result is None


# Validate detection of multiple secrets within a single line
def test_multiple_matches():
    result = detect_secrets('password = "abcdef"; api_key = "1234abcd"; token = "qwerty"')
    assert result == [
        ("Password", "HIGH", "abcdef"),
        ("API Key", "HIGH", "1234abcd"),
        ("Token", "MEDIUM", "qwerty")
    ]


# Ensure fully commented lines are ignored
def test_comment_match():
    result = detect_secrets('#password = "abcdef"')
    assert result is None


# Ensure inline comments do not affect detection
def test_inline_comment_match():
    result = detect_secrets('password = "abcdef"    #comment')
    assert result == [("Password", "HIGH", "abcdef")]


# Ensure values below minimum length threshold are ignored
def test_short_match():
    result = detect_secrets('password = "abc"')
    assert result is None


# Validate detection with irregular spacing around assignment
def test_spacing_match():
    result = detect_secrets('password        =           "abcdef"')
    assert result == [("Password", "HIGH", "abcdef")]


# Ensure case-insensitive matching for variable names
def test_uppercase_match():
    result = detect_secrets('PASSWORD = "abcdef"')
    assert result == [("Password", "HIGH", "abcdef")]


# Ensure multiple occurrences of the same secret type are captured
def test_duplicate_match():
    result = detect_secrets('password = "abcdef"; password = "abcdefef"')
    assert result == [
        ("Password", "HIGH", "abcdef"),
        ("Password", "HIGH", "abcdefef")
    ]


# Ensure valid secrets are detected while invalid ones are ignored
def test_valid_invalid_match():
    result = detect_secrets('password = "abcdef"; token = "abc"')
    assert result == [("Password", "HIGH", "abcdef")]


# Ensure empty input returns no findings
def test_empty_match():
    result = detect_secrets("")
    assert result is None


# Ensure lines with only comments are ignored
def test_only_comment_match():
    result = detect_secrets('     #comment')
    assert result is None


# Ensure whitespace-only lines are ignored
def test_whitespace_match():
    result = detect_secrets('          ')
    assert result is None


# Validate detection of complex strings with special characters
def test_weird_match():
    result = detect_secrets('password = "abc_def-123#$%^&*()"')
    assert result == [("Password", "HIGH", "abc_def-123#$%^&*()")]
