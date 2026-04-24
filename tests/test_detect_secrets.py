from detectors.find_secrets import detect_secrets

def test_match():
    result = detect_secrets('password = "abcdef"')
    assert result == [("Password", "HIGH", "abcdef")]

def test_no_match():
    result = detect_secrets('passwo = "abcdef"')
    assert result is None

def test_multiple_matches():
    result = detect_secrets('password = "abcdef"; api_key = "1234abcd"; token = "qwerty"')
    assert result == [("Password", "HIGH", "abcdef"), ("API Key", "HIGH", "1234abcd"), ("Token", "MEDIUM", "qwerty")]

def test_comment_match():
    result = detect_secrets('#password = "abcdef"')
    assert result is None

def test_inline_comment_match():
    result = detect_secrets('password = "abcdef"    #comment')
    assert result == [("Password", "HIGH", "abcdef")]

def test_short_match():
    result = detect_secrets('password = "abc"')
    assert result is None

def test_spacing_match():
    result = detect_secrets('password        =           "abcdef"')
    assert result == [("Password", "HIGH", "abcdef")]

def test_uppercase_match():
    result = detect_secrets('PASSWORD = "abcdef"')
    assert result == [("Password", "HIGH", "abcdef")]

def test_duplicate_match():
    result = detect_secrets('password = "abcdef"; password = "abcdefef"')
    assert result == [("Password", "HIGH", "abcdef"), ("Password", "HIGH", "abcdefef")]

def test_valid_invalid_match():
    result = detect_secrets('password = "abcdef"; token = "abc"')
    assert result == [("Password", "HIGH", "abcdef")]

def test_empty_match():
    result = detect_secrets("")
    assert result is None

def test_only_comment_match():
    result = detect_secrets('     #comment')
    assert result is None

def test_whitespace_match():
    result = detect_secrets('          ')
    assert result is None

def test_weird_match():
    result = detect_secrets('password = "abc_def-123#$%^&*()"')
    assert result == [("Password", "HIGH", "abc_def-123#$%^&*()")]
