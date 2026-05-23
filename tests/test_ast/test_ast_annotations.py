from tests.test_ast.ast_helpers import (
    API_KEY_REASON,
    PASSWORD_REASON,
    SECRET_REASON,
    TOKEN_REASON,
    assert_single_finding,
    detect_ast_secrets,
)


def test_ast_annotated_password_assignment():
    """
    Annotated assignments should be treated like normal assignments.

    Example:
        password: str = "abcdef"
    """
    code = 'password: str = "abcdef"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_ast_annotated_api_key_assignment():
    """
    Annotated api_key assignments should produce API key findings.
    """
    code = 'api_key: str = "abc1234567890j"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="api_key",
        value="abc1234567890j",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
        confidence="HIGH",
    )


def test_ast_annotated_token_assignment():
    """
    Annotated token assignments should produce token findings.
    """
    code = 'token: str = "abc1234567890j"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="token",
        value="abc1234567890j",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_ast_annotated_secret_assignment():
    """
    Annotated secret assignments should produce secret findings.
    """
    code = 'client_secret: str = "abcdef"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="client_secret",
        value="abcdef",
        rule_id="SECRET",
        rule_name="Secret",
        severity="MEDIUM",
        reason=SECRET_REASON,
        confidence="LOW",
    )


def test_ast_annotated_uppercase_variable_is_normalized():
    """
    Annotated variable names should still be normalized to lowercase.
    """
    code = 'PASSWORD: str = "abcdef"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_ast_annotated_irrelevant_variable_is_ignored():
    """
    Annotated assignments should not create findings for safe variable names.
    """
    code = 'username: str = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_annotated_short_value_is_ignored():
    """
    Annotated assignments should still respect minimum length rules.
    """
    code = 'password: str = "abc"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_annotated_assignment_without_value_is_ignored():
    """
    Bare annotations without assigned values should be ignored.

    Example:
        password: str
    """
    code = "password: str"
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_annotated_non_string_value_is_ignored():
    """
    Annotated assignments with non-string values should be ignored.
    """
    code = "password: str = 123456"
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_annotated_assignment_preserves_line_number():
    """
    Annotated assignment findings should preserve AST line numbers.
    """
    code = """
    username: str = "safe"
    password: str = "abcdef"
    """
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=3,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )