from tests.test_ast.ast_helpers import (
    API_KEY_REASON,
    AWS_REASON,
    PASSWORD_REASON,
    SECRET_REASON,
    TOKEN_REASON,
    assert_finding,
    assert_single_finding,
    detect_ast_secrets,
)


def test_ast_function_call_password_keyword():
    """
    Function calls with password keyword arguments should produce password findings.
    """
    code = 'connect(password="abcdef")'
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


def test_ast_function_call_api_key_keyword():
    """
    Function calls with api_key keyword arguments should produce API key findings.
    """
    code = 'client(api_key="abc1234567890j")'
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


def test_ast_function_call_token_keyword():
    """
    Function calls with token keyword arguments should produce token findings.
    """
    code = 'authenticate(token="abc1234567890j")'
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


def test_ast_function_call_secret_keyword():
    """
    Function calls with secret keyword arguments should produce secret findings.
    """
    code = 'create_client(client_secret="abcdef")'
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


def test_ast_function_call_uppercase_keyword_is_normalized():
    """
    Keyword argument names should be normalized to lowercase before rule matching.
    """
    code = 'connect(PASSWORD="abcdef")'
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


def test_ast_function_call_irrelevant_keyword_is_ignored():
    """
    Safe keyword argument names should not produce findings.
    """
    code = 'connect(username="abcdef")'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_function_call_short_value_is_ignored():
    """
    Function call keyword findings should still respect minimum length rules.
    """
    code = 'connect(password="abc")'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_function_call_non_string_value_is_ignored():
    """
    Function call keyword arguments with non-string values should be ignored.
    """
    code = "connect(password=123456)"
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_function_call_positional_string_is_ignored():
    """
    Positional string arguments should be ignored because they do not provide
    a clear secret-related variable name.
    """
    code = 'connect("abcdef")'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_function_call_kwargs_expansion_is_ignored():
    """
    **kwargs expansions should be ignored because the keyword name is not
    statically available from keyword.arg.
    """
    code = """
    config = {"password": "abcdef"}
    connect(**config)
    """
    result = detect_ast_secrets(code)

    # The dictionary literal is still detected, but connect(**config) should
    # not create an additional duplicate finding.
    assert_single_finding(
        result,
        line_number=2,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_ast_function_call_multiple_secret_keywords():
    """
    Multiple secret-like keyword arguments in one call should produce multiple findings.
    """
    code = """
    connect(
        password="abcdef",
        api_key="abc1234567890j",
        token="abc1234567890j",
    )
    """
    result = detect_ast_secrets(code)

    assert len(result) == 3

    assert_finding(
        result[0],
        line_number=3,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )

    assert_finding(
        result[1],
        line_number=4,
        var_name="api_key",
        value="abc1234567890j",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
        confidence="HIGH",
    )

    assert_finding(
        result[2],
        line_number=5,
        var_name="token",
        value="abc1234567890j",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="HIGH",
    )


def test_ast_function_call_preserves_multiline_keyword_line_number():
    """
    Function call findings should use the keyword value line number.
    """
    code = """
    connect(
        username="safe",
        password="abcdef",
    )
    """
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=4,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="LOW",
    )


def test_ast_function_call_nested_inside_assignment_is_detected_once():
    """
    Function calls used inside assignments should still be detected once.
    """
    code = 'client = connect(password="abcdef")'
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


def test_ast_function_call_aws_value_with_irrelevant_keyword():
    """
    AWS access key values should be detected even when the keyword name is not sensitive.
    """
    code = 'connect(region="AKIAEXAMPLE123456789")'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="region",
        value="AKIAEXAMPLE123456789",
        rule_id="AWS_ACCESS_KEY",
        rule_name="AWS Access Key",
        severity="HIGH",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_ast_function_call_api_key_with_aws_value():
    """
    A sensitive keyword with an AWS-looking value should match both relevant rules.
    """
    code = 'connect(api_key="AKIAEXAMPLE123456789")'
    result = detect_ast_secrets(code)

    assert len(result) == 2

    assert_finding(
        result[0],
        line_number=1,
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
        line_number=1,
        var_name="api_key",
        value="AKIAEXAMPLE123456789",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
        confidence="HIGH",
    )