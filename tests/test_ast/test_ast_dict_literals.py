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


def test_ast_dict_literal_password_key():
    """
    Dictionary literals should create candidates from string key/value pairs.

    Example:
        config = {"password": "abcdef"}
    """
    code = 'config = {"password": "abcdef"}'
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


def test_ast_dict_literal_api_key_key():
    """
    Dictionary literal api_key entries should produce API key findings.
    """
    code = 'config = {"api_key": "abc1234567890j"}'
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


def test_ast_dict_literal_token_key():
    """
    Dictionary literal token entries should produce token findings.
    """
    code = 'config = {"token": "abc1234567890j"}'
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


def test_ast_dict_literal_secret_key():
    """
    Dictionary literal secret entries should produce secret findings.
    """
    code = 'config = {"client_secret": "abcdef"}'
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


def test_ast_dict_literal_irrelevant_key_is_ignored():
    """
    Safe dictionary keys should not produce findings.
    """
    code = 'config = {"username": "abcdef"}'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_dict_literal_short_value_is_ignored():
    """
    Dictionary literal findings should still respect minimum length rules.
    """
    code = 'config = {"password": "abc"}'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_dict_literal_non_string_key_is_ignored():
    """
    Dictionary entries with non-string keys should be ignored.
    """
    code = 'config = {password: "abcdef"}'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_dict_literal_non_string_value_is_ignored():
    """
    Dictionary entries with non-string values should be ignored.
    """
    code = 'config = {"password": 123456}'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_dict_literal_multiple_secret_entries():
    """
    Multiple secret-like dictionary entries should produce multiple findings.
    """
    code = """
    config = {
        "password": "abcdef",
        "api_key": "abc1234567890j",
        "token": "abc1234567890j",
    }
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


def test_ast_dict_literal_aws_value_with_irrelevant_key():
    """
    AWS access key values should be detected even when the dictionary key is not sensitive.
    """
    code = 'config = {"random": "AKIAEXAMPLE123456789"}'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="random",
        value="AKIAEXAMPLE123456789",
        rule_id="AWS_ACCESS_KEY",
        rule_name="AWS Access Key",
        severity="HIGH",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_ast_dict_literal_api_key_with_aws_value():
    """
    A dictionary api_key entry with an AWS-looking value should match both rules.
    """
    code = 'config = {"api_key": "AKIAEXAMPLE123456789"}'
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


def test_ast_dict_literal_mixed_safe_and_unsafe_entries():
    """
    Safe dictionary entries should be skipped while unsafe entries are reported.
    """
    code = """
    config = {
        "username": "saharsh",
        "password": "abcdef",
        "debug": True,
    }
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


def test_ast_dict_literal_empty_dict_is_ignored():
    """
    Empty dictionary literals should not produce findings.
    """
    code = "config = {}"
    result = detect_ast_secrets(code)

    assert result == []
