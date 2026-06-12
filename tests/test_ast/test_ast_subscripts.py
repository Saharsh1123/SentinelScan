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


def test_ast_subscript_password_assignment():
    code = 'config["password"] = "abcdef"'
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


def test_ast_subscript_api_key_assignment():
    code = 'settings["api_key"] = "abc1234567890j"'
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


def test_ast_subscript_token_assignment():
    code = 'secrets["token"] = "abc1234567890j"'
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


def test_ast_subscript_secret_assignment():
    code = 'config["secret"] = "abcdef"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="secret",
        value="abcdef",
        rule_id="SECRET",
        rule_name="Secret",
        severity="MEDIUM",
        reason=SECRET_REASON,
        confidence="LOW",
    )


def test_ast_subscript_uppercase_key_assignment():
    code = 'config["PASSWORD"] = "abcdef"'
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


def test_ast_attribute_subscript_assignment():
    code = 'self.config["password"] = "abcdef"'
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


def test_ast_nested_subscript_assignment():
    code = 'config["auth"]["password"] = "abcdef"'
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


def test_ast_multiple_sensitive_subscript_targets():
    code = 'config["password"] = settings["token"] = "abcdef"'
    result = detect_ast_secrets(code)

    assert len(result) == 2

    assert_finding(
        result[0],
        line_number=1,
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
        line_number=1,
        var_name="token",
        value="abcdef",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="LOW",
    )


def test_ast_subscript_aws_access_key_value_assignment():
    code = 'config["random"] = "AKIAEXAMPLE123456789"'
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


def test_ast_subscript_api_key_with_aws_value():
    code = 'config["api_key"] = "AKIAEXAMPLE123456789"'
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


def test_ast_subscript_non_string_key_is_ignored():
    code = 'config[password_key] = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_subscript_numeric_index_is_ignored():
    code = 'items[0] = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_subscript_non_string_value_is_ignored():
    code = 'config["password"] = 123456'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_subscript_short_value_is_ignored():
    code = 'config["password"] = "abc"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_subscript_preserves_line_number():
    code = """
    username = "safe"
    config["password"] = "abcdef"
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
