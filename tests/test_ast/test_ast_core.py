from tests.test_ast.ast_helpers import (
    API_KEY_REASON,
    AWS_REASON,
    PASSWORD_REASON,
    SECRET_REASON,
    SUPPORTED_CONFIDENCE,
    TOKEN_REASON,
    assert_finding,
    assert_single_finding,
    detect_ast_secrets,
    get_entropy,
)


def test_ast_basic_password():
    code = 'password = "abcdef"'
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


def test_ast_secret():
    code = 'client_secret = "abcdef"'
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


def test_ast_aws_access_key_value():
    code = 'random_var = "AKIAEXAMPLE123456789"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="random_var",
        value="AKIAEXAMPLE123456789",
        rule_id="AWS_ACCESS_KEY",
        rule_name="AWS Access Key",
        severity="HIGH",
        reason=AWS_REASON,
        confidence="HIGH",
    )


def test_ast_aws_access_key_with_api_key_variable():
    code = 'api_key = "AKIAEXAMPLE123456789"'
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


def test_ast_multiple_classifications_preserve_rule_order():
    code = 'api_key = "AKIAEXAMPLE123456789"'
    result = detect_ast_secrets(code)

    assert [finding.rule_id for finding in result] == [
        "AWS_ACCESS_KEY",
        "API_KEY",
    ]


def test_ast_non_string_assignment_is_ignored():
    code = "password = 123456"
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_irrelevant_variable_is_ignored():
    code = 'username = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_short_value_is_ignored():
    code = 'password = "abc"'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_multiple_assignments():
    code = """
    password = "abcdef"
    api_key = "12345678"
    token = "qwerty123"
    """
    result = detect_ast_secrets(code)

    assert len(result) == 3

    assert_finding(
        result[0],
        line_number=2,
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
        line_number=3,
        var_name="api_key",
        value="12345678",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
    )

    assert_finding(
        result[2],
        line_number=4,
        var_name="token",
        value="qwerty123",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
    )


def test_ast_syntax_error_returns_empty_list():
    code = 'password = "abc'
    result = detect_ast_secrets(code)

    assert result == []


def test_ast_uppercase_variable_is_normalized():
    code = 'PASSWORD = "abcdef"'
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


def test_ast_multiple_targets():
    code = 'a = password = "abcdef"'
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


def test_ast_multiple_sensitive_targets():
    code = 'password = token = "abcdef"'
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


def test_ast_complex_password_value():
    code = 'password = "abc_def-123#$%^&*()"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="password",
        value="abc_def-123#$%^&*()",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason=PASSWORD_REASON,
        confidence="HIGH",
    )


def test_ast_dedented_multiline_code():
    code = """
        password = "abcdef"
        username = "notsecret"
    """
    result = detect_ast_secrets(code)

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


def test_ast_preserves_line_number():
    code = """
    username = "safe"
    token = "abcdef"
    """
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=3,
        var_name="token",
        value="abcdef",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="LOW",
    )


def test_ast_high_confidence_token():
    code = 'token = "abc1234567890j"'
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


def test_ast_repetitive_token_medium_confidence():
    code = 'token = "xyzttttggfdddf"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="token",
        value="xyzttttggfdddf",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
        confidence="MEDIUM",
    )


def test_ast_repetitive_api_key_low_confidence():
    code = 'api_key = "12dwdqwdqwdqw3"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="api_key",
        value="12dwdqwdqwdqw3",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
        confidence="LOW",
    )


def test_ast_findings_use_supported_confidence_labels():
    code = """
    password = "abcdef"
    token = "abc1234567890j"
    api_key = "AKIAEXAMPLE123456789"
    """
    result = detect_ast_secrets(code)

    assert result
    assert all(finding.confidence in SUPPORTED_CONFIDENCE for finding in result)


def test_ast_findings_include_entropy_metadata():
    code = """
    password = "abcdef"
    token = "abc1234567890j"
    api_key = "AKIAEXAMPLE123456789"
    """
    result = detect_ast_secrets(code)

    assert result
    assert all(get_entropy(finding) >= 0 for finding in result)


def test_ast_findings_do_not_include_file_path_before_scanner_enrichment():
    code = 'password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result[0].file_path is None
