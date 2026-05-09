from detectors.find_secrets import detect_ast_secrets


PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern and value met minimum length"
)
API_KEY_REASON = (
    "variable name matched api_key/apikey pattern and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"
SECRET_REASON = "variable name matched secret pattern and value met minimum length"
AWS_REASON = "value matched AKIA-prefixed AWS access key pattern"

SUPPORTED_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}


def get_entropy(finding):
    """
    Return the entropy field from a Finding.

    Supports either `entropy` or `entropy_score` if the field name changes
    during refactoring.
    """
    if hasattr(finding, "entropy"):
        return finding.entropy

    if hasattr(finding, "entropy_score"):
        return finding.entropy_score

    raise AssertionError("Finding is missing entropy metadata")


def assert_entropy_metadata(finding):
    entropy = get_entropy(finding)

    assert isinstance(entropy, (int, float))
    assert entropy >= 0


def assert_finding(
    finding,
    *,
    line_number,
    file_path=None,
    var_name,
    value,
    rule_id,
    rule_name,
    severity,
    reason,
    confidence=None,
):
    assert finding.file_path == file_path
    assert finding.line_number == line_number
    assert finding.var_name == var_name
    assert finding.value == value
    assert finding.rule_id == rule_id
    assert finding.rule_name == rule_name
    assert finding.severity == severity
    assert finding.reason == reason

    if confidence is None:
        assert finding.confidence in SUPPORTED_CONFIDENCE
    else:
        assert finding.confidence == confidence

    assert_entropy_metadata(finding)


def assert_single_finding(result, **expected):
    assert len(result) == 1
    assert_finding(result[0], **expected)


# Detect a basic hardcoded password assignment
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


# Detect password assigned through a simple object attribute
def test_ast_attribute_password():
    code = 'self.password = "abcdef"'
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


# Detect API key assigned through an attribute
def test_ast_api_key():
    code = 'config.api_key = "12345678"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="api_key",
        value="12345678",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
    )


# Detect token with correct MEDIUM severity
def test_ast_token():
    code = 'user.token = "qwerty123"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="token",
        value="qwerty123",
        rule_id="TOKEN",
        rule_name="Token",
        severity="MEDIUM",
        reason=TOKEN_REASON,
    )


# Detect generic secret assignment
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


# Detect AWS access key by value, regardless of variable name
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


# Detect multiple classifications when both value and variable name match
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


# Ensure multiple classifications preserve rule order
def test_ast_multiple_classifications_preserve_rule_order():
    code = 'api_key = "AKIAEXAMPLE123456789"'
    result = detect_ast_secrets(code)

    assert [finding.rule_id for finding in result] == [
        "AWS_ACCESS_KEY",
        "API_KEY",
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


# Validate multiple assignments, metadata, confidence, and line numbers
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


# Handle syntax errors gracefully without crashing
def test_ast_syntax_error():
    code = 'password = "abc'
    result = detect_ast_secrets(code)

    assert result == []


# Detect uppercase variable names through case-insensitive rules
def test_ast_uppercase_variable():
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


# Process multiple assignment targets correctly
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


# Process multiple sensitive targets assigned the same value
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


# Detect secrets in deeply nested attribute chains
def test_ast_nested_attribute():
    code = 'self.config.db.password = "abcdef"'
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


# Detect API keys in deeply nested attribute chains
def test_ast_deep_nested_api_key():
    code = 'settings.auth.credentials.api_key = "12345678"'
    result = detect_ast_secrets(code)

    assert_single_finding(
        result,
        line_number=1,
        var_name="api_key",
        value="12345678",
        rule_id="API_KEY",
        rule_name="API Key",
        severity="HIGH",
        reason=API_KEY_REASON,
    )


# Ignore unsupported assignment targets such as subscript assignments
def test_ast_unsupported_subscript_target():
    code = 'config["password"] = "abcdef"'
    result = detect_ast_secrets(code)

    assert result == []


# Preserve complex string values with special characters
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


# Handle indented multiline code by normalizing indentation
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


# Ensure detected findings preserve their source line number
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


# Ensure high-confidence token values keep confidence through AST detection
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


# Ensure repetitive token values do not become high confidence
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


# Ensure repetitive API key values can be low confidence
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


# Ensure all findings include supported confidence labels
def test_ast_findings_use_supported_confidence_labels():
    code = """
    password = "abcdef"
    token = "abc1234567890j"
    api_key = "AKIAEXAMPLE123456789"
    """
    result = detect_ast_secrets(code)

    assert result
    assert all(finding.confidence in SUPPORTED_CONFIDENCE for finding in result)


# Ensure all findings include entropy metadata
def test_ast_findings_include_entropy_metadata():
    code = """
    password = "abcdef"
    token = "abc1234567890j"
    api_key = "AKIAEXAMPLE123456789"
    """
    result = detect_ast_secrets(code)

    assert result
    assert all(get_entropy(finding) >= 0 for finding in result)


# Ensure AST findings do not include file paths before scanner enrichment
def test_ast_findings_do_not_include_file_path():
    code = 'password = "abcdef"'
    result = detect_ast_secrets(code)

    assert result[0].file_path is None