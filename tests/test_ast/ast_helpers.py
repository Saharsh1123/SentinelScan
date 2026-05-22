from detectors.find_secrets import detect_ast_secrets  # noqa: F401

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
    Return entropy metadata from a Finding.

    Supports either `entropy` or `entropy_score` if the field name changes
    during refactoring.
    """
    if hasattr(finding, "entropy"):
        return finding.entropy

    if hasattr(finding, "entropy_score"):
        return finding.entropy_score

    raise AssertionError("Finding is missing entropy metadata")


def assert_entropy_metadata(finding):
    """
    Assert that entropy metadata exists and is numeric.
    """
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
    """
    Assert stable Finding fields while allowing future metadata fields.
    """
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
    """
    Assert that detection produced exactly one expected finding.
    """
    assert len(result) == 1
    assert_finding(result[0], **expected)