"""Unit tests for finding filtering behavior."""

from detectors.models import Finding
from output import filter_results


def make_finding(rule_id, severity, confidence):
    """Create a minimal finding with the fields filter_results reads."""
    return Finding(
        line_number=1,
        value="secret-value",
        rule_id=rule_id,
        rule_name=rule_id.title(),
        severity=severity,
        reason="test finding",
        confidence=confidence,
    )


def test_filter_results_requires_matching_severity_and_confidence_in_order():
    """Filtering should keep only exact level matches without reordering them."""
    wrong_severity = make_finding("TOKEN", "MEDIUM", "HIGH")
    first_match = make_finding("PASSWORD", "HIGH", "HIGH")
    wrong_confidence = make_finding("SECRET", "HIGH", "LOW")
    second_match = make_finding("API_KEY", "HIGH", "MEDIUM")

    result = filter_results(
        [wrong_severity, first_match, wrong_confidence, second_match],
        chosen_severity=["HIGH"],
        chosen_confidence=["HIGH", "MEDIUM"],
    )

    assert result == [first_match, second_match]
