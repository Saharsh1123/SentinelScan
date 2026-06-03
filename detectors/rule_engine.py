"""
Rule evaluation for extracted candidates.

The rule engine is intentionally separate from AST extraction. It receives
candidate values, applies all built-in rules, and returns structured findings.
"""

from detectors.confidence import calculate_confidence, calculate_entropy
from detectors.models import Finding
from detectors.rules import RULES


def apply_rules(candidate):
    """
    Apply all detection rules to a candidate assignment.

    A single candidate can produce multiple findings. For example, an `api_key`
    variable containing an AWS-looking value can match both the API key rule and
    the AWS access key value rule.

    Args:
        candidate (Candidate): Extracted variable name, value, and line number.

    Returns:
        list[Finding]: Findings created from rules that matched the candidate.
    """
    findings = []

    for rule in RULES:
        val = candidate.value
        var_name = candidate.var_name
        entropy = calculate_entropy(val)

        # Match structured secret values, such as AWS access keys.
        if rule.value_pattern is not None and rule.value_pattern.fullmatch(val):
            findings.append(
                Finding(
                    line_number=candidate.line_number,
                    var_name=var_name,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    value=val,
                    reason=rule.reason,
                    entropy=entropy,
                    confidence="HIGH",
                )
            )

        # Match suspicious variable names and enforce minimum value length.
        if rule.var_patterns:
            confidence = calculate_confidence(val)

            for var_pattern in rule.var_patterns:
                match = var_pattern.search(var_name)

                if (
                    match
                    and rule.min_length is not None
                    and len(val) >= rule.min_length
                ):
                    findings.append(
                        Finding(
                            line_number=candidate.line_number,
                            var_name=var_name,
                            rule_id=rule.rule_id,
                            rule_name=rule.rule_name,
                            severity=rule.severity,
                            value=val,
                            reason=rule.reason,
                            entropy=entropy,
                            confidence=confidence,
                        )
                    )

    return findings
