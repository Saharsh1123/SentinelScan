from detectors.rules import RULES
from detectors.models import Finding


def apply_rules(candidate):

    findings = []

    for rule in RULES:
        # Match structured secret values, such as AWS access keys
        if rule.value_pattern is not None:
            val = candidate.value
            if rule.value_pattern.fullmatch(val):
                findings.append(Finding(
                    line_number=candidate.line_number,
                    var_name=candidate.var_name,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    value = val,
                    reason=rule.reason
                ))

        # Match suspicious variable names and enforce minimum value length
        if rule.var_patterns:
            for var_pattern in rule.var_patterns:
                val = candidate.value
                var_name = candidate.var_name
                match = var_pattern.search(var_name)
                if match and rule.min_length is not None and len(val) >= rule.min_length:
                    findings.append(Finding(
                    line_number=candidate.line_number,
                    var_name=var_name,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    value = val,
                    reason=rule.reason
                ))

    return findings