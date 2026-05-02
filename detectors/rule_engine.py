from detectors.rules import RULES


def apply_rules(var_name, val):
    """
    Classify an extracted variable/value pair against secret detection rules.

    Args:
        var_name (str): Normalized variable name or final attribute name.
        val (str): Extracted string literal value.

    Returns:
        list[tuple[str, str, str]] | None:
            A list of findings where each finding is:
                (rule_name, severity, extracted_value)

            Returns None if no rule matches.
    """
    findings = []

    for rule, data in RULES.items():
        # Match structured secret values, such as AWS access keys
        if "value_pattern" in data:
            if data["value_pattern"].fullmatch(val):
                findings.append((rule, data["severity"], val))

        # Match suspicious variable names and enforce minimum value length
        if "var_patterns" in data:
            for pattern in data["var_patterns"]:
                match = pattern.search(var_name)
                if match and len(val) >= data["min_length"]:
                    findings.append((rule, data["severity"], val))

    return findings or None