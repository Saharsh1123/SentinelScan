import re

# Detection rules for identifying hardcoded secrets in source code.
# Each rule includes:
# - pattern: Regex used to identify the secret
# - severity: Risk level associated with the finding
REGEX_INFO = {
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "HIGH"
    },
    "Password": {
        "pattern": r"password\s*=\s*['\"]([^'\"]+)['\"]",
        "severity": "HIGH"
    },
    "API Key": {
        "pattern": r"api_key\s*=\s*['\"]([^'\"]+)['\"]",
        "severity": "HIGH"
    },
    "Token": {
        "pattern": r"token\s*=\s*['\"]([^'\"]+)['\"]",
        "severity": "MEDIUM"
    },
    "Secret": {
        "pattern": r"secret\s*=\s*['\"]([^'\"]+)['\"]",
        "severity": "MEDIUM"
    }
}


def detect_secrets(line):
    """
    Analyze a single line of code for hardcoded secrets using predefined regex rules.

    Iterates through all detection patterns and collects all matches found in the line.

    Args:
        line (str): A single line of source code.

    Returns:
        list[tuple[str, str, str]] | None:
            A list of findings where each finding is a tuple:
            (rule_name, severity, matched_value).
            Returns None if no matches are found.
    """
    vulnerabilities = []

    for pattern_name, data in REGEX_INFO.items():
        # Find all occurrences of the pattern in the line
        matches = list(re.finditer(data["pattern"], line))

        if matches:
            for match in matches:
                # Store rule name, severity, and matched content
                vulnerabilities.append(
                    (pattern_name, data["severity"], match.group())
                )

    return vulnerabilities or None