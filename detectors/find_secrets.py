import re

# Detection rules for identifying hardcoded secrets in source code.
# Each rule includes:
# - pattern: Regex used to identify the secret
# - severity: Risk level associated with the finding
REGEX_INFO = {
    "AWS Access Key": {
        "pattern": re.compile(r"(AKIA[0-9A-Z]{16})"),
        "severity": "HIGH"
    },
    "Password": {
        "pattern": re.compile(r"password\s*=\s*['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
        "severity": "HIGH"
    },
    "API Key": {
        "pattern": re.compile(r"api_key\s*=\s*['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
        "severity": "HIGH"
    },
    "Token": {
        "pattern": re.compile(r"token\s*=\s*['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    "Secret": {
        "pattern": re.compile(r"secret\s*=\s*['\"]([^'\"]{6,})['\"]", re.IGNORECASE),
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
    line = line.split("#")[0].strip()
    if not line:
        return None

    findings = []

    for pattern_name, data in REGEX_INFO.items():
        # Find all occurrences of the pattern in the line

        for match in data["pattern"].finditer(line):
            # Store rule name, severity, and matched content
            findings.append(
                (pattern_name, data["severity"], match.group(1))
            )

    return findings or None