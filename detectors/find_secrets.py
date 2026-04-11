import re

# Mapping of detection rules to their regex patterns and severity levels.
# Each rule represents a type of hardcoded secret to detect.
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
    Scan a single line of code for hardcoded secrets using predefined regex rules.

    Iterates through all detection patterns and returns the first match found.

    Args:
        line (str): A single line of code to analyze.

    Returns:
        tuple[str, str] | None:
            - (rule_name, severity) if a secret is detected
            - None if no match is found
    """
    for pattern_name, data in REGEX_INFO.items():
        # Check if the current regex pattern matches the line
        if re.search(data["pattern"], line):
            return pattern_name, data["severity"]

    return None  # Explicitly return None when no patterns match
        



