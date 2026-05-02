import re


# Rule definitions for secret detection.
# Rules can match either:
# - a secret-like value pattern, regardless of variable name
# - a suspicious variable name combined with a minimum value length
RULES = {
    "AWS Access Key": {
        "value_pattern": re.compile(r"(AKIA[0-9A-Z]{16})"),
        "severity": "HIGH",
    },
    "Password": {
        "var_patterns": [
            re.compile(r"password", re.IGNORECASE),
            re.compile(r"pwd", re.IGNORECASE),
            re.compile(r"passwd", re.IGNORECASE),
        ],
        "min_length": 4,
        "severity": "HIGH",
    },
    "API Key": {
        "var_patterns": [
            re.compile(r"api_key", re.IGNORECASE),
            re.compile(r"apikey", re.IGNORECASE),
        ],
        "min_length": 4,
        "severity": "HIGH",
    },
    "Token": {
        "var_patterns": [re.compile(r"token", re.IGNORECASE)],
        "min_length": 4,
        "severity": "MEDIUM",
    },
    "Secret": {
        "var_patterns": [
            re.compile(r"secret", re.IGNORECASE),
        ],
        "min_length": 4,
        "severity": "MEDIUM",
    },
}