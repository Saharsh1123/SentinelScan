import re


# Rule definitions for secret detection.
# Rules can match either:
# - a secret-like value pattern, regardless of variable name
# - a suspicious variable name combined with a minimum value length
RULES = {
    "AWS Access Key": {
        "value_pattern": re.compile(r"(AKIA[0-9A-Z]{16})"),
        "severity": "HIGH",
        "reason": "value matched AKIA-prefixed AWS access key pattern",
    },
    "Password": {
        "var_patterns": [
            re.compile(r"password", re.IGNORECASE),
            re.compile(r"pwd", re.IGNORECASE),
            re.compile(r"passwd", re.IGNORECASE),
        ],
        "min_length": 4,
        "severity": "HIGH",
        "reason": "variable name matched password/pwd/passwd pattern and value met minimum length",
    },
    "API Key": {
        "var_patterns": [
            re.compile(r"api_key", re.IGNORECASE),
            re.compile(r"apikey", re.IGNORECASE),
        ],
        "min_length": 4,
        "severity": "HIGH",
        "reason": "variable name matched api_key/apikey pattern and value met minimum length",
    },
    "Token": {
        "var_patterns": [re.compile(r"token", re.IGNORECASE)],
        "min_length": 4,
        "severity": "MEDIUM",
        "reason": "variable name matched token pattern and value met minimum length",
    },
    "Secret": {
        "var_patterns": [
            re.compile(r"secret", re.IGNORECASE),
        ],
        "min_length": 4,
        "severity": "MEDIUM",
        "reason": "variable name matched secret pattern and value met minimum length",
    },
}