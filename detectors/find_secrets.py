import re

REGEX_INFO = {
    "AWS Access Key": {
        "pattern" : r"AKIA[0-9A-Z]{16}",
        "severity" : "HIGH"
    },
    "Password": {
        "pattern" : r"password\s*=\s*['\"]([^'\"]+)['\"]",
        "severity" : "HIGH"
    },
    "API Key": {
        "pattern" : r"api_key\s*=\s*['\"]([^'\"]+)['\"]",
        "severity" : "HIGH"
    },
    "Token": {
        "pattern" : r"token\s*=\s*['\"]([^'\"]+)['\"]",
        "severity" : "MEDIUM"
    },
    "Secret": {
        "pattern" : r"secret\s*=\s*['\"]([^'\"]+)['\"]",
        "severity" : "MEDIUM"
    }
}

def detect_secrets(line):
    for pattern_name, data in REGEX_INFO.items():  
        if re.search(data["pattern"], line):
            return pattern_name, data["severity"]
        



