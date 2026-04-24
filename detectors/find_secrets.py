import re
import ast

# Precompiled regex rules for detecting hardcoded secrets in source code.
# Each rule contains:
# - pattern: compiled regex used to identify the secret
# - severity: classification of the finding (e.g., HIGH, MEDIUM)
#
# Notes:
# - Patterns use capture groups to extract only the secret value.
# - Length constraints ({6,}) help reduce false positives.
# - Case-insensitive matching is applied where appropriate.
REGEX_INFO = {
    "AWS Access Key": {
        "pattern": re.compile(r"(AKIA[0-9A-Z]{16})"),
        "severity": "HIGH"
    },
    "Password": {
        "pattern": re.compile(r"password\s*=\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
        "severity": "HIGH"
    },
    "API Key": {
        "pattern": re.compile(r"api_key\s*=\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
        "severity": "HIGH"
    },
    "Token": {
        "pattern": re.compile(r"token\s*=\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
        "severity": "MEDIUM"
    },
    "Secret": {
        "pattern": re.compile(r"secret\s*=\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
        "severity": "MEDIUM"
    }
}


def detect_secrets(line):
    """
    Scan a single line of source code for hardcoded secrets.

    This function applies all predefined regex detection rules to the given line
    and returns any matches found. It ignores commented portions of the line and
    skips empty or non-executable content.

    Args:
        line (str): A raw line of source code.

    Returns:
        list[tuple[str, str, str]] | None:
            A list of findings, where each finding is a tuple:
                (rule_name, severity, extracted_secret_value)

            - rule_name (str): Type of secret detected (e.g., "API Key")
            - severity (str): Risk level associated with the finding
            - extracted_secret_value (str): The actual secret value captured

            Returns None if no secrets are detected in the line.

    Behavior:
        - Strips inline comments using '#' delimiter
        - Ignores empty or whitespace-only lines
        - Supports multiple detections per line
        - Uses precompiled regex for efficiency
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    findings = []

    # Apply each detection rule to the line
    for pattern_name, data in REGEX_INFO.items():
        for match in data["pattern"].finditer(line):
            findings.append(
                (pattern_name, data["severity"], match.group(1))
            )

    return findings or None


def detect_ast_secrets(file):
    findings = []

    try:
        tree = ast.parse(file)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):

            var = node.targets[0]
            val = node.value
             
            if (
                isinstance(var, ast.Name)
                and isinstance(val, ast.Constant)
                and isinstance(val.value, str)
            ):
                line_number = node.lineno
                original_name = var.id
                var_name = original_name.lower()
                
                fake_line = f"{var_name} = \"{val.value}\""

                vulnerabilities = detect_secrets(fake_line)

                if vulnerabilities:
                    for pattern_name, severity, value in vulnerabilities:
                        findings.append((line_number, pattern_name, severity, value))

    return findings