import re
import ast
import textwrap

# Precompiled regex rules for detecting hardcoded secrets in source code.
# Each rule contains:
# - pattern: compiled regex used to identify the secret
# - severity: classification of the finding (e.g., HIGH, MEDIUM)
#
# Notes:
# - Patterns use capture groups to extract only the secret value.
# - Length constraints ({4,}) help reduce false positives.
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


def parse_ast(file):
    """
    Parse source code into an AST.

    Args:
        file (str): Raw Python source code.

    Returns:
        ast.AST | None: Parsed AST object, or None if parsing fails.
    """
    file = textwrap.dedent(file)

    try:
        tree = ast.parse(file)
    except SyntaxError:
        return None
    
    return tree


def get_assignments(tree):
    """
    Yield all assignment nodes from an AST.

    Args:
        tree (ast.AST): Parsed syntax tree.

    Yields:
        ast.Assign: Assignment nodes found during traversal.
    """
    for node in ast.walk(tree): 
        if isinstance(node, ast.Assign):
            yield node


def extract_node_value(node):
    """
    Extract a string literal value from an assignment node.

    Args:
        node (ast.Assign): Assignment node.

    Returns:
        str | None: String value if valid, otherwise None.
    """
    val = node.value
    if not(
        isinstance(val, ast.Constant)
        and isinstance(val.value, str)
    ):
        return None
    return val.value


def extract_variable_path(node):
    """
    Extract variable name paths from assignment targets.

    Supports simple variables and nested attributes (e.g., self.config.key).

    Args:
        node (ast.Assign): Assignment node.

    Yields:
        list[str]: Normalized variable path (lowercased components).
    """
    for var in node.targets:
        full_path = []
        temp_node = var

        # Traverse nested attribute chain (e.g., self.config.key)
        if isinstance(temp_node, ast.Attribute):
            while isinstance(temp_node, ast.Attribute):
                full_path.append(temp_node.attr.lower())
                temp_node = temp_node.value

            # Ensure root is a valid variable name
            if not isinstance(temp_node, ast.Name):
                continue

            full_path.append(temp_node.id.lower())
            full_path.reverse()

        # Handle simple variable assignment
        elif isinstance(var, ast.Name):
            full_path.append(var.id.lower())

        # Yield only valid, non-empty paths
        if len(full_path) != 0:
            yield full_path


def detect_ast_secrets(code):
    """
    Scan Python source code using AST analysis to detect hardcoded secrets.

    This function identifies string assignments and evaluates them against
    predefined detection rules by reconstructing a normalized assignment pattern.

    Args:
        code (str): Python source code.

    Returns:
        list[tuple[int, str, str, str]]:
            List of findings:
                (line_number, rule_name, severity, extracted_value)
    """
    findings = []
    tree = parse_ast(code)
    if tree is None:
        return []

    for node in get_assignments(tree):
        val = extract_node_value(node)
        if val is None:
            continue

        line_number = node.lineno

        for full_path in extract_variable_path(node):
            var_name = full_path[-1]

            # Normalize AST data into a regex-compatible assignment string
            fake_line = f"{var_name} = \"{val}\""

            vulnerabilities = detect_secrets(fake_line)

            if vulnerabilities:
                for pattern_name, severity, value in vulnerabilities:
                    findings.append((line_number, pattern_name, severity, value))
        
    return findings


    