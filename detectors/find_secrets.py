import re
import ast
import textwrap

REGEX_INFO = {
    "AWS Access Key": {
        "value_pattern": re.compile(r"(AKIA[0-9A-Z]{16})"),
        "severity": "HIGH"
    },
    "Password": {
        "var_patterns": [
            re.compile(r"password", re.IGNORECASE),
            re.compile(r"pwd", re.IGNORECASE),
            re.compile(r"passwd", re.IGNORECASE)         
        ],
        "min_length": 4,
        "severity": "HIGH"
    },
    "API Key": {
        "var_patterns": [
            re.compile(r"api_key", re.IGNORECASE),
            re.compile(r"apikey", re.IGNORECASE)
        ],
        "min_length": 4,        
        "severity": "HIGH"
    },
    "Token": {
        "var_patterns": [re.compile(r"token", re.IGNORECASE)],
        "min_length": 4,
        "severity": "MEDIUM"
    },
    "Secret": {
        "var_patterns": [re.compile(r"secret", re.IGNORECASE),],
        "min_length": 4,
        "severity": "MEDIUM"
    }
}


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

def detect_from_parts(var_name, val):
    findings = []
    for rule, data in REGEX_INFO.items():
        if "value_pattern" in data:
            if data["value_pattern"].fullmatch(val):
                findings.append((rule, data["severity"], val))

        if "var_patterns" in data:
            for pattern in data["var_patterns"]:
                match = pattern.search(var_name) 
                if match and len(val) >= data["min_length"]:
                    findings.append((rule, data["severity"], val))

    return findings or None


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

            vulnerabilities = detect_from_parts(var_name, val)

            if vulnerabilities:
                for pattern_name, severity, value in vulnerabilities:
                    findings.append((line_number, pattern_name, severity, value))
        
    return findings


    