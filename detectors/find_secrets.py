from detectors.ast_analyzer import parse_ast, get_assignments, extract_node_value, extract_variable_path
from detectors.rule_engine import apply_rules

def detect_ast_secrets(code):
    """
    Scan Python source code using AST analysis to detect hardcoded secrets.

    This function extracts string assignments from the AST, resolves variable
    or attribute names, and classifies each variable/value pair using the
    configured detection rules.

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

            vulnerabilities = apply_rules(var_name, val)

            if vulnerabilities:
                for pattern_name, severity, value, reason in vulnerabilities:
                    findings.append((line_number, pattern_name, severity, value, reason))

    return findings
