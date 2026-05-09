from detectors.rule_engine import apply_rules
from detectors.ast_analyzer import extract_candidates


def detect_ast_secrets(code):
    """
    Detect hardcoded secrets in Python source code using AST-based analysis.

    Extracts candidate string assignments from source code, applies detection
    rules, and returns confirmed findings.

    Args:
        code (str): Raw Python source code.

    Returns:
        list[Finding]: Findings produced by matching candidates against rules.
    """
    findings = []

    for candidate in extract_candidates(code):
        vulnerabilities = apply_rules(candidate)

        # Collect all rule matches for the current candidate.
        if vulnerabilities:
            for finding in vulnerabilities:
                findings.append(finding)

    return findings
