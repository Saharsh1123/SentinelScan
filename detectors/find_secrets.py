"""
High-level secret detection orchestration.

This module connects AST candidate extraction to rule evaluation. It does not
read files, print output, or apply suppression rules; those responsibilities
belong to scanner and output modules.
"""

from detectors.ast_analyzer import extract_candidates
from detectors.rule_engine import apply_rules


def detect_ast_secrets(code):
    """
    Detect hardcoded secrets in Python source code using AST-based analysis.

    Args:
        code (str): Raw Python source code.

    Returns:
        list[Finding]: Findings produced by matching extracted candidates
        against built-in rules.
    """
    findings = []

    for candidate in extract_candidates(code):
        vulnerabilities = apply_rules(candidate)

        if vulnerabilities:
            findings.extend(vulnerabilities)

    return findings
