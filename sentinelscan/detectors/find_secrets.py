"""
High-level secret detection orchestration.

This module connects AST parsing and candidate extraction to rule evaluation.
It does not read files, print output, or apply suppression rules; those
responsibilities belong to scanner and output modules.
"""

from sentinelscan.detectors.ast_analyzer import extract_candidates, parse_ast
from sentinelscan.detectors.rule_engine import apply_rules


def detect_ast_secrets(code):
    """
    Detect hardcoded secrets or return a structured AST parse failure.

    Args:
        code (str): Raw Python source code.

    Returns:
        tuple[list[Finding], SkippedFile | None]: Findings produced from valid
            source, or an empty finding list plus a syntax-error diagnostic.
    """
    tree, skipped_file = parse_ast(code)

    if skipped_file is not None:
        return [], skipped_file

    findings = []

    for candidate in extract_candidates(tree):
        findings.extend(apply_rules(candidate))

    return findings, None
