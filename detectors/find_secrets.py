from detectors.rule_engine import apply_rules
from detectors.ast_analyzer import extract_candidates


def detect_ast_secrets(code):
    findings = []

    for candidate in extract_candidates(code):
        vulnerabilities = apply_rules(candidate)

        if vulnerabilities:
            for finding in vulnerabilities:
                findings.append(finding)

    return findings
