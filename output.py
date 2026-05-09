import json


def redact_value(value):
    """
    Redact a secret value while preserving limited identifying context.

    Short values are fully redacted. Longer values keep a small prefix and
    suffix so users can identify the finding without exposing the full value.
    """
    if not value or len(value) <= 4:
        return "[REDACTED]"

    if len(value) <= 8:
        return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"

    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def filter_results(results, chosen_severity):
    """
    Filter findings by severity.

    Args:
        results (list[Finding]): Findings returned by the scanner.
        chosen_severity (str | None): Severity to keep, or None to keep all findings.

    Returns:
        list[Finding]: Findings matching the selected severity.
    """
    filtered_findings = []

    for finding in results:
        if finding.severity == chosen_severity or chosen_severity is None:
            filtered_findings.append(finding)

    return filtered_findings


def output_json(filtered_findings, redact_secrets):
    """
    Print findings as machine-readable JSON.

    Args:
        filtered_findings (list[Finding]): Findings to serialize.
        redact_secrets (bool): Whether to redact detected values.

    Returns:
        None
    """
    json_results = []

    for filtered_finding in filtered_findings:
        value = filtered_finding.value
        if redact_secrets:
            value = redact_value(value)

        finding = {
            "line": filtered_finding.line_number,
            "var_name": filtered_finding.var_name,
            "file": str(filtered_finding.file_path),
            "rule_id": filtered_finding.rule_id,
            "rule": filtered_finding.rule_name,
            "severity": filtered_finding.severity,
            "value": value,
            "reason": filtered_finding.reason,
        }
        json_results.append(finding)

    print(json.dumps(json_results, indent=2))


def output(filtered_findings, use_json, redact_secrets, files):
    """
    Print scan results as JSON or human-readable CLI output.

    Args:
        filtered_findings (list[Finding]): Findings after optional filtering.
        use_json (bool): Whether to output valid JSON only.
        redact_secrets (bool): Whether to redact detected values.
        files (list[Path]): Python files included in the scan.

    Returns:
        None
    """
    if use_json:
        output_json(filtered_findings, redact_secrets)
        return

    print(f"Scanning {len(files)} Python files...")

    if not filtered_findings:
        print("\nNo vulnerabilities found.")
    else:
        print("\n--- Findings ---\n")

        for finding in filtered_findings:
            display_value = finding.value
            if redact_secrets:
                display_value = redact_value(display_value)

            print(
                f"[{finding.severity}] "
                f"{finding.file_path}:{finding.line_number} "
                f"{finding.rule_name} → {display_value}"
            )
            print(f"       Reason: {finding.reason}\n")

        print(f"\nTotal findings: {len(filtered_findings)}")