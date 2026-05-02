import json


def filter_results(results, chosen_severity):
    """
    Filter scan findings by severity.

    If no severity is provided, all findings are returned unchanged.

    Args:
        results (list[tuple[int, Path, str, str, str]]):
            Findings returned by scan().
        chosen_severity (str | None):
            Severity level to filter by, or None to keep all findings.

    Returns:
        list[tuple[int, Path, str, str, str]]:
            Filtered findings matching the selected severity.
    """
    filtered_findings = []
    for line_number, file, rule_name, severity, value, reason in results:
        if severity == chosen_severity or chosen_severity is None:
            filtered_findings.append((line_number, file, rule_name, severity, value, reason))
    return filtered_findings


def output_json(filtered_findings):
    """
    Output findings in machine-readable JSON format.

    Args:
        filtered_findings (list[tuple[int, Path, str, str, str]]):
            Findings to serialize as JSON.

    Returns:
        None
    """
    json_results = []
    for line_number, file, rule_name, severity, value, reason in filtered_findings:
        finding = {
            "line": line_number,
            "file": str(file),
            "rule": rule_name,
            "severity": severity,
            "value": value,
            "reason": reason,
        }
        json_results.append(finding)
    print(json.dumps(json_results, indent=2))


def output(filtered_findings, use_json, files):
    """
    Display scan results in either JSON or human-readable CLI format.

    JSON mode prints only valid JSON so the output can be consumed by other
    tools. Human-readable mode prints findings with severity, file location,
    extracted value, and a summary count.

    Args:
        filtered_findings (list[tuple[int, Path, str, str, str]]):
            Findings after optional severity filtering.
        use_json (bool): Whether to output results as JSON.
        files (list[Path]): List of scanned Python files.

    Returns:
        None
    """
    if use_json:
        output_json(filtered_findings)
        return

    print(f"Scanning {len(files)} Python files...")

    if not filtered_findings:
        print("\nNo vulnerabilities found.")
    else:
        print("\n--- Findings ---\n")

        for line_number, file, rule_name, severity, value, reason in filtered_findings:
            print(f"[{severity}] {file}:{line_number} {rule_name} → {value}")
            print(f"       Reason: {reason}\n")

        print(f"\nTotal findings: {len(filtered_findings)}")