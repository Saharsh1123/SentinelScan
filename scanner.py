from pathlib import Path
from detectors.find_secrets import detect_ast_secrets
import json


def check_path(input_path):
    """
    Validate that the provided path exists and is a directory.

    Args:
        input_path (str | Path): Path to validate.

    Returns:
        Path: A Path object pointing to a valid directory.

    Raises:
        FileNotFoundError: If the path does not exist or is not a directory.
    """
    path = Path(input_path)

    if path.is_dir():
        return path

    raise FileNotFoundError(f"'{input_path}' does not exist or is not a directory!")


def list_python_files(path):
    """
    Recursively discover all Python (.py) files within a directory.

    Args:
        path (Path): Root directory to search.

    Returns:
        list[Path]: List of Python file paths found in the directory tree.
    """
    return list(path.rglob("*.py"))


def scan(files):
    """
    Scan a collection of Python files for hardcoded secrets.

    Each file is read into memory and analyzed using the AST-based detection
    engine. All detected findings are collected and returned for filtering
    and output formatting.

    Args:
        files (list[Path]): List of Python files to scan.

    Returns:
        list[tuple[int, Path, str, str, str]]:
            A list of findings where each finding is a tuple:
                (line_number, file_path, rule_name, severity, matched_value)

        Returns an empty list if no findings are detected or if no files are provided.

    Behavior:
        - Processes files in sorted order for consistent output
        - Ignores encoding errors to prevent scan interruptions
        - Supports multiple detections per file
    """
    if not files:
        print("No Python files found.")
        return []

    files = sorted(files)  # Ensure deterministic output order
    findings = []

    for file in files:
        # Read file content safely before passing it to the AST detector
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

            ast_results = detect_ast_secrets(content)
            for line_number, rule_name, severity, value in ast_results:
                findings.append((line_number, file, rule_name, severity, value))

    return findings


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
    for line_number, file, rule_name, severity, value in results:
        if severity == chosen_severity or chosen_severity is None:
            filtered_findings.append((line_number, file, rule_name, severity, value))
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
    for line_number, file, rule_name, severity, value in filtered_findings:
        finding = {
            "line": line_number,
            "file": str(file),
            "rule": rule_name,
            "severity": severity,
            "value": value,
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

        for line_number, file, rule_name, severity, value in filtered_findings:
            print(f"[{severity}] {file}:{line_number} {rule_name} → {value}")

        print(f"\nTotal findings: {len(filtered_findings)}")
