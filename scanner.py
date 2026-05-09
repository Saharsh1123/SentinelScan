from dataclasses import replace
from pathlib import Path

from detectors.find_secrets import detect_ast_secrets


def check_path(input_path):
    """
    Validate that the provided path exists and is a directory.

    Args:
        input_path (str | Path): Path to validate.

    Returns:
        Path: Valid directory path.

    Raises:
        FileNotFoundError: If the path does not exist or is not a directory.
    """
    path = Path(input_path)

    if path.is_dir():
        return path

    raise FileNotFoundError(f"'{input_path}' does not exist or is not a directory!")


def list_python_files(path):
    """
    Recursively find Python files within a directory.

    Args:
        path (Path): Root directory to search.

    Returns:
        list[Path]: Python files discovered under the root directory.
    """
    return list(path.rglob("*.py"))


def scan(files):
    """
    Scan Python files for hardcoded secrets.

    Reads each file, runs AST-based detection, attaches the source file path
    to each finding, and returns all findings for filtering or output.

    Args:
        files (list[Path]): Python files to scan.

    Returns:
        list[Finding]: Findings detected across all scanned files.

    Behavior:
        - Processes files in sorted order for deterministic output
        - Ignores encoding errors to avoid scan interruptions
        - Supports multiple findings per file
    """
    if not files:
        print("No Python files found.")
        return []

    files = sorted(files)
    findings = []

    for file in files:
        # Read file content safely before passing it to the AST detector.
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        ast_results = detect_ast_secrets(content)

        for finding in ast_results:
            # Attach file context at the scanner layer, where file paths are known.
            finding_with_file = replace(finding, file_path=str(file))
            findings.append(finding_with_file)

    return findings



