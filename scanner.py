from pathlib import Path
from detectors.find_secrets import detect_ast_secrets
from dataclasses import replace

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
            for finding in ast_results:
                finding_with_file = replace(finding, file_path=str(file))
                findings.append(finding_with_file)

    return findings



