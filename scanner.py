from dataclasses import replace
from pathlib import Path

from detectors.find_secrets import detect_ast_secrets
from ignore import filter_ignored_files, load_ignore_patterns
from inline_ignore import finding_has_inline_ignore

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

    Applies .sentinelscanignore patterns if the file exists in the scan root
    or one of its parent directories.
    """
    files = list(path.rglob("*.py"))

    ignore_patterns, ignore_root = load_ignore_patterns(path)

    return filter_ignored_files(files, ignore_root, ignore_patterns)


def scan_file(file):
    result = []

    with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

            ast_results = detect_ast_secrets(content)

            for finding in ast_results:
                line = lines[finding.line_number - 1]
                if finding_has_inline_ignore(line, finding):
                    continue
                finding_with_file = replace(finding, file_path=str(file))
                result.append(finding_with_file)

    return result


def scan(files):
    """
    Scan Python files for hardcoded secrets.

    Reads each file, runs AST-based detection, attaches the source file path
    to each finding, and returns all findings for filtering or output.

    Args:
        files (list[Path]): Python files to scan.

    Returns:
        list[Finding]: Findings detected across all scanned files.
    """
    if not files:
        return []

    findings = []

    files = sorted(files)

    for file in files:
        findings.extend(scan_file(file))
    
    return findings




