"""
File discovery and scan orchestration for SentinelScan.

This module validates scan paths, finds Python files, applies file-level ignore
rules, scans each file, suppresses inline-ignored findings, and attaches file
paths to findings returned by the detector layer.
"""

from dataclasses import replace
from pathlib import Path

from detectors.find_secrets import detect_ast_secrets
from ignore import filter_ignored_files, load_ignore_patterns
from inline_ignore import finding_has_inline_ignore
from exceptions import ExpectedUserError


def check_path(input_path):
    """
    Validate that the provided path exists and is a directory.

    Args:
        input_path (str | Path): Path to validate.

    Returns:
        Path: Valid directory path.

    Raises:
        ExpectedUserError: If the path does not exist or is not a directory.
    """
    path = Path(input_path)

    if path.is_dir():
        return path

    raise ExpectedUserError(f"'{input_path}' does not exist or is not a directory")


def list_python_files(path):
    """
    Recursively find Python files under a scan root.

    If a `.sentinelscanignore` file exists in the scan root or one of its parent
    directories, matching files are removed before scanning.

    Args:
        path (Path): Valid directory to scan.

    Returns:
        list[Path]: Python files that are not ignored.
    """
    files = list(path.rglob("*.py"))
    ignore_patterns, ignore_root = load_ignore_patterns(path)

    return filter_ignored_files(files, ignore_root, ignore_patterns)


def scan_file(file):
    """
    Scan one Python file and return findings from that file.

    Detection runs on the full source text so AST parsing can preserve source
    structure. Inline ignores are checked against the original source line after
    findings are produced.

    Args:
        file (Path): Python file to scan.

    Returns:
        list[Finding]: Findings detected in the file, with file path attached.
    """
    findings = []

    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    lines = content.splitlines()
    ast_results = detect_ast_secrets(content)

    for finding in ast_results:
        line = lines[finding.line_number - 1]
        if finding_has_inline_ignore(line, finding):
            continue

        finding_with_file = replace(finding, file_path=str(file))
        findings.append(finding_with_file)

    return findings


def scan(files):
    """
    Scan Python files for hardcoded secrets.

    Args:
        files (list[Path]): Python files to scan.

    Returns:
        list[Finding]: Flat list of findings detected across all files.
    """
    if not files:
        return []

    findings = []

    for file in sorted(files):
        findings.extend(scan_file(file))

    return findings
