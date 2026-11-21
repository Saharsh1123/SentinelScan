"""
File discovery and scan orchestration for SentinelScan.

This module validates scan paths, finds Python files, applies file-level ignore
rules, scans each file, suppresses inline-ignored findings, and aggregates
security findings separately from structured skipped-file diagnostics.
"""

import tokenize
from dataclasses import replace
from pathlib import Path

from sentinelscan.detectors.find_secrets import detect_ast_secrets
from sentinelscan.detectors.models import SkippedFile
from sentinelscan.exceptions import ExpectedUserError
from sentinelscan.ignore import filter_ignored_files, load_ignore_patterns
from sentinelscan.inline_ignore import finding_has_inline_ignore


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
    Scan one Python file for findings or a recoverable skip condition.

    Python-aware decoding happens before AST analysis. Expected decoding,
    encoding-declaration, and file-system read failures become `SkippedFile`
    records so repository scanning can continue. Inline ignores are checked
    against the original source line after findings are produced.

    Args:
        file (Path): Python file to scan.

    Returns:
        tuple[list[Finding], list[SkippedFile]]: Findings and skipped-file
            diagnostics, with the file path attached to each result.
    """
    findings = []
    skipped_files = []

    try:
        with tokenize.open(file) as source:
            content = source.read()
    except UnicodeDecodeError as error:
        skipped_files.append(
            SkippedFile(
                path=str(file),
                reason="encoding_error",
                message=str(error),
            )
        )
        return findings, skipped_files
    except SyntaxError as error:
        # tokenize.open raises SyntaxError for invalid encoding declarations.
        skipped_files.append(
            SkippedFile(
                path=str(file),
                reason="encoding_error",
                message=str(error),
            )
        )
        return findings, skipped_files
    except OSError as error:
        skipped_files.append(
            SkippedFile(
                path=str(file),
                reason="io_error",
                message=str(error),
            )
        )
        return findings, skipped_files

    lines = content.splitlines()
    detected_findings, skipped_file = detect_ast_secrets(content)

    for finding in detected_findings:
        line = lines[finding.line_number - 1]
        if finding_has_inline_ignore(line, finding):
            continue

        findings.append(replace(finding, file_path=str(file)))

    if skipped_file is not None:
        skipped_files.append(replace(skipped_file, path=str(file)))

    return findings, skipped_files


def scan(files):
    """
    Scan Python files while keeping findings and skipped files separate.

    Args:
        files (list[Path]): Python files to scan.

    Returns:
        tuple[list[Finding], list[SkippedFile]]: Flat aggregated lists in
            deterministic file-path order.
    """
    findings = []
    skipped_files = []

    for file in sorted(files):
        file_findings, file_skips = scan_file(file)
        findings.extend(file_findings)
        skipped_files.extend(file_skips)

    return findings, skipped_files
