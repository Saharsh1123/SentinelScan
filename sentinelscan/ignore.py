"""
File-level ignore support for SentinelScan.

SentinelScan uses a `.sentinelscanignore` file to skip files before scanning.
The syntax is intentionally small and similar to common ignore files: blank
lines and comments are ignored, directory patterns are supported, and glob-style
filename/path patterns are matched against discovered files.
"""

from fnmatch import fnmatch
from pathlib import Path

IGNORE_FILE_NAME = ".sentinelscanignore"


def find_ignore_file(start_path):
    """
    Find `.sentinelscanignore` in the scan path or one of its parent directories.

    Args:
        start_path (str | Path): Scan path used as the search starting point.

    Returns:
        tuple[Path | None, Path | None]: Ignore file path and the directory that
        owns it, or `(None, None)` if no ignore file is found.
    """
    start_path = Path(start_path).resolve()

    for directory in [start_path, *start_path.parents]:
        ignore_file = directory / IGNORE_FILE_NAME

        if ignore_file.is_file():
            return ignore_file, directory

    return None, None


def load_ignore_patterns(start_path):
    """
    Load ignore patterns from the nearest `.sentinelscanignore` file.

    Blank lines and comment lines are skipped. Patterns are returned exactly as
    configured except for surrounding whitespace.

    Args:
        start_path (str | Path): Scan path used to locate the ignore file.

    Returns:
        tuple[list[str], Path | None]: Ignore patterns and their root directory.
    """
    ignore_file, ignore_root = find_ignore_file(start_path)

    if ignore_file is None:
        return [], None

    patterns = []

    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        pattern = line.strip()

        if not pattern:
            continue

        if pattern.startswith("#"):
            continue

        patterns.append(pattern)

    return patterns, ignore_root


def should_ignore(file_path, ignore_root, patterns):
    """
    Return True when a file matches any configured ignore pattern.

    Args:
        file_path (str | Path): Candidate file path.
        ignore_root (Path | None): Directory that owns the ignore patterns.
        patterns (list[str]): Loaded ignore patterns.

    Returns:
        bool: True if the file should be skipped.
    """
    if not patterns or ignore_root is None:
        return False

    file_path = Path(file_path).resolve()
    ignore_root = Path(ignore_root).resolve()

    relative_path = file_path.relative_to(ignore_root)
    relative_path_str = relative_path.as_posix()
    path_parts = relative_path.parts

    for pattern in patterns:
        pattern = pattern.strip().replace("\\", "/")

        # Directory patterns skip everything below the matching directory.
        if pattern.endswith("/"):
            directory_pattern = pattern.rstrip("/")

            if "/" in directory_pattern:
                if (
                    relative_path_str == directory_pattern
                    or relative_path_str.startswith(directory_pattern + "/")
                ):
                    return True
            elif directory_pattern in path_parts[:-1]:
                return True

            continue

        if fnmatch(relative_path_str, pattern):
            return True

        if fnmatch(file_path.name, pattern):
            return True

    return False


def filter_ignored_files(files, ignore_root, patterns):
    """
    Remove files that match `.sentinelscanignore` patterns.

    Args:
        files (list[Path]): Discovered Python files.
        ignore_root (Path | None): Directory that owns the ignore patterns.
        patterns (list[str]): Loaded ignore patterns.

    Returns:
        list[Path]: Files that should still be scanned.
    """
    kept_files = []

    for file_path in files:
        if should_ignore(file_path, ignore_root, patterns):
            continue

        kept_files.append(file_path)

    return kept_files
