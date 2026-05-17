from fnmatch import fnmatch
from pathlib import Path


IGNORE_FILE_NAME = ".sentinelscanignore"


def find_ignore_file(start_path):
    """
    Find .sentinelscanignore in the scan path or one of its parent directories.

    Returns:
        tuple[Path | None, Path | None]:
            (ignore_file, ignore_root), or (None, None) if not found.
    """
    start_path = Path(start_path).resolve()

    for directory in [start_path, *start_path.parents]:
        ignore_file = directory / IGNORE_FILE_NAME

        if ignore_file.is_file():
            return ignore_file, directory

    return None, None


def load_ignore_patterns(start_path):
    """
    Load ignore patterns from .sentinelscanignore.

    Returns:
        tuple[list[str], Path | None]:
            Ignore patterns and the directory where the ignore file was found.
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
    Return True if a file matches any ignore pattern.
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
    Remove files that match .sentinelscanignore patterns.
    """
    kept_files = []

    for file_path in files:
        if should_ignore(file_path, ignore_root, patterns):
            continue

        kept_files.append(file_path)

    return kept_files
        


    
    
        



