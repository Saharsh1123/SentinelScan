from pathlib import Path
from detectors.find_secrets import detect_secrets


def check_path(input_path):
    """
    Validate that the provided path exists and is a directory.

    Args:
        input_path (str or Path): Path to validate.

    Returns:
        Path: A valid Path object pointing to the directory.

    Raises:
        FileNotFoundError: If the path does not exist or is not a directory.
    """
    path = Path(input_path)
    if path.is_dir():
        return path
    else:
        raise FileNotFoundError(
            f"'{input_path}' does not exist or is not a directory!"
        )


def list_python_files(path):
    """
    Recursively collect all Python (.py) files from a directory.

    Args:
        path (Path): Directory to search.

    Returns:
        list[Path]: List of Python file paths.
    """
    return list(path.rglob("*.py"))


def scan(files):
    """
    Scan a list of Python files for hardcoded secrets using detection rules.

    For each file, reads line-by-line and applies secret detection logic.
    Outputs findings in a structured CLI format with severity levels.

    Args:
        files (list[Path]): List of Python files to scan.

    Returns:
        None
    """
    if not files:
        print("No Python files found.")
        return

    number_of_files = len(files)
    print(f"Scanning {number_of_files} Python files...")

    findings = 0
    files = sorted(files)  # Ensure deterministic output order

    found = False  # Tracks if directory contains any findings

    for file in files:

        # Open file safely with UTF-8 encoding; ignore decode errors to avoid crashes
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                vulnerability = detect_secrets(line)

                if vulnerability is not None:
                    # Print findings header only once (on first detection)
                    if not found:
                        print("\n--- Findings ---\n")

                    # vulnerability = (rule_name, severity)
                    print(
                        f"[{vulnerability[1]}] "
                        f"{file}:{line_number} "
                        f"{vulnerability[0]} detected → {line.rstrip()}"
                    )

                    findings += 1
                    found = True

    print(f"\nTotal findings: {findings}")