from pathlib import Path
from detectors.find_secrets import detect_secrets


def check_path(input_path):
    """
    Validate that the provided path exists and is a directory.

    Args:
        input_path (str | Path): Path to validate.

    Returns:
        Path: Resolved Path object pointing to a valid directory.

    Raises:
        FileNotFoundError: If the path does not exist or is not a directory.
    """
    path = Path(input_path)

    if path.is_dir():
        return path

    raise FileNotFoundError(
        f"'{input_path}' does not exist or is not a directory!"
    )


def list_python_files(path):
    """
    Recursively collect all Python (.py) files within a directory.

    Args:
        path (Path): Root directory to search.

    Returns:
        list[Path]: List of discovered Python file paths.
    """
    return list(path.rglob("*.py"))


def scan(files):
    """
    Scan Python files for hardcoded secrets using detection rules.

    Iterates through each file line-by-line, applies detection logic,
    and prints findings in a structured CLI format.

    Args:
        files (list[Path]): List of Python files to scan.

    Returns:
        None
    """
    if not files:
        print("No Python files found.")
        return

    print(f"Scanning {len(files)} Python files...")

    total_findings = 0
    files = sorted(files)  # Ensure deterministic output order
    has_findings = False   # Tracks whether any findings were detected

    for file in files:
        # Open file with UTF-8 encoding; ignore decode errors to prevent crashes
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                vulnerabilities = detect_secrets(line)

                if vulnerabilities:
                    # Print header only once when first finding is detected
                    if not has_findings:
                        print("\n--- Findings ---\n")
                        has_findings = True

                    for rule_name, severity, match in vulnerabilities:
                        print(
                            f"[{severity}] "
                            f"{file}:{line_number} "
                            f"{rule_name} detected → {match}"
                        )
                        total_findings += 1

    print(f"\nTotal findings: {total_findings}")