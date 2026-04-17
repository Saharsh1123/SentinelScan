from pathlib import Path
from detectors.find_secrets import detect_secrets


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

    raise FileNotFoundError(
        f"'{input_path}' does not exist or is not a directory!"
    )


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

    Each file is read line-by-line and analyzed using the detection engine.
    All detected findings are collected and returned for further processing.

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
        - Supports multiple detections per line
    """
    if not files:
        print("No Python files found.")
        return []

    print(f"Scanning {len(files)} Python files...")

    files = sorted(files)  # Ensure deterministic output order
    findings = []

    for file in files:
        # Open file safely with UTF-8 encoding; ignore decode errors
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                vulnerabilities = detect_secrets(line)

                if vulnerabilities:
                    for rule_name, severity, match in vulnerabilities:
                        findings.append(
                            (line_number, file, rule_name, severity, match)
                        )

    return findings


def output(results):
    """
    Display scan results in a structured CLI format.

    Prints all detected findings with severity, file location, and extracted value.
    Also outputs a summary count of total findings.

    Args:
        results (list[tuple[int, Path, str, str, str]]):
            List of findings returned by the scan() function.

    Returns:
        None
    """
    if not results:
        print("\nNo vulnerabilities found.")
    else:
        print("\n--- Findings ---\n")

        for line_number, file, rule_name, severity, match in results:
            print(
                f"[{severity}] "
                f"{file}:{line_number} "
                f"{rule_name} → {match}"
            )

    print(f"\nTotal findings: {len(results)}")