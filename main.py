"""
Entry point for SentinelScan.

Handles CLI input, validates the target path, collects Python files,
and initiates the scanning process. Gracefully handles invalid paths.
"""

from cli import input_path
from scanner import check_path, scan, list_python_files


if __name__ == "__main__":
    try:
        # Validate the provided path and convert it to a Path object
        path = check_path(input_path)

        # Recursively collect all Python files from the directory
        files = list_python_files(path)

        # Execute the scanning process on collected files
        scan(files)

    except FileNotFoundError as e:
        # Handle invalid directory input and display a user-friendly error
        print(f"[ERROR] {e}")


