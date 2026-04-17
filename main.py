"""
SentinelScan CLI entry point.

This module orchestrates the execution flow of the application:
- Parses user-provided input from the CLI
- Validates the target directory
- Discovers Python files recursively
- Executes the scanning engine
- Outputs formatted results to the console

Errors related to invalid input paths are handled gracefully.
"""

from cli import input_path
from scanner import check_path, scan, list_python_files, output


if __name__ == "__main__":
    try:
        # Validate input path and ensure it is a valid directory
        path = check_path(input_path)

        # Discover all Python files within the target directory
        files = list_python_files(path)

        # Run the scanning engine and collect findings
        results = scan(files)

        # Output results to the CLI
        output(results)

    except FileNotFoundError as e:
        # Display a user-friendly error message for invalid paths
        print(f"[ERROR] {e}")


