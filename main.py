"""
SentinelScan CLI entry point.

This module orchestrates the execution flow of the application:
- Parses user-provided input from the CLI
- Validates the target directory
- Discovers Python files recursively
- Executes the scanning engine
- Applies optional severity filtering
- Outputs results as human-readable text or JSON

Errors related to invalid input paths are handled gracefully.
"""

from cli import input_path, chosen_severity, use_json, redact_secrets
from scanner import check_path, scan, list_python_files
from output import filter_results, output


if __name__ == "__main__":
    try:
        # Validate input path and ensure it is a valid directory
        path = check_path(input_path)

        # Discover all Python files within the target directory
        files = list_python_files(path)

        # Run the scanning engine and collect all findings
        results = scan(files)

        # Apply optional severity filtering before output formatting
        filtered_findings = filter_results(results, chosen_severity)

        # Output results in the selected format
        output(filtered_findings, use_json, redact_secrets, files)

    except FileNotFoundError as e:
        # Display a user-friendly error message for invalid paths
        print(f"[ERROR] {e}")
