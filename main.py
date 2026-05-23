"""
SentinelScan application entry point.

Coordinates CLI input, file discovery, scanning, filtering, and output.
"""

from cli import return_args
from scanner import check_path, scan, list_python_files
from output import filter_results, output


if __name__ == "__main__":
    try:
        args = return_args()

        # Export parsed values for the application entry point.
        input_path = args.path
        use_json = args.json
        redact_secrets = args.redact
        chosen_severity = args.severity
        chosen_confidence = args.confidence  

        # Validate the target directory.
        path = check_path(input_path)

        # Discover Python files to scan.
        files = list_python_files(path)

        # Scan files and collect findings.
        results = scan(files)

        # Apply optional severity filtering.
        filtered_findings = filter_results(results, chosen_severity, chosen_confidence)

        # Render findings as text or JSON, with optional redaction.
        output(filtered_findings, use_json, redact_secrets, files)

    except FileNotFoundError as e:
        # Report invalid paths without showing a traceback.
        print(f"[ERROR] {e}")
