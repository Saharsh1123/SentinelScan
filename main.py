"""
SentinelScan application entry point.

Coordinates CLI parsing, path validation, file discovery, scanning, filtering,
and output rendering. Scanner and detector internals stay in their own modules.
"""

from cli import return_args
from output import filter_results, output
from scanner import check_path, list_python_files, scan


if __name__ == "__main__":
    try:
        args = return_args()

        # Copy parsed arguments into local names for the scan pipeline.
        input_path = args.path
        use_json = args.json
        redact_secrets = args.redact
        chosen_severity = args.severity
        chosen_confidence = args.confidence

        path = check_path(input_path)
        files = list_python_files(path)
        results = scan(files)

        filtered_findings = filter_results(results, chosen_severity, chosen_confidence)
        output(filtered_findings, use_json, redact_secrets, files)

    except FileNotFoundError as e:
        # Report invalid paths without showing a traceback.
        print(f"[ERROR] {e}")
