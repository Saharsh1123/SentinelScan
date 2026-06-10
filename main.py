"""
SentinelScan application entry point.

Coordinates CLI parsing, path validation, config loading, file discovery,
scanning, filtering, and output rendering. Scanner and detector internals stay
in their own modules.
"""

from cli import return_args
from config.config import get_config
from output import filter_results, output
from scanner import check_path, list_python_files, scan

if __name__ == "__main__":
    try:
        args = return_args()

        input_path = args.path
        path = check_path(input_path)
        scanner_config = get_config(path)

        # CLI values override config only when the user explicitly provided them.
        output_format = (
            scanner_config.output_format
            if args.format is None
            else args.format
        )
        redact_secrets = (
            args.redact if args.redact is not None else scanner_config.redact
        )
        chosen_severity = (
            scanner_config.severity_levels if args.severity is None else args.severity
        )
        chosen_confidence = (
            scanner_config.confidence_levels
            if args.confidence is None
            else args.confidence
        )

        files = list_python_files(path)
        results = scan(files)

        filtered_findings = filter_results(results, chosen_severity, chosen_confidence)
        output(filtered_findings, output_format, redact_secrets, files)

    except FileNotFoundError as e:
        # Report invalid paths without showing a traceback.
        print(f"[ERROR] {e}")
