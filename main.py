"""
SentinelScan application entry point.

Coordinates CLI parsing, path validation, config loading, file discovery,
scanning, filtering, and output rendering. Scanner and detector internals stay
in their own modules.
"""

import sys
from cli import return_args
from config.config import get_config
from output import filter_results, output
from scanner import check_path, list_python_files, scan
from exit_codes import ExitCode
from exceptions import ExpectedUserError


def main() -> int:
    try:
        args = return_args()

        input_path = args.path
        path = check_path(input_path)
        scanner_config = get_config(path)

        # Supported CLI settings override config only when explicitly provided.
        output_format = (
            scanner_config.output_format if args.format is None else args.format
        )
        # Plaintext secret display is a runtime-only, explicit unsafe opt-in.
        show_secrets = (
            args.unsafe_show_secrets
            if args.unsafe_show_secrets is not None
            else scanner_config.show_secrets
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
        output(filtered_findings, output_format, show_secrets, files, path)

        if filtered_findings:
            return ExitCode.FINDINGS

        return ExitCode.SUCCESS

    except ExpectedUserError as e:
        # Report invalid paths without showing a traceback.
        print(f"[ERROR] {e}", file=sys.stderr)
        return ExitCode.INVALID_USAGE

    except Exception as e:
        print(f"[INTERNAL ERROR] {e}", file=sys.stderr)
        return ExitCode.INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
