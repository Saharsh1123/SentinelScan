"""
Command-line argument parsing for SentinelScan.

This module defines the user-facing CLI flags and returns parsed arguments to
`main.py`. It should not start a scan or depend on scanner internals.
"""

import argparse


parser = argparse.ArgumentParser(
    description="Scan a directory for hardcoded secrets in Python files"
)

# Required target directory to scan.
parser.add_argument("path", help="Path to the directory to scan")

# Output findings as machine-readable JSON.
parser.add_argument("--json", action="store_true", default=None, help="Output findings as JSON")

# Limit displayed findings to a selected severity.
parser.add_argument(
    "--severity",
    choices=["LOW", "MEDIUM", "HIGH"],
    help="Only show findings matching the selected severity",
)

# Limit displayed findings to a selected confidence level.
parser.add_argument(
    "--confidence",
    choices=["LOW", "MEDIUM", "HIGH"],
    help="Only show findings matching the selected confidence level",
)

# Mask detected secret values in text or JSON output.
parser.add_argument(
    "--redact",
    action="store_true",
    default=None,
    help="Redact detected secret values",
)


def return_args():
    """
    Parse and return CLI arguments.

    Returns:
        argparse.Namespace: Parsed CLI options used by the application entry point.
    """
    return parser.parse_args()
