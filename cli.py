"""
Command-line argument parsing for SentinelScan.

This module defines user-facing CLI flags and returns parsed arguments to
`main.py`. It should not start scans or depend on scanner internals.
"""

import argparse

from config.config_model import VALID_LEVELS, VALID_OUTPUT_FORMATS

parser = argparse.ArgumentParser(
    description="Scan a directory for hardcoded secrets in Python files"
)

# Required target directory to scan.
parser.add_argument("path", help="Path to the directory to scan")

# Select human-readable text, JSON, or SARIF output.
parser.add_argument(
    "--format",
    choices=VALID_OUTPUT_FORMATS,
    type=str.lower,
    default=None,
    help="Output format: text, json, or sarif",
)

# Keep only findings whose severity is in the selected exact level list.
parser.add_argument(
    "--severity",
    nargs="+",
    choices=VALID_LEVELS,
    type=str.upper,
    default=None,
    help="Only show findings matching one or more selected severities",
)

# Keep only findings whose confidence is in the selected exact level list.
parser.add_argument(
    "--confidence",
    nargs="+",
    choices=VALID_LEVELS,
    type=str.upper,
    default=None,
    help="Only show findings matching one or more selected confidence levels",
)

# Mask detected secret values in text or JSON; SARIF omits values entirely.
parser.add_argument(
    "--redact",
    action="store_true",
    default=None,
    help="Redact detected secret values",
)


def return_args():
    """
    Parse and return CLI arguments.

    Boolean flags default to `None` when absent so config file values can apply
    unless the user explicitly provides a CLI override.

    Returns:
        argparse.Namespace: Parsed CLI options used by the application entry
            point.
    """
    return parser.parse_args()
