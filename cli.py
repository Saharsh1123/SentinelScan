"""
CLI argument configuration for SentinelScan.

Parses the target scan path and optional output controls.
"""

import argparse


parser = argparse.ArgumentParser(
    description="Scan a directory for hardcoded secrets in Python files"
)

# Required target directory to scan.
parser.add_argument("path", help="Path to the directory to scan")

# Output findings as machine-readable JSON.
parser.add_argument("--json", action="store_true", help="Output findings as JSON")

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
    help="Redact detected secret values",
)

def return_args():
    return parser.parse_args()
