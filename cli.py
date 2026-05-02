"""
Command-line interface (CLI) configuration for SentinelScan.

Parses user input to retrieve the target directory path, output format,
and optional severity filter for scanning.
"""

import argparse

# Initialize argument parser for CLI input
parser = argparse.ArgumentParser(
    description="Scan a directory for hardcoded secrets in Python files"
)

# Define required positional argument for the target directory
parser.add_argument("path", help="Path to the directory to scan")

# Enable machine-readable JSON output when present
parser.add_argument("--json", action="store_true", help="Output findings as JSON")

# Optionally filter displayed findings by severity level
parser.add_argument(
    "--severity",
    choices=["LOW", "MEDIUM", "HIGH"],
    help="Only show findings matching the selected severity",
)

# Parse command-line arguments
args = parser.parse_args()

# Extract parsed CLI values for use by the application
input_path = args.path
use_json = args.json
chosen_severity = args.severity
