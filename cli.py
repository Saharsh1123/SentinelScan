"""
Command-line interface (CLI) configuration for SentinelScan.

Parses user input to retrieve the target directory path for scanning.
"""

import argparse

# Initialize argument parser for CLI input
parser = argparse.ArgumentParser(
    description="Scan a directory for hardcoded secrets in Python files"
)

# Define required positional argument for target path
parser.add_argument(
    "path",
    help="Path to the directory to scan"
)

# Parse command-line arguments
args = parser.parse_args()

# Extract the input path for use in the application
input_path = args.path

