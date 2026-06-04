"""
Configuration loading and validation for SentinelScan.

The config loader reads optional `sentinelscan.json` files, validates supported
settings, and returns a `ScannerConfig` object with defaults filled in for
missing fields.
"""

import json
from pathlib import Path

from config.config_model import ScannerConfig

CONFIG_FILE_NAME = "sentinelscan.json"
VALID_LEVELS = {"LOW", "MEDIUM", "HIGH"}
VALID_OUTPUT_FORMATS = {"text", "json"}


def _validate_level(field_name, value):
    """
    Validate a severity or confidence level from config.

    Args:
        field_name (str): Config field being validated.
        value (object): Config value to validate.

    Returns:
        str: Validated level.

    Raises:
        ValueError: If the value is not a supported string level.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")

    normalized = value.upper()
    if normalized not in VALID_LEVELS:
        raise ValueError(
            f"{field_name} must be one of: {', '.join(sorted(VALID_LEVELS))}"
        )

    return normalized


def _validate_output_format(value):
    """
    Validate the configured output format.

    Args:
        value (object): Config value to validate.

    Returns:
        str: Validated output format.

    Raises:
        ValueError: If the value is not a supported output format.
    """
    if not isinstance(value, str):
        raise ValueError("output_format must be a string")

    normalized = value.lower()
    if normalized not in VALID_OUTPUT_FORMATS:
        raise ValueError(
            "output_format must be one of: "
            f"{', '.join(sorted(VALID_OUTPUT_FORMATS))}"
        )

    return normalized


def _validate_redact(value):
    """
    Validate the configured redaction setting.

    Args:
        value (object): Config value to validate.

    Returns:
        bool: Validated redaction setting.

    Raises:
        ValueError: If the value is not a boolean.
    """
    if not isinstance(value, bool):
        raise ValueError("redact must be a boolean")

    return value


def _config_path(scan_path=None):
    """
    Resolve the config file path.

    If a scan path is provided, SentinelScan looks for `sentinelscan.json` in
    that scan root. Otherwise, it looks in the current working directory.

    Args:
        scan_path (str | Path | None): Optional directory being scanned.

    Returns:
        Path: Candidate config file path.
    """
    if scan_path is None:
        return Path(CONFIG_FILE_NAME)

    return Path(scan_path) / CONFIG_FILE_NAME


def get_config(scan_path=None):
    """
    Load SentinelScan configuration from an optional JSON config file.

    Missing config files fall back to `ScannerConfig` defaults. Partial config
    files are allowed; missing fields keep their default values. Unknown keys
    are ignored for forward compatibility.

    Args:
        scan_path (str | Path | None): Optional scan root to search for
            `sentinelscan.json`. If omitted, the current working directory is
            used.

    Returns:
        ScannerConfig: Validated scanner configuration.

    Raises:
        json.JSONDecodeError: If the config file is not valid JSON.
        ValueError: If a supported config field has an invalid type or value.
    """
    path = _config_path(scan_path)
    if not path.exists():
        return ScannerConfig()

    with open(path, "r", encoding="utf-8") as f:
        raw_config = json.load(f)

    if not isinstance(raw_config, dict):
        raise ValueError("sentinelscan.json must contain a JSON object")

    scanner_config = ScannerConfig()

    if "min_confidence" in raw_config:
        scanner_config.min_confidence = _validate_level(
            "min_confidence",
            raw_config["min_confidence"],
        )

    if "min_severity" in raw_config:
        scanner_config.min_severity = _validate_level(
            "min_severity",
            raw_config["min_severity"],
        )

    if "redact" in raw_config:
        scanner_config.redact = _validate_redact(raw_config["redact"])

    if "output_format" in raw_config:
        scanner_config.output_format = _validate_output_format(
            raw_config["output_format"]
        )

    return scanner_config
