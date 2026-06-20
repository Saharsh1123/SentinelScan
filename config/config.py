"""
Configuration loading and validation for SentinelScan.

The loader reads an optional `sentinelscan.json`, validates severity,
confidence, and output-format fields, and returns a `ScannerConfig` with
defaults filled in for missing values. Secret disclosure is not configurable.

Config lookup order:
1. scan_path/sentinelscan.json, if a scan path is provided and the file exists
2. ./sentinelscan.json from the current working directory
3. ScannerConfig defaults if neither file exists
"""

import json
from pathlib import Path

from config.config_model import ScannerConfig, VALID_LEVELS, VALID_OUTPUT_FORMATS
from exceptions import ExpectedUserError

CONFIG_FILE_NAME = "sentinelscan.json"

_LEVEL_SET = set(VALID_LEVELS)
_OUTPUT_FORMAT_SET = set(VALID_OUTPUT_FORMATS)


def _validate_levels(field_name, value):
    """
    Validate a severity or confidence level list from config.

    Args:
        field_name (str): Config field being validated.
        value (object): Raw JSON value to validate.

    Returns:
        list[str]: Validated uppercase levels.

    Raises:
        ValueError: If the value is not a non-empty list containing only
            supported level strings.
    """
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")

    if not value:
        raise ValueError(f"{field_name} must contain at least one level")

    normalized_levels = []

    for level in value:
        if not isinstance(level, str):
            raise ValueError(f"{field_name} entries must be strings")

        normalized = level.upper()

        if normalized not in _LEVEL_SET:
            raise ValueError(
                f"{field_name} entries must be one of: "
                f"{', '.join(sorted(_LEVEL_SET))}"
            )

        normalized_levels.append(normalized)

    return normalized_levels


def _validate_output_format(value):
    """
    Validate the configured output format.

    Args:
        value (object): Raw JSON value to validate.

    Returns:
        str: Validated lowercase output format.

    Raises:
        ValueError: If the value is not a supported output format.
    """
    if not isinstance(value, str):
        raise ValueError("output_format must be a string")

    normalized = value.lower()

    if normalized not in _OUTPUT_FORMAT_SET:
        raise ValueError(
            "output_format must be one of: " f"{', '.join(sorted(_OUTPUT_FORMAT_SET))}"
        )

    return normalized


def _config_path(scan_path=None):
    """
    Resolve the config file path.

    If a scan path is provided, SentinelScan first checks that scan root for
    `sentinelscan.json`. If no scan-root config exists, it falls back to the
    current working directory.

    Args:
        scan_path (str | Path | None): Optional directory being scanned.

    Returns:
        Path | None: Config file path if one exists, otherwise None.
    """
    if scan_path is not None:
        scan_config = Path(scan_path) / CONFIG_FILE_NAME

        if scan_config.exists():
            return scan_config

    cwd_config = Path(CONFIG_FILE_NAME)

    if cwd_config.exists():
        return cwd_config

    return None


def get_config(scan_path=None):
    """
    Load SentinelScan configuration from an optional JSON config file.

    Missing config files fall back to `ScannerConfig` defaults. Partial config
    files are allowed; missing fields keep their default values. Unknown keys
    are ignored for forward compatibility.

    Args:
        scan_path (str | Path | None): Optional scan root to check first for
            `sentinelscan.json`.

    Returns:
        ScannerConfig: Validated scanner configuration.

    Raises:
        json.JSONDecodeError: If the config file is not valid JSON.
        ValueError: If a supported field has an invalid type or value.
    """
    path = _config_path(scan_path)

    if path is None:
        return ScannerConfig()

    with open(path, "r", encoding="utf-8") as f:
        try:
            raw_config = json.load(f)
        except json.JSONDecodeError as e:
            raise ExpectedUserError(
                f"Invalid JSON in config at line {e.lineno}, column {e.colno}: "
                f"{e.msg}"
            ) from e

    if not isinstance(raw_config, dict):
        raise ValueError("sentinelscan.json must contain a JSON object")

    scanner_config = ScannerConfig()

    if "severity_levels" in raw_config:
        scanner_config.severity_levels = _validate_levels(
            "severity_levels",
            raw_config["severity_levels"],
        )

    if "confidence_levels" in raw_config:
        scanner_config.confidence_levels = _validate_levels(
            "confidence_levels",
            raw_config["confidence_levels"],
        )

    # Legacy branch pending removal; plaintext output is intended to be CLI-only.
    if "output_format" in raw_config:
        scanner_config.output_format = _validate_output_format(
            raw_config["output_format"]
        )

    return scanner_config
