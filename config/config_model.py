"""
Configuration data model for SentinelScan.

This module defines the final scanner settings used by the application after
built-in defaults, optional `sentinelscan.json` values, and explicit CLI
overrides are merged.
"""

from dataclasses import dataclass, field
from typing import Literal

Level = Literal["LOW", "MEDIUM", "HIGH"]
OutputFormat = Literal["text", "json"]

VALID_LEVELS: tuple[Level, ...] = ("LOW", "MEDIUM", "HIGH")
VALID_OUTPUT_FORMATS: tuple[OutputFormat, ...] = ("text", "json")


def _default_levels() -> list[Level]:
    """
    Return a fresh list of all supported levels.

    A function is used so each `ScannerConfig` instance receives its own list.
    """
    return list(VALID_LEVELS)


@dataclass
class ScannerConfig:
    """
    Store user-configurable scanner settings.

    Severity and confidence fields are explicit allow-lists. By default, all
    levels are included so scans show every finding unless config or CLI options
    narrow the result set.
    """

    severity_levels: list[Level] = field(default_factory=_default_levels)
    confidence_levels: list[Level] = field(default_factory=_default_levels)
    redact: bool = False
    output_format: OutputFormat = "text"
