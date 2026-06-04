"""
Configuration model for SentinelScan.

`ScannerConfig` represents the final scanner settings after applying built-in
defaults, optional config file values, and explicit CLI overrides.
"""

from dataclasses import dataclass
from typing import Literal


Level = Literal["LOW", "MEDIUM", "HIGH"]
OutputFormat = Literal["text", "json"]


@dataclass
class ScannerConfig:
    """
    Store user-configurable scanner settings.

    `None` for severity or confidence means no filter is applied. This keeps
    default scans broad while allowing config files or CLI flags to narrow
    results when requested.
    """

    min_confidence: Level | None = None
    min_severity: Level | None = None
    redact: bool = False
    output_format: OutputFormat = "text"
