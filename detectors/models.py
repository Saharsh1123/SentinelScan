"""
Shared dataclass models used by SentinelScan.

The detection pipeline uses `Candidate` objects as rule-engine inputs and
`Finding` objects as confirmed matches. `SkippedFile` is a separate diagnostic
channel for files that could not be analyzed safely.
"""

import re
from dataclasses import dataclass, field


@dataclass(kw_only=True, frozen=True)
class Rule:
    """
    Define one detection rule used by the rule engine.

    Rules may match suspicious variable names, specific value formats, or both.
    """

    rule_id: str
    rule_name: str
    severity: str
    reason: str
    var_patterns: list[re.Pattern] = field(default_factory=list)
    value_pattern: re.Pattern | None = None
    min_length: int | None = None


@dataclass(kw_only=True)
class Candidate:
    """
    Represent extracted source-code data that may be suspicious.

    Candidates are not confirmed vulnerabilities. They are normalized inputs for
    the rule engine.
    """

    line_number: int
    var_name: str
    value: str


@dataclass(kw_only=True)
class Finding:
    """
    Represent a confirmed rule match.

    Findings are produced by the rule engine and later enriched with file path
    information by the scanner.
    """

    file_path: str | None = None
    line_number: int
    var_name: str | None = None
    value: str
    rule_id: str
    rule_name: str
    severity: str
    reason: str
    entropy: int | float | None = None
    confidence: str


@dataclass(kw_only=True)
class SkippedFile:
    """Describe a file SentinelScan could not read or parse safely."""

    path: str | None = None
    reason: str
    message: str
