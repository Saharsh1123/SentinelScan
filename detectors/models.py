from dataclasses import dataclass, field
import re


@dataclass(kw_only=True, frozen=True)
class Rule:
    """
    Define a single detection rule used by the rule engine.

    Rules may match either suspicious variable names, structured secret
    values, or both.
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
    Represent a string assignment extracted from source code.

    Candidates are not confirmed findings. They are passed to the rule engine
    for evaluation.
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
    entropy: int | None = None
    confidence: str