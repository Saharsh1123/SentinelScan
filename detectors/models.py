from dataclasses import dataclass, field
import re

@dataclass(kw_only=True, frozen=True)
class Rule:
    rule_id: str
    rule_name: str
    severity: str
    reason: str
    var_patterns: list[re.Pattern] = field(default_factory=list)
    value_pattern: re.Pattern | None = None
    min_length: int | None = None

@dataclass(kw_only=True)
class Candidate:
    line_number: int
    var_name: str
    value: str

@dataclass(kw_only=True)
class Finding:
    file_path: str | None = None
    line_number: int
    var_name: str | None = None
    value: str
    rule_id: str
    rule_name: str
    severity: str
    reason: str