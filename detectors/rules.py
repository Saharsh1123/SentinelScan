"""
Built-in detection rules for SentinelScan.

Rules are declarative configuration objects consumed by the rule engine. Each
rule defines matching criteria, severity, and the explanation shown in output.
"""

import re

from detectors.models import Rule

# Detect AWS access keys by value format, regardless of variable name.
AWS_ACCESS_KEY = Rule(
    rule_id="AWS_ACCESS_KEY",
    rule_name="AWS Access Key",
    severity="HIGH",
    reason="value matched AKIA-prefixed AWS access key pattern",
    value_pattern=re.compile(r"(AKIA[0-9A-Z]{16})"),
)

# Detect password-like variable names with string values above the length threshold.
PASSWORD = Rule(
    rule_id="PASSWORD",
    rule_name="Password",
    severity="HIGH",
    reason="variable name matched password/pwd/passwd pattern and value met minimum length",
    var_patterns=[
        re.compile(r"password", re.IGNORECASE),
        re.compile(r"pwd", re.IGNORECASE),
        re.compile(r"passwd", re.IGNORECASE),
    ],
    min_length=4,
)

# Detect API key variable names with string values above the length threshold.
API_KEY = Rule(
    rule_id="API_KEY",
    rule_name="API Key",
    severity="HIGH",
    reason="variable name matched api_key/apikey pattern and value met minimum length",
    var_patterns=[
        re.compile(r"api_key", re.IGNORECASE),
        re.compile(r"apikey", re.IGNORECASE),
    ],
    min_length=4,
)

# Detect token variable names with string values above the length threshold.
TOKEN = Rule(
    rule_id="TOKEN",
    rule_name="Token",
    severity="MEDIUM",
    reason="variable name matched token pattern and value met minimum length",
    var_patterns=[re.compile(r"token", re.IGNORECASE)],
    min_length=4,
)

# Detect generic secret variable names with string values above the length threshold.
SECRET = Rule(
    rule_id="SECRET",
    rule_name="Secret",
    severity="MEDIUM",
    reason="variable name matched secret pattern and value met minimum length",
    var_patterns=[re.compile(r"secret", re.IGNORECASE)],
    min_length=4,
)


# Rules are evaluated in order. This order is intentionally tested because a
# single candidate may match multiple rules.
RULES = [
    AWS_ACCESS_KEY,
    PASSWORD,
    API_KEY,
    TOKEN,
    SECRET,
]
