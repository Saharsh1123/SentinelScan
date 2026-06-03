"""
Inline ignore support for SentinelScan findings.

Inline ignores are parsed from Python comments using `tokenize`, so ignore
markers inside string literals do not suppress findings accidentally.
"""

import io
import tokenize


INLINE_IGNORE_MARKER = "sentinelscan: ignore"


def finding_has_inline_ignore(line, finding):
    """
    Return True when a source line suppresses a finding.

    Generic ignores suppress all findings on the line:
        # sentinelscan: ignore

    Rule-specific ignores suppress only listed rule IDs:
        # sentinelscan: ignore AWS_ACCESS_KEY API_KEY

    Args:
        line (str): Source line containing the finding.
        finding (Finding): Finding being checked for suppression.

    Returns:
        bool: True if the finding should be ignored.
    """
    try:
        tokens = tokenize.generate_tokens(io.StringIO(line).readline)
    except tokenize.TokenError:
        return False

    for token in tokens:
        token_type = token.type
        token_value = token.string

        if token_type != tokenize.COMMENT:
            continue

        if INLINE_IGNORE_MARKER not in token_value:
            continue

        after_ignore = token_value.partition(INLINE_IGNORE_MARKER)[2].strip()
        ignored_rules = after_ignore.split()

        if not ignored_rules:
            return True

        if finding.rule_id in ignored_rules:
            return True

    return False
