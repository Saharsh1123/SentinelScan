import io
import tokenize


INLINE_IGNORE_MARKER = "sentinelscan: ignore"


def finding_has_inline_ignore(line, finding):
    """
    Return True when a source line contains a SentinelScan inline ignore comment.

    Generic ignores suppress all findings on the line.
    Rule-specific ignores suppress only listed rule IDs.
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
    

