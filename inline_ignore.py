import io
import tokenize


INLINE_IGNORE_MARKER = "sentinelscan: ignore"


def line_has_inline_ignore(line):
    """
    Return True when a source line contains a SentinelScan inline ignore comment.

    Only comment tokens are checked, so string literals containing the ignore
    marker do not suppress findings.
    """
    try:
        tokens = tokenize.generate_tokens(io.StringIO(line).readline)
    except tokenize.TokenError:
        return False

    for token in tokens:
        token_type = token.type
        token_value = token.string

        if token_type == tokenize.COMMENT and INLINE_IGNORE_MARKER in token_value:
            return True

    return False
    

