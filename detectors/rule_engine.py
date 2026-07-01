"""
Rule evaluation for extracted candidates.

The rule engine is intentionally separate from AST extraction. It receives
candidate values, applies built-in rules and conservative name-context checks,
and returns structured findings.
"""

import re

from detectors.confidence import calculate_confidence, calculate_entropy
from detectors.models import Finding
from detectors.rules import RULES

DIRECT_NEGATION_TOKENS = {
    "no",
    "without",
    "non",
}


ABSENCE_STATE_TOKENS = {
    "missing",
    "absent",
    "unset",
    "empty",
    "blank",
    "none",
    "null",
    "omitted",
    "undefined",
    "uninitialized",
    "unavailable",
}


NOT_ABSENCE_STATE_TOKENS = {
    "set",
    "present",
    "provided",
    "required",
    "needed",
    "configured",
    "defined",
    "available",
    "assigned",
    "used",
    "supplied",
    "specified",
    "initialized",
}


LOW_CONFIDENCE_TOKENS = {
    "test",
    "example",
    "sample",
    "dummy",
    "fake",
    "placeholder",
    "default",
    "temp",
}


IGNORED_CONTEXT_TOKENS = {
    "a",
    "an",
    "the",
    "any",
    "is",
    "was",
    "currently",
}


COMPOUND_SECRET_TOKENS = {
    "access",
    "api",
    "auth",
    "authentication",
    "bearer",
    "client",
    "credential",
    "database",
    "db",
    "private",
    "public",
    "refresh",
    "service",
    "session",
    "signing",
    "user",
    "value",
}


def split_identifier(name):
    """
    Split an identifier into lowercase semantic tokens.

    Supports snake_case, camelCase, PascalCase, acronym boundaries, and
    non-alphanumeric delimiters.

    Examples:
        not_password -> ["not", "password"]
        notPassword -> ["not", "password"]
        APIKeyMissing -> ["api", "key", "missing"]

    Args:
        name (str): Variable name or matched rule alias.

    Returns:
        list[str]: Ordered lowercase name tokens.
    """
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)

    return [token.lower() for token in re.split(r"[^A-Za-z0-9]+", name) if token]


def find_matching_token_spans(name_tokens, matched_tokens):
    """
    Find token ranges that represent a matched rule alias.

    Joining adjacent tokens allows names such as `api_key` and `apikey` to
    represent the same matched alias.

    Args:
        name_tokens (list[str]): Ordered tokens from the candidate name.
        matched_tokens (list[str]): Ordered tokens from the matched alias.

    Returns:
        list[tuple[int, int]]: Start-inclusive and end-exclusive token ranges.
    """
    target = "".join(matched_tokens)
    spans = []

    if not target:
        return spans

    for start in range(len(name_tokens)):
        combined = ""

        for end in range(start, len(name_tokens)):
            combined += name_tokens[end]

            if combined == target:
                spans.append((start, end + 1))
                break

            if len(combined) >= len(target):
                break

    return spans


def remove_compound_secret_tokens(tokens, *, from_end):
    """
    Remove adjacent qualifiers that belong to a compound secret name.

    This lets an absence modifier apply to names such as `access_token` even
    when a rule matches only the final `token` component.

    Args:
        tokens (list[str]): Context tokens before or after a matched alias.
        from_end (bool): Remove qualifiers from the end instead of the start.

    Returns:
        list[str]: Context tokens with adjacent secret qualifiers removed.
    """
    remaining = list(tokens)

    if from_end:
        while remaining and remaining[-1] in COMPOUND_SECRET_TOKENS:
            remaining.pop()
    else:
        while remaining and remaining[0] in COMPOUND_SECRET_TOKENS:
            remaining.pop(0)

    return remaining


def is_absence_context(name_tokens, start, end):
    """
    Determine whether a matched secret name is explicitly described as absent.

    Adjacent compound-name qualifiers are ignored when locating the modifier,
    so `missing_access_token` is treated like `missing_token`. Unknown or
    ambiguous wording continues to produce a finding.

    Args:
        name_tokens (list[str]): Ordered tokens from the candidate name.
        start (int): Start index of the matched secret-name tokens.
        end (int): End-exclusive index of the matched secret-name tokens.

    Returns:
        bool: True when the matched name is clearly described as absent.
    """
    before = [
        token for token in name_tokens[:start] if token not in IGNORED_CONTEXT_TOKENS
    ]
    after = [
        token for token in name_tokens[end:] if token not in IGNORED_CONTEXT_TOKENS
    ]

    before = remove_compound_secret_tokens(before, from_end=True)
    after = remove_compound_secret_tokens(after, from_end=False)

    previous_token = before[-1] if before else None
    next_token = after[0] if after else None

    # no_password, without_access_token, non_user_password
    if previous_token in DIRECT_NEGATION_TOKENS:
        return True

    # not_password, not_an_access_token
    if previous_token == "not":
        return True

    # missing_password, missing_access_token
    if previous_token in ABSENCE_STATE_TOKENS:
        return True

    # password_missing, token_value_unset
    if next_token in ABSENCE_STATE_TOKENS:
        return True

    # password_not_set, password_is_not_present
    if len(after) >= 2 and after[0] == "not" and after[1] in NOT_ABSENCE_STATE_TOKENS:
        return True

    # Unknown forms such as password_not_rotated still report.
    return False


def evaluate_name_context(candidate, matched_name):
    """
    Classify contextual hints surrounding a name-based rule match.

    Low-confidence tokens reduce confidence but do not suppress a finding.
    Findings are suppressed only when every occurrence of the matched secret
    name is explicitly described as absent.

    Args:
        candidate (Candidate): Candidate currently being evaluated.
        matched_name (str): Text matched by the rule's variable-name pattern.

    Returns:
        tuple[bool, str | None]:
            Whether the finding should be skipped and an optional confidence
            override.
    """
    name_tokens = split_identifier(candidate.var_name)
    matched_tokens = split_identifier(matched_name)

    confidence_override = None

    if any(token in LOW_CONFIDENCE_TOKENS for token in name_tokens):
        confidence_override = "LOW"

    spans = find_matching_token_spans(name_tokens, matched_tokens)

    if not spans:
        return False, confidence_override

    all_occurrences_are_absent = all(
        is_absence_context(name_tokens, start, end) for start, end in spans
    )

    return all_occurrences_are_absent, confidence_override


def apply_rules(candidate):
    """
    Apply all detection rules to a candidate assignment.

    A single candidate can produce multiple findings when distinct rules match.
    A single rule produces at most one finding for each candidate, even when
    multiple variable-name aliases match.

    Args:
        candidate (Candidate): Extracted variable name, value, and line number.

    Returns:
        list[Finding]: Findings created from rules that matched the candidate.
    """
    findings = []

    val = candidate.value
    var_name = candidate.var_name
    entropy = calculate_entropy(val)

    for rule in RULES:
        # Match structured secret values, such as AWS access keys.
        if rule.value_pattern is not None and rule.value_pattern.fullmatch(val):
            findings.append(
                Finding(
                    line_number=candidate.line_number,
                    var_name=var_name,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    value=val,
                    reason=rule.reason,
                    entropy=entropy,
                    confidence="HIGH",
                )
            )

        # Match suspicious variable names and enforce minimum value length.
        elif rule.var_patterns:
            match = None

            for var_pattern in rule.var_patterns:
                match = var_pattern.search(var_name)

                if match:
                    break

            if match is None or rule.min_length is None or len(val) < rule.min_length:
                continue

            should_skip, confidence_override = evaluate_name_context(
                candidate,
                match.group(0),
            )

            if should_skip:
                continue

            confidence = confidence_override or calculate_confidence(val)

            findings.append(
                Finding(
                    line_number=candidate.line_number,
                    var_name=var_name,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    value=val,
                    reason=rule.reason,
                    entropy=entropy,
                    confidence=confidence,
                )
            )

    return findings
