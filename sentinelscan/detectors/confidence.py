"""
Entropy and confidence scoring helpers.

Severity describes impact if a finding is real. Confidence describes how likely
it is that the detected value is a real secret. These helpers provide lightweight
heuristics for confidence scoring without changing detection behavior.
"""

from collections import Counter
import math

COMMON_LOW_CONFIDENCE_VALUES = {
    "password",
    "admin",
    "secret",
    "token",
    "apikey",
    "api_key",
    "test",
    "testing",
    "example",
    "changeme",
    "default",
    "letmein",
    "qwerty",
    "abcdef",
    "abc123",
    "password123",
}


def calculate_entropy(value):
    """
    Calculate Shannon entropy for a string value.

    Args:
        value (str): Value to score.

    Returns:
        float: Entropy score. Empty values return 0.0.
    """
    if not value:
        return 0.0

    counts = Counter(value)
    total = len(value)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_confidence(value):
    """
    Estimate whether a detected value is likely to be a real secret.

    Confidence uses simple heuristics: known placeholder values, length, and
    entropy. Specific value-pattern rules, such as AWS keys, may override this
    in the rule engine.

    Args:
        value (str): Detected value.

    Returns:
        str: One of LOW, MEDIUM, or HIGH.
    """
    entropy = calculate_entropy(value)

    if value.lower() in COMMON_LOW_CONFIDENCE_VALUES:
        return "LOW"

    if len(value) < 8:
        return "LOW"

    if entropy < 2.5:
        return "LOW"

    if entropy < 3.5:
        return "MEDIUM"

    if len(value) < 12:
        return "MEDIUM"

    return "HIGH"
