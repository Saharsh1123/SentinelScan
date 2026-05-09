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