import pytest

from detectors.confidence import calculate_entropy, calculate_confidence


# -------------------------
# Entropy calculation tests
# -------------------------


# Empty values should not crash and should have zero entropy
def test_entropy_empty_string():
    assert calculate_entropy("") == 0.0


# A single repeated character has no uncertainty
def test_entropy_single_repeated_character():
    assert calculate_entropy("aaaaaa") == 0.0


# A single-character string has zero entropy
def test_entropy_single_character():
    assert calculate_entropy("a") == 0.0


# Two equally distributed characters should produce 1 bit of entropy
def test_entropy_two_balanced_characters():
    assert calculate_entropy("abab") == pytest.approx(1.0)


# Four equally distributed characters should produce 2 bits of entropy
def test_entropy_four_unique_characters():
    assert calculate_entropy("abcd") == pytest.approx(2.0)


# Entropy should increase when character variety increases
def test_entropy_varied_string_higher_than_repeated_string():
    repeated_entropy = calculate_entropy("aaaaaaaa")
    varied_entropy = calculate_entropy("abcdef12")

    assert varied_entropy > repeated_entropy


# Entropy should treat uppercase and lowercase letters as different characters
def test_entropy_is_case_sensitive():
    assert calculate_entropy("Aa") == pytest.approx(1.0)


# Entropy should count symbols as normal characters
def test_entropy_counts_symbols():
    assert calculate_entropy("a!") == pytest.approx(1.0)


# Repeated patterns should have lower entropy than fully varied strings
def test_entropy_repeated_pattern_lower_than_unique_string():
    repeated_pattern_entropy = calculate_entropy("abcdabcd")
    unique_string_entropy = calculate_entropy("abcdefgh")

    assert repeated_pattern_entropy < unique_string_entropy


# Entropy should handle whitespace without crashing
def test_entropy_handles_whitespace():
    assert calculate_entropy("        ") == 0.0


# Entropy should handle mixed letters, numbers, and symbols
def test_entropy_handles_mixed_character_types():
    entropy = calculate_entropy("aB9$xQ2p")

    assert entropy > 2.5


# -------------------------
# Confidence calculation tests
# -------------------------


# Empty values should be low confidence
def test_confidence_empty_string_is_low():
    assert calculate_confidence("") == "LOW"


# Very short values should stay low confidence even if varied
def test_confidence_short_varied_value_is_low():
    assert calculate_confidence("abcd") == "LOW"


# Short detected values should not become high confidence from entropy alone
def test_confidence_short_random_looking_value_is_low():
    assert calculate_confidence("aB9$xQ") == "LOW"


# Long repetitive values should be low confidence
def test_confidence_long_repetitive_value_is_low():
    assert calculate_confidence("aaaaaaaaaaaa") == "LOW"


# Repeated patterns should remain low confidence
def test_confidence_repeated_pattern_is_low():
    assert calculate_confidence("abcdabcdabcd") == "LOW"


# Values at length 8 with moderate entropy should be medium confidence
def test_confidence_length_8_varied_value_is_medium():
    assert calculate_confidence("abcd1234") == "MEDIUM"


# Medium-length varied values should be medium confidence
def test_confidence_medium_length_varied_value_is_medium():
    assert calculate_confidence("abcdefghi") == "MEDIUM"


# Values under 12 characters should not become high confidence
def test_confidence_length_11_value_is_not_high():
    assert calculate_confidence("abcdefghijk") == "MEDIUM"


# Long varied values should be high confidence
def test_confidence_long_varied_value_is_high():
    assert calculate_confidence("abcdefghijkl") == "HIGH"


# Long mixed-character values should be high confidence
def test_confidence_long_mixed_value_is_high():
    assert calculate_confidence("aB9$xQ2pLm4Z") == "HIGH"


# Numeric-only sequential-looking values should not automatically be high confidence
def test_confidence_numeric_sequence_is_medium_or_low():
    result = calculate_confidence("123456789012")

    assert result in {"LOW", "MEDIUM"}


# Common simple words should not be high confidence
def test_confidence_common_word_is_low():
    assert calculate_confidence("password") == "LOW"


# Mixed but repetitive token-looking values should not be high confidence
def test_confidence_repetitive_token_like_value_is_not_high():
    assert calculate_confidence("xyzttttggfdddf") in {"LOW", "MEDIUM"}


# More varied token-looking values can be high confidence
def test_confidence_varied_token_like_value_is_high():
    assert calculate_confidence("abc1234567890j") == "HIGH"


# Confidence should always return one of the supported labels
@pytest.mark.parametrize(
    "value",
    [
        "",
        "abcd",
        "abcdef",
        "password",
        "aaaaaaaaaaaa",
        "abcd1234",
        "abcdefghi",
        "abcdefghijkl",
        "aB9$xQ2pLm4Z",
        "abc1234567890j",
    ],
)
def test_confidence_returns_supported_label(value):
    assert calculate_confidence(value) in {"LOW", "MEDIUM", "HIGH"}