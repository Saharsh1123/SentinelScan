"""Unit tests for deterministic secret-value masking."""

import pytest

from output import redact_value


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", "[REDACTED]"),
        ("abcd", "[REDACTED]"),
        ("abcdef", "a****f"),
        ("abc1234567890j", "ab**********0j"),
    ],
)
def test_redact_value_masks_each_supported_length_band(value, expected):
    """Masking should cover empty/short, medium, and long value branches."""
    assert redact_value(value) == expected
