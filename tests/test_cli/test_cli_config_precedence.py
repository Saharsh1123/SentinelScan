import sys

import pytest

from cli import return_args


def test_cli_optional_overrides_default_to_none(monkeypatch):
    """
    Optional CLI overrides should default to None when absent.

    This lets sentinelscan.json control the setting unless the user explicitly
    provides a CLI override.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs"])

    args = return_args()

    assert args.redact is None
    assert args.format is None


def test_cli_redact_flag_sets_true_when_provided(monkeypatch):
    """
    --redact should explicitly enable output redaction.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--redact"])

    args = return_args()

    assert args.redact is True


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
def test_cli_format_accepts_all_supported_formats(monkeypatch, output_format):
    """--format should accept every output format exposed by SentinelScan."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--format", output_format],
    )

    args = return_args()

    assert args.format == output_format


def test_cli_format_normalizes_mixed_case(monkeypatch):
    """--format should accept mixed-case input and normalize it to lowercase."""
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--format", "SaRiF"])

    args = return_args()

    assert args.format == "sarif"


@pytest.mark.parametrize("bad_format", ["xml", "yaml", "banana"])
def test_cli_rejects_invalid_format(monkeypatch, bad_format):
    """
    Unsupported output formats should be rejected by argparse.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--format", bad_format],
    )

    with pytest.raises(SystemExit):
        return_args()


def test_cli_level_filters_default_to_none(monkeypatch):
    """
    Level filters should default to None when absent.

    This lets config file level selections apply.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs"])

    args = return_args()

    assert args.severity is None
    assert args.confidence is None


def test_cli_accepts_single_severity_level(monkeypatch):
    """
    Existing one-level severity syntax should still work.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--severity", "HIGH"])

    args = return_args()

    assert args.severity == ["HIGH"]


def test_cli_accepts_multiple_severity_levels(monkeypatch):
    """
    --severity should accept one or more exact levels.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--severity", "HIGH", "MEDIUM"],
    )

    args = return_args()

    assert args.severity == ["HIGH", "MEDIUM"]


def test_cli_accepts_single_confidence_level(monkeypatch):
    """
    Existing one-level confidence syntax should still work.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--confidence", "LOW"],
    )

    args = return_args()

    assert args.confidence == ["LOW"]


def test_cli_accepts_multiple_confidence_levels(monkeypatch):
    """
    --confidence should accept one or more exact levels.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--confidence", "LOW", "HIGH"],
    )

    args = return_args()

    assert args.confidence == ["LOW", "HIGH"]


@pytest.mark.parametrize("bad_level", ["CRITICAL", "VERY_HIGH", "banana"])
def test_cli_rejects_invalid_severity_levels(monkeypatch, bad_level):
    """
    Unsupported severity levels should be rejected by argparse.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--severity", bad_level],
    )

    with pytest.raises(SystemExit):
        return_args()


@pytest.mark.parametrize("bad_level", ["CRITICAL", "VERY_HIGH", "banana"])
def test_cli_rejects_invalid_confidence_levels(monkeypatch, bad_level):
    """
    Unsupported confidence levels should be rejected by argparse.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--confidence", bad_level],
    )

    with pytest.raises(SystemExit):
        return_args()


def test_cli_normalizes_lowercase_severity_level(monkeypatch):
    """
    --severity should accept lowercase input and normalize it to uppercase.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--severity", "high"],
    )

    args = return_args()

    assert args.severity == ["HIGH"]


def test_cli_normalizes_mixed_case_severity_levels(monkeypatch):
    """
    --severity should normalize multiple selected levels to uppercase.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--severity", "high", "Medium", "LOW"],
    )

    args = return_args()

    assert args.severity == ["HIGH", "MEDIUM", "LOW"]


def test_cli_normalizes_lowercase_confidence_level(monkeypatch):
    """
    --confidence should accept lowercase input and normalize it to uppercase.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--confidence", "medium"],
    )

    args = return_args()

    assert args.confidence == ["MEDIUM"]


def test_cli_normalizes_mixed_case_confidence_levels(monkeypatch):
    """
    --confidence should normalize multiple selected levels to uppercase.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--confidence", "low", "High", "MEDIUM"],
    )

    args = return_args()

    assert args.confidence == ["LOW", "HIGH", "MEDIUM"]
