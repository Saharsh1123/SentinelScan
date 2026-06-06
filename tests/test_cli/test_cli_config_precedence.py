import sys

import pytest

from cli import return_args


def test_cli_boolean_flags_default_to_none(monkeypatch):
    """
    Boolean flags should default to None when absent.

    This lets sentinelscan.json control the setting unless the user explicitly
    provides a CLI override.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs"])

    args = return_args()

    assert args.redact is None
    assert args.json is None


def test_cli_redact_flag_sets_true_when_provided(monkeypatch):
    """
    --redact should explicitly enable output redaction.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--redact"])

    args = return_args()

    assert args.redact is True


def test_cli_json_flag_sets_true_when_provided(monkeypatch):
    """
    --json should explicitly enable JSON output.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--json"])

    args = return_args()

    assert args.json is True


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
