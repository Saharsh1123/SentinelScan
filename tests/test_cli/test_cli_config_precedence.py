import sys

from cli import return_args


def test_cli_boolean_flags_default_to_none(monkeypatch):
    """
    Boolean CLI flags should default to None when absent.

    This allows sentinelscan.json to control the value when the user does not
    explicitly provide a CLI override.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs"])

    args = return_args()

    assert args.redact is None
    assert args.json is None


def test_cli_redact_flag_sets_true_when_provided(monkeypatch):
    """
    --redact should explicitly override config redaction.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--redact"])

    args = return_args()

    assert args.redact is True


def test_cli_json_flag_sets_true_when_provided(monkeypatch):
    """
    --json should explicitly override config output_format.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--json"])

    args = return_args()

    assert args.json is True


def test_cli_filters_default_to_none(monkeypatch):
    """
    Severity and confidence should default to None when absent.

    This allows config file values to apply when the user does not provide CLI
    filter overrides.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs"])

    args = return_args()

    assert args.severity is None
    assert args.confidence is None


def test_cli_severity_override(monkeypatch):
    """
    --severity should preserve explicit user intent for config merging.
    """
    monkeypatch.setattr(sys, "argv", ["main.py", "test_dirs", "--severity", "HIGH"])

    args = return_args()

    assert args.severity == "HIGH"


def test_cli_confidence_override(monkeypatch):
    """
    --confidence should preserve explicit user intent for config merging.
    """
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "test_dirs", "--confidence", "MEDIUM"],
    )

    args = return_args()

    assert args.confidence == "MEDIUM"