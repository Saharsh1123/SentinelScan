from config.config_model import ScannerConfig


def test_scanner_config_defaults():
    """
    ScannerConfig should provide safe defaults when no config file values exist.
    """
    config = ScannerConfig()

    assert config.min_confidence is None
    assert config.min_severity is None
    assert config.redact is False
    assert config.output_format == "text"


def test_scanner_config_accepts_explicit_values():
    """
    ScannerConfig should store explicit config values.
    """
    config = ScannerConfig(
        min_confidence="MEDIUM",
        min_severity="HIGH",
        redact=True,
        output_format="json",
    )

    assert config.min_confidence == "MEDIUM"
    assert config.min_severity == "HIGH"
    assert config.redact is True
    assert config.output_format == "json"