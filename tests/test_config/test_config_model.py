from config.config_model import ScannerConfig, VALID_LEVELS, VALID_OUTPUT_FORMATS


def test_scanner_config_defaults_are_safe_and_include_all_levels():
    """Built-in defaults should scan all levels and hide plaintext secrets."""
    config = ScannerConfig()

    assert config.severity_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.confidence_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.show_secrets is False
    assert config.output_format == "text"


def test_scanner_config_accepts_explicit_supported_settings():
    """Explicit level and output selections should be stored as provided."""
    config = ScannerConfig(
        severity_levels=["HIGH", "MEDIUM"],
        confidence_levels=["HIGH"],
        output_format="json",
    )

    assert config.severity_levels == ["HIGH", "MEDIUM"]
    assert config.confidence_levels == ["HIGH"]
    assert config.show_secrets is False
    assert config.output_format == "json"


def test_scanner_config_level_lists_are_not_shared_between_instances():
    """Each config instance should receive independent default lists."""
    first = ScannerConfig()
    second = ScannerConfig()

    first.severity_levels.append("CUSTOM")

    assert second.severity_levels == ["LOW", "MEDIUM", "HIGH"]


def test_config_constants_match_supported_values():
    """Shared constants should expose every accepted level and format."""
    assert VALID_LEVELS == ("LOW", "MEDIUM", "HIGH")
    assert VALID_OUTPUT_FORMATS == ("text", "json", "sarif")
