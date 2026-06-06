from config.config_model import ScannerConfig, VALID_LEVELS, VALID_OUTPUT_FORMATS


def test_scanner_config_defaults_include_all_levels():
    """
    Defaults should include all levels and use text output.
    """
    config = ScannerConfig()

    assert config.severity_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.confidence_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.redact is False
    assert config.output_format == "text"


def test_scanner_config_accepts_explicit_level_lists():
    """
    Explicit selections should be stored without reordering.
    """
    config = ScannerConfig(
        severity_levels=["HIGH", "MEDIUM"],
        confidence_levels=["HIGH"],
        redact=True,
        output_format="json",
    )

    assert config.severity_levels == ["HIGH", "MEDIUM"]
    assert config.confidence_levels == ["HIGH"]
    assert config.redact is True
    assert config.output_format == "json"


def test_scanner_config_level_lists_are_not_shared_between_instances():
    """
    Default level lists should be independent per instance.
    """
    first = ScannerConfig()
    second = ScannerConfig()

    first.severity_levels.append("CUSTOM")

    assert second.severity_levels == ["LOW", "MEDIUM", "HIGH"]


def test_config_constants_match_supported_values():
    """
    Shared constants should expose the supported config values.
    """
    assert VALID_LEVELS == ("LOW", "MEDIUM", "HIGH")
    assert VALID_OUTPUT_FORMATS == ("text", "json")
