import json

import pytest

from config.config import get_config
from config.config_model import ScannerConfig
from exceptions import ExpectedUserError


def write_config(tmp_path, data):
    """Write sentinelscan.json into a temporary directory."""
    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text(json.dumps(data), encoding="utf-8")
    return config_file


def test_get_config_returns_defaults_when_config_file_missing(tmp_path, monkeypatch):
    """Missing config files should fall back to safe ScannerConfig defaults."""
    monkeypatch.chdir(tmp_path)

    assert get_config() == ScannerConfig()


def test_get_config_loads_every_supported_field(tmp_path, monkeypatch):
    """The loader should apply all supported file-based settings."""
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "severity_levels": ["HIGH", "MEDIUM"],
            "confidence_levels": ["HIGH"],
            "output_format": "json",
        },
    )

    config = get_config()

    assert config.severity_levels == ["HIGH", "MEDIUM"]
    assert config.confidence_levels == ["HIGH"]
    assert config.show_secrets is False
    assert config.output_format == "json"


def test_get_config_allows_partial_config_file(tmp_path, monkeypatch):
    """Missing supported fields should retain their built-in defaults."""
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {"severity_levels": ["HIGH"]})

    config = get_config()

    assert config.severity_levels == ["HIGH"]
    assert config.confidence_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.show_secrets is False
    assert config.output_format == "text"


@pytest.mark.parametrize(
    ("unsupported_key", "value"),
    [
        ("redact", True),
        ("show_secrets", True),
        ("unknown_setting", "ignored"),
    ],
)
def test_get_config_ignores_unsupported_keys(
    tmp_path,
    monkeypatch,
    unsupported_key,
    value,
):
    """Config files must not enable plaintext output or add unknown fields."""
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "severity_levels": ["HIGH"],
            unsupported_key: value,
        },
    )

    config = get_config()

    assert config.severity_levels == ["HIGH"]
    assert config.show_secrets is False
    assert not hasattr(config, "redact")
    assert not hasattr(config, "unknown_setting")


def test_get_config_normalizes_level_and_output_case(tmp_path, monkeypatch):
    """Levels should normalize uppercase and output formats lowercase."""
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "severity_levels": ["high", "medium"],
            "confidence_levels": ["low"],
            "output_format": "SARIF",
        },
    )

    config = get_config()

    assert config.severity_levels == ["HIGH", "MEDIUM"]
    assert config.confidence_levels == ["LOW"]
    assert config.output_format == "sarif"


def test_get_config_rejects_invalid_json(tmp_path, monkeypatch):
    """Malformed JSON should fail instead of silently using defaults."""
    monkeypatch.chdir(tmp_path)

    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text("{ invalid json", encoding="utf-8")

    with pytest.raises(ExpectedUserError):
        get_config()


def test_get_config_rejects_non_object_json(tmp_path, monkeypatch):
    """The config document must be a JSON object."""
    monkeypatch.chdir(tmp_path)

    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text('["HIGH"]', encoding="utf-8")

    with pytest.raises(ValueError):
        get_config()


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity_levels", "HIGH"),
        ("severity_levels", 123),
        ("severity_levels", True),
        ("severity_levels", []),
        ("confidence_levels", "HIGH"),
        ("confidence_levels", 123),
        ("confidence_levels", False),
        ("confidence_levels", []),
    ],
)
def test_get_config_rejects_invalid_level_field_types(
    tmp_path,
    monkeypatch,
    field,
    value,
):
    """Level settings must be non-empty JSON arrays."""
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {field: value})

    with pytest.raises(ValueError):
        get_config()


@pytest.mark.parametrize(
    "field,value",
    [
        ("severity_levels", ["CRITICAL"]),
        ("severity_levels", ["HIGH", "CRITICAL"]),
        ("severity_levels", [""]),
        ("severity_levels", [None]),
        ("severity_levels", [123]),
        ("confidence_levels", ["VERY_HIGH"]),
        ("confidence_levels", ["LOW", "VERY_HIGH"]),
        ("confidence_levels", [""]),
        ("confidence_levels", [None]),
        ("confidence_levels", [123]),
    ],
)
def test_get_config_rejects_invalid_level_values(tmp_path, monkeypatch, field, value):
    """Level arrays should contain only LOW, MEDIUM, or HIGH strings."""
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {field: value})

    with pytest.raises(ValueError):
        get_config()


@pytest.mark.parametrize("value", ["xml", True, None])
def test_get_config_rejects_invalid_output_format(tmp_path, monkeypatch, value):
    """Output format remains a strictly validated supported setting."""
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {"output_format": value})

    with pytest.raises(ValueError):
        get_config()


def test_get_config_can_load_from_scan_path(tmp_path):
    """An explicit scan path should load its local config file."""
    write_config(tmp_path, {"severity_levels": ["HIGH"]})

    config = get_config(tmp_path)

    assert config.severity_levels == ["HIGH"]


def test_get_config_falls_back_to_current_working_directory(tmp_path, monkeypatch):
    """A cwd config should apply when the scan root has no config."""
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()

    write_config(tmp_path, {"output_format": "json"})
    monkeypatch.chdir(tmp_path)

    config = get_config(scan_dir)

    assert config.output_format == "json"
    assert config.show_secrets is False


def test_get_config_prefers_scan_path_config_over_current_working_directory(
    tmp_path,
    monkeypatch,
):
    """A scan-root config should take precedence over a cwd config."""
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()

    write_config(tmp_path, {"output_format": "json"})
    write_config(scan_dir, {"output_format": "text"})
    monkeypatch.chdir(tmp_path)

    config = get_config(scan_dir)

    assert config.output_format == "text"
    assert config.show_secrets is False
