import json

import pytest

from config.config import get_config
from config.config_model import ScannerConfig


def write_config(tmp_path, data):
    """
    Write a sentinelscan.json file into a temporary directory.
    """
    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text(json.dumps(data), encoding="utf-8")
    return config_file


def test_get_config_returns_defaults_when_config_file_missing(tmp_path, monkeypatch):
    """
    Missing config files should not crash the scanner.

    The scanner should fall back to built-in defaults.
    """
    monkeypatch.chdir(tmp_path)

    config = get_config()

    assert config == ScannerConfig()


def test_get_config_loads_full_config_file(tmp_path, monkeypatch):
    """
    get_config should load all supported config fields from sentinelscan.json.
    """
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "min_confidence": "MEDIUM",
            "min_severity": "HIGH",
            "redact": True,
            "output_format": "json",
        },
    )

    config = get_config()

    assert config.min_confidence == "MEDIUM"
    assert config.min_severity == "HIGH"
    assert config.redact is True
    assert config.output_format == "json"


def test_get_config_allows_partial_config_file(tmp_path, monkeypatch):
    """
    Config files should be allowed to override only some settings.

    Missing fields should use ScannerConfig defaults.
    """
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "redact": True,
        },
    )

    config = get_config()

    assert config.min_confidence is None
    assert config.min_severity is None
    assert config.redact is True
    assert config.output_format == "text"


def test_get_config_ignores_unknown_keys_or_warns_without_crashing(tmp_path, monkeypatch):
    """
    Unknown keys should not crash config loading.

    This protects forward compatibility if users add unsupported settings.
    """
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "redact": True,
            "unknown_setting": "ignored",
        },
    )

    config = get_config()

    assert config.redact is True
    assert not hasattr(config, "unknown_setting")


def test_get_config_rejects_invalid_json(tmp_path, monkeypatch):
    """
    Invalid JSON should fail loudly instead of silently using defaults.
    """
    monkeypatch.chdir(tmp_path)

    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text("{ invalid json", encoding="utf-8")

    with pytest.raises(Exception):
        get_config()


@pytest.mark.parametrize(
    "field,value",
    [
        ("min_confidence", "VERY_HIGH"),
        ("min_severity", "CRITICAL"),
        ("output_format", "xml"),
    ],
)
def test_get_config_rejects_invalid_enum_values(tmp_path, monkeypatch, field, value):
    """
    Config fields with fixed allowed values should reject unsupported values.
    """
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {field: value})

    with pytest.raises(ValueError):
        get_config()


@pytest.mark.parametrize(
    "field,value",
    [
        ("min_confidence", 123),
        ("min_severity", True),
        ("redact", "true"),
        ("output_format", False),
    ],
)
def test_get_config_rejects_invalid_value_types(tmp_path, monkeypatch, field, value):
    """
    Config fields should reject wrong JSON types.

    Example:
        "redact": "true"

    should fail because redact must be a real JSON boolean.
    """
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {field: value})

    with pytest.raises(ValueError):
        get_config()