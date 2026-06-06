import json

import pytest

from config.config import get_config
from config.config_model import ScannerConfig


def write_config(tmp_path, data):
    """
    Write sentinelscan.json into a temporary directory.
    """
    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text(json.dumps(data), encoding="utf-8")
    return config_file


def test_get_config_returns_defaults_when_config_file_missing(tmp_path, monkeypatch):
    """
    Missing config files should fall back to ScannerConfig defaults.
    """
    monkeypatch.chdir(tmp_path)

    assert get_config() == ScannerConfig()


def test_get_config_loads_full_config_file(tmp_path, monkeypatch):
    """
    get_config should load all supported config fields.
    """
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "severity_levels": ["HIGH", "MEDIUM"],
            "confidence_levels": ["HIGH"],
            "redact": True,
            "output_format": "json",
        },
    )

    config = get_config()

    assert config.severity_levels == ["HIGH", "MEDIUM"]
    assert config.confidence_levels == ["HIGH"]
    assert config.redact is True
    assert config.output_format == "json"


def test_get_config_allows_partial_config_file(tmp_path, monkeypatch):
    """
    Partial config files should override only provided fields.
    """
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {"redact": True})

    config = get_config()

    assert config.severity_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.confidence_levels == ["LOW", "MEDIUM", "HIGH"]
    assert config.redact is True
    assert config.output_format == "text"


def test_get_config_ignores_unknown_keys_without_crashing(tmp_path, monkeypatch):
    """
    Unknown keys should be ignored instead of added to ScannerConfig.
    """
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "severity_levels": ["HIGH"],
            "unknown_setting": "ignored",
        },
    )

    config = get_config()

    assert config.severity_levels == ["HIGH"]
    assert not hasattr(config, "unknown_setting")


def test_get_config_normalizes_level_and_output_case(tmp_path, monkeypatch):
    """
    Level names should normalize to uppercase and output format to lowercase.
    """
    monkeypatch.chdir(tmp_path)

    write_config(
        tmp_path,
        {
            "severity_levels": ["high", "medium"],
            "confidence_levels": ["low"],
            "output_format": "JSON",
        },
    )

    config = get_config()

    assert config.severity_levels == ["HIGH", "MEDIUM"]
    assert config.confidence_levels == ["LOW"]
    assert config.output_format == "json"


def test_get_config_rejects_invalid_json(tmp_path, monkeypatch):
    """
    Invalid JSON should fail loudly instead of silently using defaults.
    """
    monkeypatch.chdir(tmp_path)

    config_file = tmp_path / "sentinelscan.json"
    config_file.write_text("{ invalid json", encoding="utf-8")

    with pytest.raises(Exception):
        get_config()


def test_get_config_rejects_non_object_json(tmp_path, monkeypatch):
    """
    Config files must contain a JSON object.
    """
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
    """
    Level fields must be non-empty JSON arrays.
    """
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
    """
    Level arrays should contain only LOW, MEDIUM, or HIGH.
    """
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {field: value})

    with pytest.raises(ValueError):
        get_config()


@pytest.mark.parametrize(
    "field,value",
    [
        ("redact", "true"),
        ("redact", 1),
        ("redact", None),
        ("output_format", "xml"),
        ("output_format", True),
        ("output_format", None),
    ],
)
def test_get_config_rejects_invalid_non_level_fields(
    tmp_path,
    monkeypatch,
    field,
    value,
):
    """
    Redaction and output format should be strictly validated.
    """
    monkeypatch.chdir(tmp_path)

    write_config(tmp_path, {field: value})

    with pytest.raises(ValueError):
        get_config()


def test_get_config_can_load_from_scan_path(tmp_path):
    """
    Passing a scan path should load sentinelscan.json from that directory.
    """
    write_config(tmp_path, {"severity_levels": ["HIGH"]})

    config = get_config(tmp_path)

    assert config.severity_levels == ["HIGH"]
