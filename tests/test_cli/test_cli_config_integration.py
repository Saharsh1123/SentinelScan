import json

from tests.helpers import assert_success, parse_json_output, run_cli, write_python_file


def write_config(root_path, data):
    """
    Write sentinelscan.json under a test-controlled directory.
    """
    config_file = root_path / "sentinelscan.json"
    config_file.write_text(json.dumps(data), encoding="utf-8")
    return config_file


def test_cli_uses_current_working_directory_config_when_scan_path_has_none(
    tmp_path,
):
    """A cwd config should select SARIF when the scan path has no config."""
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()
    write_python_file(scan_dir, "vulnerable.py", 'password = "abcdef"\n')
    write_config(tmp_path, {"output_format": "sarif"})

    result = run_cli(scan_dir, cwd=tmp_path)
    assert_success(result)

    document = parse_json_output(result)
    sarif_result = document["runs"][0]["results"][0]

    assert document["version"] == "2.1.0"
    assert sarif_result["ruleId"] == "PASSWORD"
    assert (
        sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "vulnerable.py"
    )


def test_cli_prefers_scan_path_config_over_current_working_directory_config(
    tmp_path,
):
    """
    A config in the scanned directory should override cwd config.
    """
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()
    write_python_file(scan_dir, "vulnerable.py", 'password = "abcdef"\n')
    write_config(tmp_path, {"output_format": "json"})
    write_config(scan_dir, {"output_format": "text"})

    result = run_cli(scan_dir, cwd=tmp_path)
    assert_success(result)

    assert "Scanning" in result.stdout
    assert "[HIGH]" in result.stdout


def test_cli_format_argument_overrides_config_output_format(tmp_path):
    """An explicit SARIF format should override the config output format."""
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()
    write_python_file(scan_dir, "vulnerable.py", 'password = "abcdef"\n')
    write_config(tmp_path, {"output_format": "text"})

    result = run_cli(scan_dir, "--format", "sarif", cwd=tmp_path)
    assert_success(result)

    document = parse_json_output(result)

    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "PASSWORD"
