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
    """
    A cwd config should apply when the scanned directory has no config file.
    """
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()
    write_python_file(scan_dir, "vulnerable.py", 'password = "abcdef"\n')
    write_config(tmp_path, {"output_format": "json"})

    result = run_cli(scan_dir, cwd=tmp_path)
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) == 1
    assert data[0]["var_name"] == "password"


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
    """
    Explicit CLI output format should override sentinelscan.json.
    """
    scan_dir = tmp_path / "scan_target"
    scan_dir.mkdir()
    write_python_file(scan_dir, "vulnerable.py", 'password = "abcdef"\n')
    write_config(tmp_path, {"output_format": "text"})

    result = run_cli(scan_dir, "--format", "json", cwd=tmp_path)
    assert_success(result)

    data = parse_json_output(result)

    assert len(data) == 1
    assert data[0]["var_name"] == "password"
