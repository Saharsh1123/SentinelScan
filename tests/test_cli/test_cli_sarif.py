"""End-to-end CLI tests for SARIF output."""

from tests.helpers import (
    AWS_REASON,
    assert_success,
    make_combined_filter_fixture,
    parse_json_output,
    run_cli,
    write_python_file,
)

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def test_cli_sarif_output_is_valid_and_deduplicates_rules(tmp_path):
    """The CLI should emit relative paths, unique rules, and all results."""
    write_python_file(tmp_path, "nested/password.py", 'password = "abcdef"\n')
    write_python_file(
        tmp_path,
        "nested/first_token.py",
        'token = "abc1234567890j"\n',
    )
    write_python_file(
        tmp_path,
        "second_token.py",
        'token = "xyzttttggfdddf"\n',
    )

    result = run_cli(tmp_path, "--format", "sarif", "--redact")
    assert_success(result)

    document = parse_json_output(result)
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    declared_rule_ids = {rule["id"] for rule in rules}
    result_rule_ids = [finding["ruleId"] for finding in results]
    result_uris = {
        finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for finding in results
    }

    assert isinstance(document, dict)
    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "SentinelScan"
    assert declared_rule_ids == {"PASSWORD", "TOKEN"}
    assert len(rules) == 2
    assert result_rule_ids.count("PASSWORD") == 1
    assert result_rule_ids.count("TOKEN") == 2
    assert len(results) == 3
    assert set(result_rule_ids) <= declared_rule_ids
    assert result_uris == {
        "nested/password.py",
        "nested/first_token.py",
        "second_token.py",
    }
    assert "abcdef" not in result.stdout
    assert "abc1234567890j" not in result.stdout
    assert "xyzttttggfdddf" not in result.stdout


def test_cli_sarif_respects_combined_severity_and_confidence_filters(tmp_path):
    """Excluded findings should not appear in SARIF rules or results."""
    make_combined_filter_fixture(tmp_path)

    result = run_cli(
        tmp_path,
        "--format",
        "sarif",
        "--severity",
        "HIGH",
        "--confidence",
        "HIGH",
    )
    assert_success(result)

    document = parse_json_output(result)
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    assert len(rules) == 1
    assert rules[0]["id"] == "AWS_ACCESS_KEY"
    assert rules[0]["defaultConfiguration"]["level"] == "error"
    assert len(results) == 1

    finding = results[0]
    physical_location = finding["locations"][0]["physicalLocation"]

    assert finding["ruleId"] == "AWS_ACCESS_KEY"
    assert finding["level"] == "error"
    assert finding["message"]["text"] == AWS_REASON
    assert physical_location["artifactLocation"]["uri"] == "findings.py"
    assert physical_location["region"]["startLine"] == 3


def test_cli_sarif_no_findings_returns_valid_empty_report(tmp_path):
    """A safe scan should return empty SARIF arrays and no text output."""
    write_python_file(tmp_path, "safe.py", 'username = "safe"\n')

    result = run_cli(tmp_path, "--format", "sarif")
    assert_success(result)

    document = parse_json_output(result)
    run = document["runs"][0]

    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "SentinelScan"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
    assert "No vulnerabilities found." not in result.stdout
    assert "Scanning" not in result.stdout
