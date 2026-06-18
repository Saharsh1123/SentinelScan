"""Unit tests for SentinelScan SARIF 2.1.0 serialization."""

import json

import pytest

from detectors.models import Finding
from sarif import build_rule_definition, build_sarif_result, output_sarif

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
PASSWORD_REASON = (
    "variable name matched password/pwd/passwd pattern " "and value met minimum length"
)
TOKEN_REASON = "variable name matched token pattern and value met minimum length"


def make_finding(
    *,
    file_path,
    line_number=1,
    var_name="password",
    value="super-secret-value",
    rule_id="PASSWORD",
    rule_name="Password",
    severity="HIGH",
    reason=PASSWORD_REASON,
    confidence="HIGH",
):
    """Create a Finding while allowing each test to override relevant fields."""
    return Finding(
        file_path=str(file_path),
        line_number=line_number,
        var_name=var_name,
        value=value,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        reason=reason,
        entropy=4.2,
        confidence=confidence,
    )


def render_sarif(capsys, findings, scan_root):
    """Render SARIF to stdout and return both parsed and raw output."""
    output_sarif(findings, scan_root)
    raw_output = capsys.readouterr().out
    return json.loads(raw_output), raw_output


def test_build_rule_definition_uses_rule_metadata(tmp_path):
    """A rule definition should expose stable metadata for its rule ID."""
    finding = make_finding(file_path=tmp_path / "vulnerable.py")

    rule = build_rule_definition(finding)

    assert rule == {
        "id": "PASSWORD",
        "name": "Password",
        "shortDescription": {"text": PASSWORD_REASON},
        "defaultConfiguration": {"level": "error"},
    }


@pytest.mark.parametrize(
    ("severity", "expected_level"),
    [
        ("LOW", "note"),
        ("MEDIUM", "warning"),
        ("HIGH", "error"),
    ],
)
def test_sarif_builders_map_all_severity_levels(
    tmp_path,
    severity,
    expected_level,
):
    """Rule and result builders should use valid SARIF severity names."""
    finding = make_finding(
        file_path=tmp_path / "vulnerable.py",
        severity=severity,
    )

    rule = build_rule_definition(finding)
    result = build_sarif_result(finding, tmp_path)

    assert rule["defaultConfiguration"]["level"] == expected_level
    assert result["level"] == expected_level


def test_build_sarif_result_contains_relative_posix_location(tmp_path):
    """A result should identify its rule, message, relative path, and line."""
    scan_root = tmp_path / "scan_root"
    finding_path = scan_root / "src" / "settings.py"
    finding = make_finding(file_path=finding_path, line_number=27)

    result = build_sarif_result(finding, scan_root)

    assert result["ruleId"] == "PASSWORD"
    assert result["message"]["text"] == PASSWORD_REASON

    physical_location = result["locations"][0]["physicalLocation"]

    assert physical_location["artifactLocation"]["uri"] == "src/settings.py"
    assert physical_location["region"]["startLine"] == 27


def test_output_sarif_emits_required_document_structure(tmp_path, capsys):
    """SARIF output should be one pure JSON object with one analysis run."""
    finding = make_finding(file_path=tmp_path / "vulnerable.py")

    document, raw_output = render_sarif(capsys, [finding], tmp_path)

    assert raw_output.lstrip().startswith("{")
    assert "Scanning" not in raw_output
    assert "Total findings" not in raw_output
    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == "2.1.0"
    assert len(document["runs"]) == 1

    run = document["runs"][0]

    assert run["tool"]["driver"]["name"] == "SentinelScan"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1


def test_output_sarif_deduplicates_rules_without_dropping_results(
    tmp_path,
    capsys,
):
    """Repeated rule IDs should share one definition but keep every result."""
    findings = [
        make_finding(
            file_path=tmp_path / "first.py",
            line_number=2,
            var_name="token",
            value="first-token-value",
            rule_id="TOKEN",
            rule_name="Token",
            severity="MEDIUM",
            reason=TOKEN_REASON,
        ),
        make_finding(
            file_path=tmp_path / "second.py",
            line_number=8,
            var_name="token",
            value="second-token-value",
            rule_id="TOKEN",
            rule_name="Token",
            severity="MEDIUM",
            reason=TOKEN_REASON,
        ),
        make_finding(
            file_path=tmp_path / "third.py",
            line_number=4,
        ),
    ]

    document, _ = render_sarif(capsys, findings, tmp_path)
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    declared_rule_ids = {rule["id"] for rule in rules}
    result_rule_ids = [result["ruleId"] for result in results]

    assert declared_rule_ids == {"TOKEN", "PASSWORD"}
    assert len(rules) == 2
    assert result_rule_ids.count("TOKEN") == 2
    assert result_rule_ids.count("PASSWORD") == 1
    assert len(results) == 3
    assert set(result_rule_ids) <= declared_rule_ids


def test_output_sarif_with_no_findings_is_valid_empty_report(tmp_path, capsys):
    """An empty scan should still emit a valid SARIF report structure."""
    document, raw_output = render_sarif(capsys, [], tmp_path)
    run = document["runs"][0]

    assert document["$schema"] == SARIF_SCHEMA
    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "SentinelScan"
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []
    assert "No vulnerabilities found." not in raw_output


def test_output_sarif_never_serializes_secret_values(tmp_path, capsys):
    """SARIF messages should describe findings without exposing credentials."""
    secret = "unique-secret-that-must-never-appear"
    finding = make_finding(
        file_path=tmp_path / "vulnerable.py",
        value=secret,
    )

    document, raw_output = render_sarif(capsys, [finding], tmp_path)

    assert secret not in raw_output
    assert secret not in document["runs"][0]["results"][0]["message"]["text"]
