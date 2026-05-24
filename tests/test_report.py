"""End-to-end tests: ingest → report → markdown/json."""
from __future__ import annotations

import json
from pathlib import Path

from cft_veracode.ingest import ingest
from cft_veracode.report import build_report

FIXTURES = Path(__file__).parent / "fixtures"


def test_end_to_end_pipeline_markdown():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    md = report.to_markdown()
    assert "Veracode remediation report" in md
    assert "DemoApp" in md
    assert "CWE-89" in md
    assert "CWE-79" in md
    # Should surface the primary fix for SQLi
    assert "CFT021.01" in md


def test_end_to_end_groups_dao_sqli():
    """Both SQLi findings (UserDao and OrderDao) sit in the same package directory
    and share CWE-89, so they should land in ONE group."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    sqli_groups = [g for g in report.groups if g.cwe_id == "CWE-89"]
    assert len(sqli_groups) == 1
    assert sqli_groups[0].count == 2


def test_skip_mitigated_default():
    """Findings marked ACCEPTED in Veracode are dropped by default."""
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    report = build_report(findings)  # skip_mitigated=True is default
    assert report.skipped_mitigated == 1
    cwes_kept = {g.cwe_id for g in report.groups}
    assert "CWE-327" not in cwes_kept  # the mitigated MD5 finding


def test_include_mitigated_flag():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    report = build_report(findings, skip_mitigated=False)
    cwes_kept = {g.cwe_id for g in report.groups}
    assert "CWE-327" in cwes_kept


def test_language_inference_from_path():
    """Java file paths should produce Java language guidance in the report."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    sqli_group = next(g for g in report.groups if g.cwe_id == "CWE-89")
    assert sqli_group.language == "java"
    md = report.to_markdown()
    # Java-specific guidance keyword should appear in the rendered Markdown
    assert "PreparedStatement" in md


def test_effort_cap_drops_high_options():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings, effort_cap="Low")
    # The SQLi group's plan should have NO Medium/High primary fixes left under Low cap
    sqli = next(g for g in report.groups if g.cwe_id == "CWE-89")
    if sqli.plan is not None:
        for e in sqli.plan.primary:
            assert e.sub_technique.effort == "Low"


def test_min_severity_filter():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings, min_severity="High")
    # XSS (severity=3 → Medium) should be dropped
    cwes_kept = {g.cwe_id for g in report.groups}
    assert "CWE-79" not in cwes_kept
    assert report.skipped_below_severity == 1


def test_json_output_shape():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    data = json.loads(report.to_json())
    assert "summary" in data
    assert "groups" in data
    assert data["summary"]["fix_groups"] == len(report.groups)
    # Each group has either a plan or null
    for g in data["groups"]:
        assert "cwe_id" in g
        assert "findings" in g
        assert "plan" in g
