"""Tests for the Findings v2 API JSON normalizer."""
from __future__ import annotations

from pathlib import Path

from cft_veracode.ingest import ingest

FIXTURES = Path(__file__).parent / "fixtures"


def test_api_basic_parse():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    assert len(findings) == 3


def test_api_extracts_mitigation_status():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    md5_finding = next(f for f in findings if f.cwe_id == "CWE-327")
    assert md5_finding.mitigation_status == "ACCEPTED"
    assert md5_finding.is_mitigated is True


def test_api_violates_policy_flag():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    for f in findings:
        assert f.violates_policy is True


def test_api_scan_context():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    ctx = findings[0].scan_context
    assert ctx.scanner == "veracode-api"
    assert ctx.app_name == "DemoApp"
    assert ctx.sandbox == "main-policy-scan"


def test_api_function_and_file():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    xss = next(f for f in findings if f.cwe_id == "CWE-79")
    assert xss.location.file_path == "src/main/webapp/views/profile.jsp"
    assert xss.location.line == 14
    assert xss.location.function_name == "render"
