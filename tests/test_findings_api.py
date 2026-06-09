"""Tests for the Findings v2 API JSON normalizer."""
from __future__ import annotations

from pathlib import Path

from cft_veracode.ingest import ingest

FIXTURES = Path(__file__).parent / "fixtures"


def test_api_basic_parse():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    assert len(findings) == 4


def test_api_extracts_mitigation_status():
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    md5_finding = next(f for f in findings if f.cwe_id == "CWE-327")
    assert md5_finding.mitigation_status == "ACCEPTED"
    assert md5_finding.is_mitigated is True


def test_api_extracts_finding_status():
    """finding_status.status (e.g. OPEN/CLOSED) is captured onto Finding.status."""
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    sqli = next(f for f in findings if f.cwe_id == "CWE-89")
    md5 = next(f for f in findings if f.cwe_id == "CWE-327")
    assert sqli.status == "OPEN"
    assert md5.status == "CLOSED"


def test_api_is_closed_property():
    """Finding.is_closed reflects a CLOSED status case-insensitively; the
    path-traversal finding is closed but NOT mitigated."""
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    sqli = next(f for f in findings if f.cwe_id == "CWE-89")
    closed = next(f for f in findings if f.cwe_id == "CWE-22")
    assert sqli.is_closed is False
    assert closed.is_closed is True
    assert closed.is_mitigated is False


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


def test_api_extracts_flaw_details_link():
    """The SQLi finding in the fixture carries flaw_details_link directly on the record."""
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    sqli = next(f for f in findings if f.cwe_id == "CWE-89")
    assert sqli.flaw_details_url is not None
    assert "veracode.com" in sqli.flaw_details_url


def test_api_flaw_details_falls_back_to_links_block():
    """If `flaw_details_link` isn't on the record, fall back to _links.html.href."""
    from cft_veracode.ingest import parse_findings_api
    doc = {
        "_embedded": {
            "findings": [{
                "issue_id": 99,
                "finding_status": {"status": "OPEN", "resolution": "UNRESOLVED"},
                "finding_details": {
                    "severity": 3,
                    "cwe": {"id": 79, "name": "XSS"},
                    "file_path": "x.java",
                    "file_line_number": 1,
                },
                "_links": {
                    "html": {"href": "https://analysiscenter.veracode.com/some/path"},
                },
            }],
        },
    }
    f = parse_findings_api(doc)[0]
    assert f.flaw_details_url == "https://analysiscenter.veracode.com/some/path"
