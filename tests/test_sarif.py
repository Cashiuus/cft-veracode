"""Tests for the SARIF normalizer."""
from __future__ import annotations

from pathlib import Path

from cft_veracode.ingest import ingest, parse_sarif

FIXTURES = Path(__file__).parent / "fixtures"


def test_sarif_basic_parse():
    findings = ingest(FIXTURES / "sarif-sample.json", format="sarif")
    assert len(findings) == 2


def test_sarif_cwe_from_result_properties():
    findings = ingest(FIXTURES / "sarif-sample.json", format="sarif")
    sqli = next(f for f in findings if "SQL" in f.title or f.cwe_id == "CWE-89")
    assert sqli.cwe_id == "CWE-89"


def test_sarif_cwe_inherited_from_rule():
    """When a result lacks properties.cwe, it should inherit from the rule."""
    findings = ingest(FIXTURES / "sarif-sample.json", format="sarif")
    # In the fixture, the XSS result has no properties.cwe; it inherits from the rule
    xss = next(f for f in findings if "scripting" in f.title.lower() or f.cwe_id == "CWE-79")
    assert xss.cwe_id == "CWE-79"


def test_sarif_severity_mapping():
    findings = ingest(FIXTURES / "sarif-sample.json", format="sarif")
    sevs = {f.severity for f in findings}
    assert "High" in sevs    # level=error → High
    assert "Medium" in sevs  # level=warning → Medium


def test_sarif_correlation_guid_as_id():
    findings = ingest(FIXTURES / "sarif-sample.json", format="sarif")
    ids = {f.finding_id for f in findings}
    assert "00000000-aaaa-bbbb-cccc-000000000001" in ids


def test_sarif_cwe_heuristic_from_message():
    """Last-resort: scan message text for 'CWE-NNN' when no other source exists."""
    doc = {
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "Mystery Scanner" } },
            "results": [{
                "level": "error",
                "message": { "text": "Buffer overflow detected (see CWE-787)" },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": "src/buf.c" },
                        "region": { "startLine": 10 }
                    }
                }]
            }]
        }]
    }
    findings = parse_sarif(doc)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-787"
