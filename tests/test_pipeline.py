"""Tests for the Pipeline Scan JSON normalizer."""
from __future__ import annotations

import json
from pathlib import Path

from cft_veracode.ingest import ingest

FIXTURES = Path(__file__).parent / "fixtures"


def test_pipeline_basic_parse():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    assert len(findings) == 3


def test_pipeline_cwe_normalization():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    cwes = {f.cwe_id for f in findings}
    # Both bare-number "89" and prefixed "CWE-89" must normalize to "CWE-89"
    assert "CWE-89" in cwes
    assert "CWE-79" in cwes
    # No stray "89" or "79"
    assert "89" not in cwes
    assert None not in cwes


def test_pipeline_severity_mapping():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    sevs = {f.severity for f in findings}
    assert "High" in sevs    # severity=4 → High
    assert "Medium" in sevs  # severity=3 → Medium


def test_pipeline_location_extracted():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    sqli = next(f for f in findings if f.cwe_id == "CWE-89" and f.finding_id == "1")
    assert sqli.location.file_path == "src/main/java/com/example/dao/UserDao.java"
    assert sqli.location.line == 87
    assert sqli.location.function_name == "findById"


def test_pipeline_preserves_native_record():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    f = findings[0]
    assert f.scanner_native["issue_id"] == 1
    assert f.veracode_flaw_id == "1"
