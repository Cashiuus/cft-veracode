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


def test_csharp_language_guidance_for_dotnet_codebase():
    """`.cs` and `.cshtml` paths must route to csharp guidance — not java.

    Regression: before the fix, the renderer iterated language_guidance.items()
    and broke on the first key, which is consistently "java" in the taxonomy.
    A C# codebase would silently get Java code examples.
    """
    findings = ingest(FIXTURES / "sarif-dotnet-sample.json", format="sarif")
    report = build_report(findings)

    sqli = next(g for g in report.groups if g.cwe_id == "CWE-89")
    xss = next(g for g in report.groups if g.cwe_id == "CWE-79")
    assert sqli.language == "csharp", "UserRepository.cs should infer csharp"
    assert xss.language == "csharp",  "Profile.cshtml should infer csharp"

    md = report.to_markdown()
    # C# guidance markers from CFT021.01 (Prepared Statements) and CFT018.01
    # (HTML Entity Encoding) should appear.
    assert "**Language guidance (csharp):**" in md
    assert "SqlCommand" in md or "Dapper" in md       # CFT021.01 csharp library
    assert "WebUtility.HtmlEncode" in md or "Razor" in md  # CFT018.01 csharp guidance
    # Java guidance must NOT leak through for a C# codebase.
    # Canaries are markers that exist ONLY inside Java guidance blocks —
    # not in CFT021.01's prose description (which mentions PreparedStatement)
    # or CFT018.01's checklist text (which mentions OWASP Java Encoder as
    # one of several recommended vetted libraries).
    assert "**Language guidance (java):**" not in md
    assert "JDBC PreparedStatement (built-in)" not in md  # CFT021.01 java library
    assert "org.owasp.encoder.Encode" not in md            # CFT018.01 java example


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


def test_group_header_includes_issue_type():
    """The group header should show the issue_type/title so it's clear what we're addressing."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    md = report.to_markdown()
    sqli_headers = [line for line in md.splitlines() if line.startswith("### Group") and "CWE-89" in line]
    assert len(sqli_headers) == 1
    assert "SQL Injection" in sqli_headers[0]


def test_findings_table_includes_details_column():
    """The affected-findings table should include a Details column with a Markdown link when available."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    md = report.to_markdown()
    # Header row includes Details
    assert "| Severity | File | Line | Issue ID | Title | Details |" in md
    # SQLi finding 1 has flaw_details_link in the fixture — should render as a Markdown link
    assert "[view](https://web.analysiscenter.veracode.com" in md


def test_report_omits_regex_patterns_and_verification_notes():
    """Per UX direction: keep checklist + common mistakes; drop the regex
    patterns and the verification-notes commentary that explains them.

    The taxonomy stores a grep_pattern like
        (executeQuery|executeUpdate|cursor\\.execute|conn\\.query|Statement\\.execute)
    on CFT021.01. Neither the regex itself nor the grep/semgrep field labels
    must appear in the report. The verification `notes` field is also
    suppressed — those notes are predominantly scanner-tool commentary about
    the (now-suppressed) grep pattern, not developer-actionable guidance.
    """
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    md = report.to_markdown()
    # No raw regex content from the SQLi grep_pattern
    assert "executeQuery|executeUpdate|cursor" not in md
    # No labels for regex / rule fields
    assert "_grep pattern:_" not in md
    assert "_semgrep rule:_" not in md
    # Verification notes label must not appear; CFT021.01's verification.notes
    # (cross-reference scanner output) must not leak through either.
    assert "_notes:_" not in md
    assert "Cross-reference scanner output" not in md
    # Verification block must still render with checklist items as bullets.
    assert "**Verification:**" in md
    assert "No SQL text is constructed by string concatenation" in md


def test_json_includes_issue_type_and_flaw_link():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    data = json.loads(report.to_json())
    sqli_group = next(g for g in data["groups"] if g["cwe_id"] == "CWE-89")
    assert sqli_group["issue_type"] == "SQL Injection"
    f_with_url = next(f for f in sqli_group["findings"] if f["finding_id"] == "1")
    assert f_with_url["flaw_details_url"] is not None
    assert "veracode" in f_with_url["flaw_details_url"]
