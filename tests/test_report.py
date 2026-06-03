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


def test_findings_table_column_order_and_status():
    """The affected-findings table uses the column order
    Severity, Status, Issue ID, Title, Line, File — and surfaces the
    scanner finding status (e.g. OPEN) captured from the REST API."""
    # API findings carry a finding_status.status; include mitigated so all show.
    findings = ingest(FIXTURES / "findings-api-sample.json", format="api")
    report = build_report(findings, skip_mitigated=False)
    md = report.to_markdown()
    # New header order — no Veracode column.
    assert "| Severity | Status | Issue ID | Title | Line | File |" in md
    assert "| Severity | File | Line | Issue ID | Title | Veracode |" not in md
    assert "Veracode |" not in md  # the old guidance-link column is gone
    # Status values from the fixture appear in the table.
    assert "OPEN" in md
    assert "CLOSED" in md


def test_group_section_order_findings_before_remediation():
    """Within a group, the affected-findings table must come BEFORE the
    recommended fix block. Devs read 'what is it / where is it' first,
    then 'how do I fix it'.

    Also asserts the metadata strip carries the count + severity + language
    + location facts (previously partly stuffed into the header).
    """
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    md = report.to_markdown()

    # The CWE-89 (SQLi) group should appear once.
    grp_idx = md.find("### Group")
    assert grp_idx != -1
    # Find first SQLi group header.
    sqli_idx = next(
        md.find(line) for line in md.splitlines()
        if line.startswith("### Group") and "CWE-89" in line
    )

    # Within the SQLi group, the findings table header must precede the
    # plan's primary-fix label.
    table_idx = md.index("| Severity | Status | Issue ID | Title | Line | File |", sqli_idx)
    plan_idx  = md.index("**Primary fix (Sufficient", sqli_idx)
    assert sqli_idx < table_idx < plan_idx, (
        f"Expected order: group header ({sqli_idx}) -> findings table "
        f"({table_idx}) -> remediation ({plan_idx})"
    )

    # Metadata strip carries the count, severity, language, and location.
    assert "**Findings:** 2" in md       # CWE-89 group has 2 findings in the fixture
    assert "**Max severity:**" in md
    assert "**Language:** `java`" in md
    assert "**Location:** `" in md

    # The old "X finding(s) in `path`" suffix should be gone from the header.
    assert "finding(s) in" not in md


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


def test_html_output_basic_shape():
    """The HTML renderer should produce a single, standalone HTML document
    with the dark theme embedded and the report content present."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    out = report.to_html()

    # Single-file standalone HTML
    assert out.startswith("<!DOCTYPE html>")
    assert "<html" in out
    assert "</html>" in out
    # Embedded CSS, no external stylesheets
    assert "<style>" in out
    assert "<link" not in out  # no external CSS
    assert "<script" not in out  # no external JS either

    # Dark theme CSS variables present
    assert "--bg:" in out
    assert "color-scheme" in out and "dark" in out

    # Severity color classes are emitted for at least one severity
    # (the SQLi fixture has Medium-severity findings)
    assert "sev-medium" in out
    # And the CSS defines all six severity tiers
    for cls in ("sev-veryhigh", "sev-high", "sev-medium", "sev-low", "sev-verylow", "sev-info"):
        assert f".pill.{cls}" in out, f"missing severity CSS for {cls}"

    # Report content
    assert "DemoApp" in out                  # app name from fixture scan context
    assert "CWE-89" in out
    assert "SQL Injection" in out
    assert "CFT021.01" in out                # primary fix surfaced
    assert "Summary" in out
    assert "Fix groups" in out


def test_html_severity_pill_for_finding_row():
    """Each finding row in the table should carry a severity pill
    (colored badge), not a plain text cell."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    out = report.to_html()
    # The SQLi findings in the fixture are Medium severity. The pill markup
    # is <span class="pill sev-medium">...</span> — assert at least one
    # appears inside a <td class="severity">.
    assert 'class="severity"' in out
    assert 'class="pill sev-medium"' in out


def test_html_escapes_user_supplied_content():
    """Finding titles, file paths, etc. must be HTML-escaped — a finding
    title with a < or & shouldn't break the document."""
    from cft_veracode.types import Finding, Location, ScanContext

    ctx = ScanContext(scanner="test", app_name="EscapeTest")
    hostile = Finding(
        finding_id="x1",
        cwe_id="CWE-79",
        severity="High",
        title='<script>alert("xss")</script> & stuff',
        location=Location(file_path="src/<weird>.java", line=10),
        scanner="test",
        scan_context=ctx,
    )
    report = build_report([hostile])
    out = report.to_html()

    # Raw script tag must NOT appear unescaped
    assert "<script>alert" not in out
    # The escaped version must appear
    assert "&lt;script&gt;alert" in out
    # File path angle brackets escaped
    assert "src/&lt;weird&gt;.java" in out


def test_html_is_the_default_via_report_helper():
    """to_html() works and is the canonical default — but to_markdown()
    and to_json() must still be available for opt-in."""
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    # All three formats coexist
    assert report.to_html().startswith("<!DOCTYPE html>")
    assert report.to_markdown().startswith("# Veracode remediation report")
    assert report.to_json().startswith("{")


def test_html_renders_language_guidance_for_csharp():
    """The .NET-codebase fixture should produce csharp language guidance
    in the HTML (same fix as the markdown-side language-picker bug)."""
    findings = ingest(FIXTURES / "sarif-dotnet-sample.json", format="sarif")
    report = build_report(findings)
    out = report.to_html()

    assert "Language guidance (csharp)" in out
    assert "SqlCommand" in out
    # Java guidance must not leak through
    assert "Language guidance (java)" not in out
    assert "JDBC PreparedStatement (built-in)" not in out


def test_json_includes_issue_type_and_flaw_link():
    findings = ingest(FIXTURES / "pipeline-sample.json", format="pipeline")
    report = build_report(findings)
    data = json.loads(report.to_json())
    sqli_group = next(g for g in data["groups"] if g["cwe_id"] == "CWE-89")
    assert sqli_group["issue_type"] == "SQL Injection"
    f_with_url = next(f for f in sqli_group["findings"] if f["finding_id"] == "1")
    assert f_with_url["flaw_details_url"] is not None
    assert "veracode" in f_with_url["flaw_details_url"]
