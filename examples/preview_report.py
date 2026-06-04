"""Render a sample report to preview the HTML output.

Usage (from the repo root, with the package installed/importable):

    python examples/preview_report.py

Writes preview-report.html next to this script. Useful for eyeballing CSS or
layout changes to the HTML renderer without needing a real Veracode scan.
"""
from pathlib import Path

from cft_veracode.types import (
    Finding, FindingGroup, Location, Report, ScanContext,
)

ctx = ScanContext(
    scanner="veracode-api",
    scan_id="abc123-def456",
    app_name="Acme Payments Service",
    sandbox="release-2026.06",
    scan_type="STATIC",
    scan_date="2026-06-03",
    tool_name="Veracode SAST",
    tool_version="2026.1",
)


def mk(fid, cwe, sev, title, fpath, line, status="OPEN", flaw=None):
    return Finding(
        finding_id=fid, cwe_id=cwe, severity=sev, title=title,
        location=Location(file_path=fpath, line=line),
        scanner="veracode-api", scan_context=ctx, status=status,
        veracode_flaw_id=flaw,
    )


groups = [
    FindingGroup(
        cwe_id="CWE-89", file_root="src/main/java/com/acme/payments/dao",
        language="java",
        findings=[
            mk("f1", "CWE-89", "VeryHigh", "SQL Injection",
               "src/main/java/com/acme/payments/dao/OrderDao.java", 142, flaw="101"),
            mk("f2", "CWE-89", "High", "SQL Injection",
               "src/main/java/com/acme/payments/dao/CustomerDao.java", 88, flaw="102"),
        ],
    ),
    FindingGroup(
        cwe_id="CWE-79", file_root="src/main/webapp/views",
        language="java",
        findings=[
            mk("f3", "CWE-79", "Medium", "Cross-Site Scripting (XSS)",
               "src/main/webapp/views/profile.jsp", 33, flaw="201"),
        ],
    ),
]

# Try to resolve real CFT plans; fall back to None if the taxonomy lacks the CWE.
try:
    from cft.resolver import UnknownCWE, resolve as cft_resolve
    for g in groups:
        try:
            g.plan = cft_resolve(g.cwe_id, language=g.language)
        except UnknownCWE:
            g.plan = None
except Exception as e:  # noqa: BLE001
    print(f"(skipping plan resolution: {e})")

report = Report(
    scan_context=ctx, groups=groups,
    skipped_mitigated=3, skipped_no_cwe=1, skipped_below_severity=5,
    min_severity="Medium",
)

out_path = Path(__file__).parent / "preview-report.html"
out_path.write_text(report.to_html(), encoding="utf-8")
print(f"wrote {out_path}")
