"""Render sample reports to preview the HTML output.

Usage (from the repo root, with the package installed/importable):

    python examples/preview_report.py

Writes two files next to this script:

  * preview-report.html        — a small report (below the large-report
    threshold) showing the baseline layout.
  * preview-large-report.html  — a large report (well above the threshold) that
    exercises the fix-first panel, filter controls, and findings index.

Useful for eyeballing CSS / layout changes to the HTML renderer without needing
a real Veracode scan.
"""
from pathlib import Path

from cft_veracode.types import (
    Finding, FindingGroup, Location, Report, ScanContext,
)


def _ctx(app_name: str, scan_id: str) -> ScanContext:
    return ScanContext(
        scanner="veracode-api",
        scan_id=scan_id,
        app_name=app_name,
        sandbox="release-2026.06",
        scan_type="STATIC",
        scan_date="2026-06-04",
        tool_name="Veracode SAST",
        tool_version="2026.1",
    )


def _mk(ctx, fid, cwe, sev, title, fpath, line, status="OPEN", flaw=None):
    return Finding(
        finding_id=fid, cwe_id=cwe, severity=sev, title=title,
        location=Location(file_path=fpath, line=line),
        scanner="veracode-api", scan_context=ctx, status=status,
        veracode_flaw_id=flaw,
    )


def _resolve_plans(groups):
    """Best-effort: attach real CFT plans; leave None if the taxonomy lacks the CWE."""
    try:
        from cft.resolver import UnknownCWE, resolve as cft_resolve
    except Exception as e:  # noqa: BLE001
        print(f"(skipping plan resolution: {e})")
        return
    for g in groups:
        try:
            g.plan = cft_resolve(g.cwe_id, language=g.language)
        except UnknownCWE:
            g.plan = None


# ---------------------------------------------------------------------------
# Small report — a handful of groups, below the large-report threshold.
# ---------------------------------------------------------------------------
def build_small_report() -> Report:
    ctx = _ctx("Acme Payments Service", "abc123-def456")
    groups = [
        FindingGroup(
            cwe_id="CWE-89", file_root="src/main/java/com/acme/payments/dao",
            language="java",
            findings=[
                _mk(ctx, "f1", "CWE-89", "VeryHigh", "SQL Injection",
                    "src/main/java/com/acme/payments/dao/OrderDao.java", 142, flaw="101"),
                _mk(ctx, "f2", "CWE-89", "High", "SQL Injection",
                    "src/main/java/com/acme/payments/dao/CustomerDao.java", 88, flaw="102"),
            ],
        ),
        FindingGroup(
            cwe_id="CWE-79", file_root="src/main/webapp/views",
            language="java",
            findings=[
                _mk(ctx, "f3", "CWE-79", "Medium", "Cross-Site Scripting (XSS)",
                    "src/main/webapp/views/profile.jsp", 33, flaw="201"),
            ],
        ),
    ]
    _resolve_plans(groups)
    return Report(
        scan_context=ctx, groups=groups,
        skipped_mitigated=3, skipped_no_cwe=1, skipped_below_severity=5,
        min_severity="Medium",
    )


# ---------------------------------------------------------------------------
# Large report — many groups / findings, well above the threshold, to exercise
# the fix-first panel, filter controls, and findings index.
# ---------------------------------------------------------------------------
# (cwe, severity, title, language, file_root, finding_count)
_LARGE_SPECS = [
    ("CWE-89",  "VeryHigh", "SQL Injection",                  "java",       "src/main/java/com/acme/payments/dao",      48),
    ("CWE-79",  "High",     "Cross-Site Scripting (XSS)",     "java",       "src/main/webapp/views",                    132),
    ("CWE-78",  "VeryHigh", "OS Command Injection",           "java",       "src/main/java/com/acme/ops",               6),
    ("CWE-22",  "High",     "Path Traversal",                 "java",       "src/main/java/com/acme/files",             21),
    ("CWE-327", "Medium",   "Use of Broken Crypto Algorithm", "java",       "src/main/java/com/acme/crypto",            14),
    ("CWE-798", "High",     "Hardcoded Credentials",          "python",     "services/ingest",                          9),
    ("CWE-352", "Medium",   "Cross-Site Request Forgery",     "java",       "src/main/webapp/controllers",              38),
    ("CWE-611", "High",     "XML External Entity (XXE)",      "java",       "src/main/java/com/acme/xml",               4),
    ("CWE-502", "VeryHigh", "Insecure Deserialization",       "java",       "src/main/java/com/acme/cache",             3),
    ("CWE-200", "Low",      "Information Exposure",            "javascript", "web/src/components",                       210),
    ("CWE-326", "Low",      "Inadequate Encryption Strength", "java",       "src/main/java/com/acme/tls",               17),
    ("CWE-90",  "High",     "LDAP Injection",                 "java",       "src/main/java/com/acme/directory",         5),
    ("CWE-601", "Medium",   "Open Redirect",                  "javascript", "web/src/routes",                           27),
    ("CWE-117", "Low",      "Improper Output Neutralization for Logs", "java", "src/main/java/com/acme/logging",         64),
    ("CWE-732", "Medium",   "Incorrect Permission Assignment", "python",    "services/deploy",                          11),
    ("CWE-918", "VeryLow",  "Server-Side Request Forgery",    "python",     "services/audit",                           2),
]


def build_large_report() -> Report:
    ctx = _ctx("Acme Megastore Platform", "big-scan-987654")
    groups = []
    fid = 0
    flaw = 1000
    for cwe, sev, title, lang, root, n in _LARGE_SPECS:
        ext = "py" if lang == "python" else ("js" if lang == "javascript" else "java")
        findings = []
        for i in range(n):
            fid += 1
            flaw += 1
            findings.append(_mk(
                ctx, f"f{fid}", cwe, sev, title,
                f"{root}/Module{i % 5}.{ext}", 100 + i, flaw=str(flaw),
            ))
        groups.append(FindingGroup(cwe_id=cwe, file_root=root, language=lang, findings=findings))
    _resolve_plans(groups)
    return Report(
        scan_context=ctx, groups=groups,
        skipped_mitigated=12, skipped_no_cwe=4, skipped_below_severity=88,
        min_severity="VeryLow",
    )


def main() -> None:
    here = Path(__file__).parent
    for filename, report in (
        ("preview-report.html", build_small_report()),
        ("preview-large-report.html", build_large_report()),
    ):
        out_path = here / filename
        out_path.write_text(report.to_html(), encoding="utf-8")
        print(f"wrote {out_path}  ({len(report.groups)} groups, {report.total_findings} findings)")


if __name__ == "__main__":
    main()
