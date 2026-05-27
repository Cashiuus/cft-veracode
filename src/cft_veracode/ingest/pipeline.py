"""Parse Veracode Pipeline Scan JSON output into Finding objects.

Reference format produced by the `veracode-pipeline-scan` CLI tool:
  {
    "scan_id": "...",
    "scan_status": "SUCCESS",
    "app_name": "...",
    "scan_engine_version": "...",
    "findings": [
      {
        "title": "Improper Neutralization...",
        "issue_id": 1,
        "gob": "AAB",
        "severity": 4,
        "issue_type": "SQL Injection",
        "issue_type_id": "...",
        "cwe_id": "89",            # bare number; sometimes "CWE-89"
        "display_text": "...",
        "files": {
          "source_file": {
            "file": "src/Foo.java",
            "line": 42,
            "function_name": "doQuery",
            "qualified_function_name": "..."
          }
        }
      },
      ...
    ]
  }
"""
from __future__ import annotations

from cft_veracode.types import VERACODE_SEVERITY, Finding, Location, ScanContext


def parse_pipeline_scan(doc: dict) -> list[Finding]:
    if not isinstance(doc, dict):
        raise ValueError("pipeline scan: expected top-level JSON object")
    if "findings" not in doc:
        raise ValueError("pipeline scan: missing 'findings' array")

    ctx = ScanContext(
        scanner="veracode-pipeline",
        scan_id=str(doc.get("scan_id") or "") or None,
        app_name=doc.get("app_name") or doc.get("project_name"),
        scan_type="STATIC",
        tool_name="Veracode Pipeline Scan",
        tool_version=doc.get("scan_engine_version"),
    )

    out: list[Finding] = []
    for raw in doc["findings"]:
        loc = _location_from_pipeline(raw)
        cwe = _normalize_cwe(raw.get("cwe_id"))
        sev_num = raw.get("severity")
        sev = VERACODE_SEVERITY.get(int(sev_num), "Informational") if sev_num is not None else "Informational"

        issue_id = raw.get("issue_id")
        if issue_id is None:
            # Synthesize a stable fingerprint when no issue_id present
            issue_id = f"{cwe or 'CWE-?'}:{loc.file_path or '?'}:{loc.line or '?'}"

        out.append(Finding(
            finding_id=str(issue_id),
            cwe_id=cwe,
            severity=sev,
            title=raw.get("issue_type") or raw.get("title") or "(unknown finding)",
            description=raw.get("display_text"),
            location=loc,
            scanner="veracode-pipeline",
            scan_context=ctx,
            veracode_flaw_id=str(raw.get("issue_id")) if raw.get("issue_id") is not None else None,
            mitigation_status=None,  # Pipeline scans don't carry mitigation history
            violates_policy=None,
            flaw_details_url=raw.get("flaw_details_link") or raw.get("flaw_details_url"),
            scanner_native=raw,
        ))
    return out


def _location_from_pipeline(raw: dict) -> Location:
    files = raw.get("files") or {}
    src = files.get("source_file") if isinstance(files, dict) else None
    if not isinstance(src, dict):
        return Location(file_path=None)
    return Location(
        file_path=src.get("file"),
        line=_to_int(src.get("line")),
        column=_to_int(src.get("column")),
        function_name=src.get("function_name") or src.get("qualified_function_name"),
    )


def _normalize_cwe(value) -> "str | None":
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.upper().startswith("CWE-"):
        return s.upper()
    if s.isdigit():
        return f"CWE-{s}"
    return None


def _to_int(v) -> "int | None":
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
