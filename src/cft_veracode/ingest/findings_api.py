"""Parse Veracode Findings v2 REST API JSON into Finding objects.

Reference shape from `GET /findings/v2/applications/<app-id>/findings`:
  {
    "_embedded": {
      "findings": [
        {
          "issue_id": 12345,
          "scan_type": "STATIC",
          "description": "...",
          "violates_policy": true,
          "finding_status": {
            "status": "OPEN",
            "resolution": "UNRESOLVED",
            "first_found_date": "...",
            "last_seen_date": "...",
            "mitigation_review_status": "NONE"
          },
          "finding_details": {
            "severity": 4,
            "cwe": { "id": 89, "name": "SQL Injection" },
            "file_path": "...",
            "file_name": "...",
            "file_line_number": 42,
            "function_name": "...",
            "module": "..."
          },
          "annotations": [...]
        }
      ]
    },
    "page": {...}
  }

Top-level wrapper may also embed application context (`application_guid`, etc.)
when the caller supplied it; we tolerate either shape.
"""
from __future__ import annotations

from cft_veracode.types import VERACODE_SEVERITY, Finding, Location, ScanContext


def parse_findings_api(doc: dict) -> list[Finding]:
    if not isinstance(doc, dict):
        raise ValueError("findings api: expected top-level JSON object")

    findings = (
        doc.get("_embedded", {}).get("findings")
        if isinstance(doc.get("_embedded"), dict)
        else doc.get("findings")
    )
    if findings is None:
        raise ValueError("findings api: missing '_embedded.findings' or 'findings' array")

    ctx = ScanContext(
        scanner="veracode-api",
        app_name=doc.get("application_name") or doc.get("app_name"),
        sandbox=doc.get("sandbox_name"),
        scan_type=doc.get("scan_type"),
        tool_name="Veracode Static Analysis",
    )

    out: list[Finding] = []
    for raw in findings:
        details = raw.get("finding_details") or {}
        status = raw.get("finding_status") or {}

        sev_num = details.get("severity")
        sev = VERACODE_SEVERITY.get(int(sev_num), "Informational") if sev_num is not None else "Informational"
        cwe_block = details.get("cwe") or {}
        cwe = _normalize_cwe(cwe_block.get("id") if isinstance(cwe_block, dict) else None)
        title = (cwe_block.get("name") if isinstance(cwe_block, dict) else None) or details.get("category") or "(unknown finding)"

        loc = Location(
            # Fall back to "scope" when no file path is reported — observed on
            # some finding types (e.g. config/library issues) where Veracode
            # populates scope but leaves file_path/file_name blank.
            file_path=(
                details.get("file_path")
                or details.get("file_name")
                # Bugfix: REST API has "module" and "procedure" instead of other fields
                or details.get("module")
                or details.get("scope")
                or raw.get("scope")
            ),
            line=_to_int(details.get("file_line_number")),
            # Bugfix: REST API has "module" and "procedure" instead of other fields
            function_name=details.get("function_name") or details.get("procedure"),
        )

        issue_id = raw.get("issue_id")
        finding_id = str(issue_id) if issue_id is not None else f"{cwe or 'CWE-?'}:{loc.file_path or '?'}:{loc.line or '?'}"

        mitigation_status = _mitigation_status(raw, status)
        review = status.get("mitigation_review_status")
        # NOTE: "status" is present in REST API but not other data sources
        finding_state = status.get("status")  # e.g. "OPEN" / "CLOSED"
        flaw_url = _flaw_details_url(raw)

        out.append(Finding(
            finding_id=finding_id,
            cwe_id=cwe,
            severity=sev,
            title=title,
            description=raw.get("description"),
            status=finding_state,
            location=loc,
            scanner="veracode-api",
            scan_context=ctx,
            veracode_flaw_id=str(issue_id) if issue_id is not None else None,
            mitigation_status=mitigation_status,
            mitigation_review=review,
            violates_policy=raw.get("violates_policy"),
            flaw_details_url=flaw_url,
            scanner_native=raw,
        ))
    return out


def _flaw_details_url(raw: dict) -> "str | None":
    """Locate a deep-link URL to the finding in Veracode's UI.

    The Findings v2 response may expose this at the top-level field
    `flaw_details_link` (some response shapes) or under the HAL block
    `_links.html.href` / `_links.self.href`. We accept any of them.
    """
    direct = raw.get("flaw_details_link") or raw.get("flaw_details_url")
    if direct:
        return direct
    links = raw.get("_links") or {}
    if isinstance(links, dict):
        for key in ("html", "self"):
            blk = links.get(key)
            if isinstance(blk, dict) and blk.get("href"):
                return blk["href"]
    return None


def _mitigation_status(raw: dict, status: dict) -> "str | None":
    """Derive a coarse mitigation status flag the bridge cares about."""
    # The Veracode model is layered: resolution + mitigation_review_status + annotations.
    # We surface the most useful single signal: was the finding accepted/approved?
    resolution = (status or {}).get("resolution")
    if resolution in ("ACCEPTED", "MITIGATED", "POTENTIAL_FALSE_POSITIVE"):
        return resolution
    review = (status or {}).get("mitigation_review_status")
    if review == "ACCEPTED":
        return "ACCEPTED"
    if review == "REJECTED":
        return "REJECTED"
    return None


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
