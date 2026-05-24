"""Parse SARIF 2.1.0 JSON (from Veracode or any SARIF-emitting scanner).

SARIF puts CWE-IDs in several places depending on the tool:
- result.properties.cwe / result.properties.cwes (Veracode, some Snyk)
- result.taxa[].toolComponent.name == 'CWE' + taxa[].id (formal SARIF taxonomy)
- rule.properties.cwe (rule-level, applies to all results that match the rule)
- result.message.text containing 'CWE-NNN' (last-resort heuristic)

We try them in that order.
"""
from __future__ import annotations

import re

from cft_veracode.types import Finding, Location, ScanContext

# SARIF level → Veracode-style severity (rough mapping)
SARIF_LEVEL_TO_SEVERITY = {
    "error": "High",
    "warning": "Medium",
    "note": "Low",
    "none": "Informational",
}

_CWE_PATTERN = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b")


def parse_sarif(doc: dict) -> list[Finding]:
    if not isinstance(doc, dict):
        raise ValueError("sarif: expected top-level JSON object")
    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise ValueError("sarif: missing 'runs' array")

    out: list[Finding] = []
    for run_idx, run in enumerate(runs):
        tool = (run.get("tool") or {}).get("driver") or {}
        ctx = ScanContext(
            scanner="sarif",
            tool_name=tool.get("name"),
            tool_version=tool.get("version") or tool.get("semanticVersion"),
        )

        # Build a rule-id → rule-properties index (for inheriting CWE from the rule)
        rules_by_id: dict[str, dict] = {}
        for rule in tool.get("rules") or []:
            rid = rule.get("id")
            if rid:
                rules_by_id[rid] = rule

        for r_idx, result in enumerate(run.get("results") or []):
            rule_id = result.get("ruleId")
            rule = rules_by_id.get(rule_id, {}) if rule_id else {}

            cwe = _extract_cwe(result, rule)
            sev = SARIF_LEVEL_TO_SEVERITY.get(result.get("level", "warning"), "Medium")

            location = _first_location(result)
            title = (rule.get("shortDescription") or {}).get("text") \
                or rule.get("name") \
                or (result.get("message") or {}).get("text") \
                or "(unknown finding)"

            # Build a stable finding ID: prefer correlationGuid, then guid, then synthesize
            finding_id = (
                result.get("correlationGuid")
                or result.get("guid")
                or f"sarif:{run_idx}:{r_idx}:{rule_id or '?'}:{location.file_path or '?'}:{location.line or '?'}"
            )

            out.append(Finding(
                finding_id=finding_id,
                cwe_id=cwe,
                severity=sev,
                title=title[:200],  # protect against pathological titles
                description=(result.get("message") or {}).get("text"),
                location=location,
                scanner="sarif",
                scan_context=ctx,
                scanner_native=result,
            ))
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_cwe(result: dict, rule: dict) -> "str | None":
    # 1. result.properties.cwe / .cwes
    props = result.get("properties") or {}
    for key in ("cwe", "cwes"):
        v = props.get(key)
        if isinstance(v, str):
            cwe = _normalize_cwe(v)
            if cwe:
                return cwe
        elif isinstance(v, list) and v:
            cwe = _normalize_cwe(v[0])
            if cwe:
                return cwe

    # 2. result.taxa[].id where toolComponent.name == "CWE"
    for taxon in result.get("taxa") or []:
        tc = taxon.get("toolComponent") or {}
        if (tc.get("name") or "").upper() == "CWE":
            cwe = _normalize_cwe(taxon.get("id"))
            if cwe:
                return cwe

    # 3. rule.properties.cwe
    rule_props = rule.get("properties") or {}
    for key in ("cwe", "cwes"):
        v = rule_props.get(key)
        if isinstance(v, str):
            cwe = _normalize_cwe(v)
            if cwe:
                return cwe
        elif isinstance(v, list) and v:
            cwe = _normalize_cwe(v[0])
            if cwe:
                return cwe

    # 4. heuristic: scan message text and rule name for "CWE-NNN"
    msg = (result.get("message") or {}).get("text") or ""
    for src in (msg, rule.get("name") or ""):
        m = _CWE_PATTERN.search(src)
        if m:
            return f"CWE-{m.group(1)}"
    return None


def _first_location(result: dict) -> Location:
    locs = result.get("locations") or []
    if not locs:
        return Location(file_path=None)
    phys = (locs[0] or {}).get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    return Location(
        file_path=art.get("uri"),
        line=_to_int(region.get("startLine")),
        column=_to_int(region.get("startColumn")),
        snippet=(region.get("snippet") or {}).get("text"),
    )


def _normalize_cwe(value) -> "str | None":
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    m = _CWE_PATTERN.search(s)
    if m:
        return f"CWE-{m.group(1)}"
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
