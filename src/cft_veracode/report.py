"""Build and render the remediation report.

build_report() orchestrates: filter → dedupe → resolve CFT plans → assemble.
render_markdown() / render_json() emit the final output.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Optional

from cft.resolver import UnknownCWE, resolve as cft_resolve

from cft_veracode.dedupe import group_findings
from cft_veracode.types import (
    SEVERITY_RANK,
    Finding,
    FindingGroup,
    Report,
)


def build_report(
    findings: list[Finding],
    *,
    language: Optional[str] = None,
    effort_cap: Optional[str] = None,
    skip_mitigated: bool = True,
    min_severity: Optional[str] = None,
) -> Report:
    """Group findings, resolve CFT plans, return a structured Report.

    Args:
        findings: List of Finding objects (already normalized).
        language: Optional override language code; otherwise inferred per group from file paths.
        effort_cap: Pass-through to cft.resolve (Low/Medium/High).
        skip_mitigated: Drop findings already marked ACCEPTED/MITIGATED in Veracode.
        min_severity: Drop findings below this severity level.
    """
    if findings and getattr(findings[0], "scan_context", None):
        ctx = findings[0].scan_context
    else:
        from cft_veracode.types import ScanContext
        ctx = ScanContext(scanner="unknown")

    skipped_mitigated = 0
    skipped_no_cwe = 0
    skipped_below_severity = 0
    min_rank = SEVERITY_RANK.get(min_severity, -1) if min_severity else -1

    kept: list[Finding] = []
    for f in findings:
        if skip_mitigated and f.is_mitigated:
            skipped_mitigated += 1
            continue
        if not f.cwe_id:
            skipped_no_cwe += 1
            continue
        if min_rank > -1 and SEVERITY_RANK.get(f.severity, -1) < min_rank:
            skipped_below_severity += 1
            continue
        kept.append(f)

    groups = group_findings(kept)

    # Resolve a CFT plan per group
    for g in groups:
        chosen_lang = language or g.language
        try:
            g.plan = cft_resolve(g.cwe_id, language=chosen_lang, effort_cap=effort_cap)
        except UnknownCWE:
            g.plan = None

    return Report(
        scan_context=ctx,
        groups=groups,
        skipped_mitigated=skipped_mitigated,
        skipped_no_cwe=skipped_no_cwe,
        skipped_below_severity=skipped_below_severity,
        language_default=language,
        effort_cap=effort_cap,
        min_severity=min_severity,
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def render_markdown(report: Report) -> str:
    lines: list[str] = []
    add = lines.append

    ctx = report.scan_context
    title_parts = ["Veracode remediation report"]
    if ctx.app_name:
        title_parts.append(f"— {ctx.app_name}")
    add(f"# {' '.join(title_parts)}")
    add("")

    # Scan context block
    meta = []
    if ctx.scanner:
        meta.append(f"**Source:** {ctx.scanner}")
    if ctx.scan_id:
        meta.append(f"**Scan ID:** `{ctx.scan_id}`")
    if ctx.sandbox:
        meta.append(f"**Sandbox:** {ctx.sandbox}")
    if ctx.scan_type:
        meta.append(f"**Scan type:** {ctx.scan_type}")
    if ctx.tool_name:
        tv = f" ({ctx.tool_version})" if ctx.tool_version else ""
        meta.append(f"**Tool:** {ctx.tool_name}{tv}")
    if meta:
        add("  \n".join(meta))
        add("")

    # Executive summary
    add("## Summary")
    add("")
    add(f"- **Total findings (after filters):** {report.total_findings}")
    add(f"- **Fix groups:** {len(report.groups)}")
    sev_counts = report.severity_counts
    if sev_counts:
        ordered = sorted(sev_counts.items(), key=lambda kv: -SEVERITY_RANK.get(kv[0], -1))
        sev_summary = ", ".join(f"{v} {k}" for k, v in ordered)
        add(f"- **By severity:** {sev_summary}")
    if report.skipped_mitigated:
        add(f"- _Skipped (already mitigated):_ {report.skipped_mitigated}")
    if report.skipped_no_cwe:
        add(f"- _Skipped (no CWE on finding):_ {report.skipped_no_cwe}")
    if report.skipped_below_severity:
        add(f"- _Skipped (below `{report.min_severity}` threshold):_ {report.skipped_below_severity}")
    add("")

    if not report.groups:
        add("No actionable findings after applying filters.")
        return "\n".join(lines) + "\n"

    add("---")
    add("")
    add("## Fix groups")
    add("")

    for idx, g in enumerate(report.groups, start=1):
        _render_group_markdown(add, idx, g)

    return "\n".join(lines) + "\n"


def _render_group_markdown(add, idx: int, g: FindingGroup) -> None:
    cwe = g.cwe_id or "(no CWE)"
    issue_type = _group_issue_type(g)
    header = f"### Group {idx}: {cwe} — {issue_type} — {g.count} finding(s) in `{g.file_root}`"
    add(header)
    add("")
    summary = [
        f"**Max severity:** {g.max_severity}",
        f"**Language:** `{g.language or 'unknown'}`",
    ]
    add("  \n".join(summary))
    add("")

    if g.plan is None:
        add(f"> _No CFT plan available for {cwe}._ The taxonomy may not yet cover this CWE. "
            "Consider opening a request to add it.")
        add("")
    else:
        _render_plan_markdown(add, g.plan)

    add("**Affected findings:**")
    add("")
    add("| Severity | File | Line | Issue ID | Title | Details |")
    add("|---|---|---|---|---|---|")
    for f in sorted(g.findings, key=lambda x: (-SEVERITY_RANK.get(x.severity, -1), x.location.file_path or "")):
        file = (f.location.file_path or "?")
        line = str(f.location.line) if f.location.line else "—"
        fid = f.veracode_flaw_id or f.finding_id
        details = f"[view]({f.flaw_details_url})" if f.flaw_details_url else "—"
        add(f"| {f.severity} | `{file}` | {line} | `{fid}` | {f.title} | {details} |")
    add("")
    add("---")
    add("")


def _group_issue_type(g: FindingGroup) -> str:
    """Pick the most representative finding title to display in the group header."""
    if not g.findings:
        return "(unknown)"
    # All findings in a group share the CWE, so titles are typically uniform.
    # Use the most common title to be defensive against per-finding variance.
    counts: dict[str, int] = {}
    for f in g.findings:
        counts[f.title] = counts.get(f.title, 0) + 1
    return max(counts, key=counts.get)


def _render_plan_markdown(add, plan) -> None:
    """Render a cft.Plan as Markdown — terser than the resolver's standalone view."""
    if plan.notes:
        add(f"> {plan.notes}")
        add("")

    if plan.primary:
        add("**Primary fix (Sufficient — pick one):**")
        add("")
        for e in plan.primary:
            _render_entry(add, e, depth=1)
    elif plan.necessary:
        add("**Necessary controls:**")
        add("")
        for e in plan.necessary:
            _render_entry(add, e, depth=1)

    if plan.defense_in_depth:
        add("**Defense in depth (additional layers):**")
        add("")
        for e in plan.defense_in_depth:
            add(f"- `{e.cft_id}` — {e.sub_technique.name} (effort: {e.sub_technique.effort})")
        add("")

    if plan.partial:
        add("**Partial fixes (apply alongside the primary):**")
        add("")
        for e in plan.partial:
            add(f"- `{e.cft_id}` — {e.sub_technique.name}")
        add("")


def _render_entry(add, entry, depth: int) -> None:
    st = entry.sub_technique
    add(f"#### `{st.id}` — {st.name}")
    add("")
    add(f"**Effort:** {st.effort}  |  **Control:** {st.control_type}  |  **Actor:** {st.actor}")
    add("")
    add(st.description)
    add("")

    if entry.notes:
        add(f"> _Mapping note:_ {entry.notes}")
        add("")

    # Language guidance for the requested language only
    language = None
    if hasattr(entry.sub_technique, "language_guidance"):
        # Find a language entry to render (resolver should already have filtered)
        for lang, g in st.language_guidance.items():
            language = lang
            add(f"**Language guidance ({lang}):**")
            add("")
            if g.library:
                add(f"- _Library/API:_ {g.library}")
            if g.notes:
                add(f"- _Notes:_ {g.notes}")
            if g.example:
                add("")
                add("```")
                add(g.example.rstrip())
                add("```")
            add("")
            break  # one language entry is enough; the rest are mapped elsewhere

    # Verification block — render checklist + notes only; suppress regex
    # patterns (grep / semgrep rules) since they're noise in a remediation
    # report aimed at developers.
    if st.verification and (st.verification.checklist or st.verification.notes):
        add("**Verification:**")
        add("")
        if st.verification.checklist:
            add("- _checklist:_")
            for c in st.verification.checklist:
                add(f"  - {c}")
        if st.verification.notes:
            add(f"- _notes:_ {st.verification.notes}")
        add("")

    if st.common_mistakes:
        add("**Common mistakes:**")
        add("")
        for cm in st.common_mistakes[:3]:
            add(f"- {cm}")
        add("")

    if st.references:
        add("**References:**")
        add("")
        for r in st.references[:2]:
            add(f"- [{r.title}]({r.url})")
        add("")


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------

def render_json(report: Report) -> str:
    payload = {
        "scan_context": asdict(report.scan_context),
        "summary": {
            "total_findings": report.total_findings,
            "fix_groups": len(report.groups),
            "severity_counts": report.severity_counts,
            "skipped_mitigated": report.skipped_mitigated,
            "skipped_no_cwe": report.skipped_no_cwe,
            "skipped_below_severity": report.skipped_below_severity,
        },
        "filters": {
            "language": report.language_default,
            "effort_cap": report.effort_cap,
            "min_severity": report.min_severity,
        },
        "groups": [_group_to_dict(g) for g in report.groups],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _group_to_dict(g: FindingGroup) -> dict:
    return {
        "cwe_id": g.cwe_id,
        "issue_type": _group_issue_type(g),
        "file_root": g.file_root,
        "language": g.language,
        "max_severity": g.max_severity,
        "count": g.count,
        "findings": [_finding_to_dict(f) for f in g.findings],
        "plan": _plan_to_dict(g.plan) if g.plan else None,
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "finding_id": f.finding_id,
        "severity": f.severity,
        "title": f.title,
        "file": f.location.file_path,
        "line": f.location.line,
        "veracode_flaw_id": f.veracode_flaw_id,
        "mitigation_status": f.mitigation_status,
        "violates_policy": f.violates_policy,
        "flaw_details_url": f.flaw_details_url,
    }


def _plan_to_dict(plan) -> dict:
    return {
        "cwe_id": plan.cwe_id,
        "cwe_name": plan.cwe_name,
        "primary_domain": plan.primary_domain,
        "primary": [{"cft_id": e.cft_id, "name": e.sub_technique.name, "effort": e.sub_technique.effort} for e in plan.primary],
        "necessary": [{"cft_id": e.cft_id, "name": e.sub_technique.name, "effort": e.sub_technique.effort} for e in plan.necessary],
        "defense_in_depth": [{"cft_id": e.cft_id, "name": e.sub_technique.name} for e in plan.defense_in_depth],
    }
