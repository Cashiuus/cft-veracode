"""Build and render the remediation report.

build_report() orchestrates: filter → dedupe → resolve CFT plans → assemble.
render_html() (default) / render_markdown() / render_json() emit the final output.
"""
from __future__ import annotations

import html
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
    title_parts = ["Veracode Remediation Fix Plan"]
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

    # Clean header: just CWE + what it is. Count, severity, language, and
    # location all live in the metadata strip below — keeps the header
    # readable when file_root is long or there are many findings.
    add(f"### Group {idx}: {cwe} — {issue_type}")
    add("")

    # Metadata strip — single scan-line of key facts.
    add(
        f"**Findings:** {g.count}  |  "
        f"**Max severity:** {g.max_severity}  |  "
        f"**Language:** `{g.language or 'unknown'}`  "
    )
    add(f"**Location:** `{g.file_root}`")
    add("")

    # Affected findings — surfaced BEFORE the fix so the reader knows what
    # they're looking at (which files, which lines) before reading guidance.
    add("| Severity | Status | Issue ID | Title | Line | File |")
    add("|---|---|---|---|---|---|")
    for f in sorted(g.findings, key=lambda x: (-SEVERITY_RANK.get(x.severity, -1), x.location.file_path or "")):
        file = (f.location.file_path or "?")
        line = str(f.location.line) if f.location.line else "—"
        fid = f.veracode_flaw_id or f.finding_id
        status = f.status or "—"
        add(f"| {f.severity} | {status} | `{fid}` | {f.title} | {line} | `{file}` |")
    add("")

    # Recommended remediation last — the "what to do about it" comes after
    # the "what is it" so devs scan the findings table first.
    if g.plan is None:
        add(f"> _No CFT plan available for {cwe}._ The taxonomy may not yet cover this CWE. "
            "Consider opening a request to add it.")
        add("")
    else:
        _render_plan_markdown(add, g.plan)

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
            _render_entry(add, e, plan.language)
    elif plan.necessary:
        add("**Necessary controls:**")
        add("")
        for e in plan.necessary:
            _render_entry(add, e, plan.language)

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


def _render_entry(add, entry, language: Optional[str]) -> None:
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

    # Language guidance: render only the guidance matching the plan's language.
    # The resolver passes the full language_guidance map through without
    # filtering, so the picker here must be explicit — iterating dict.items()
    # and breaking would pick whichever key happens to come first (almost
    # always "java"), regardless of the actual codebase language.
    guidance_map = getattr(st, "language_guidance", None) or {}
    if language and language in guidance_map:
        g = guidance_map[language]
        add(f"**Language guidance ({language}):**")
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

    # Verification block — render checklist only. grep_pattern and notes are
    # suppressed: the pattern is scanner-tool noise, and the notes are
    # predominantly commentary about that pattern.
    if st.verification and st.verification.checklist:
        add("**Verification:**")
        add("")
        for c in st.verification.checklist:
            add(f"- {c}")
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
        "status": f.status,
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


# ---------------------------------------------------------------------------
# HTML rendering (default output format)
# ---------------------------------------------------------------------------

_SEVERITY_CSS_CLASS = {
    "VeryHigh":      "sev-veryhigh",
    "High":          "sev-high",
    "Medium":        "sev-medium",
    "Low":           "sev-low",
    "VeryLow":       "sev-verylow",
    "Informational": "sev-info",
}

# Single-file standalone HTML. Embedded CSS only — no external dependencies,
# no JS, no fonts. Report must be email-able and viewable offline.
_HTML_CSS = """\
:root {
  --bg:          #0f1419;
  --surface:     #181f28;
  --surface-2:   #1f2731;
  --border:      #2a3441;
  --text:        #e4e6eb;
  --text-muted:  #8b95a7;
  --text-dim:    #6b7585;
  --accent:      #4ea1ff;
  --accent-dim:  rgba(78, 161, 255, 0.12);
  --code-bg:     #0b0f14;

  --sev-veryhigh: #ff4d6d;
  --sev-high:     #ff8a3d;
  --sev-medium:   #ffd23f;
  --sev-low:      #4ea1ff;
  --sev-verylow:  #94a3b8;
  --sev-info:     #64748b;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre, .mono {
  font-family: ui-monospace, "Cascadia Code", "JetBrains Mono", Consolas,
               "Liberation Mono", monospace;
  font-size: 13px;
}
code { background: var(--code-bg); padding: 1px 6px; border-radius: 4px; color: #cdd6e2; }
pre {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 16px;
  overflow-x: auto;
  color: #cdd6e2;
  margin: 12px 0;
}
pre code { background: transparent; padding: 0; }

.container { max-width: 1200px; margin: 0 auto; padding: 32px 28px 80px; }

/* Header */
.header {
  border-bottom: 1px solid var(--border);
  padding-bottom: 24px;
  margin-bottom: 28px;
}
.header h1 {
  margin: 0 0 6px 0;
  font-size: 26px;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.header .subtitle {
  color: var(--text-muted);
  font-size: 14px;
  margin-bottom: 14px;
}
.meta-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 14px;
  color: var(--text-muted);
  font-size: 13px;
}
.meta-strip .meta-label { color: var(--text-dim); margin-right: 4px; }

/* Summary card */
.summary {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 28px;
}
.summary h2 {
  margin: 0 0 14px 0;
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-dim);
}
.summary-intro {
  font-size: 14px;
  line-height: 1.6;
  color: var(--text);
  margin: 0 0 18px;
  padding: 12px 16px;
  background: rgba(78, 161, 255, 0.10);
  border: 1px solid rgba(78, 161, 255, 0.22);
  border-radius: 8px;
}
.summary-intro strong { color: var(--text); }
.summary-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 28px;
  align-items: center;
}
.summary-stat .num {
  font-size: 28px;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text);
  display: block;
}
.summary-stat .label {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-dim);
}
.summary-sev {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-left: auto;
}
.summary-skipped {
  margin-top: 14px;
  font-size: 13px;
  color: var(--text-muted);
}

/* Severity pills */
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 500;
  background: var(--surface-2);
  color: var(--text-muted);
  border: 1px solid var(--border);
  white-space: nowrap;
}
.pill .dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: currentColor;
  flex-shrink: 0;
}
.pill.sev-veryhigh { color: var(--sev-veryhigh); border-color: rgba(255, 77, 109, 0.4); background: rgba(255, 77, 109, 0.08); }
.pill.sev-high     { color: var(--sev-high);     border-color: rgba(255, 138, 61, 0.4); background: rgba(255, 138, 61, 0.08); }
.pill.sev-medium   { color: var(--sev-medium);   border-color: rgba(255, 210, 63, 0.4); background: rgba(255, 210, 63, 0.08); }
.pill.sev-low      { color: var(--sev-low);      border-color: rgba(78, 161, 255, 0.4); background: rgba(78, 161, 255, 0.08); }
.pill.sev-verylow  { color: var(--sev-verylow);  border-color: rgba(148, 163, 184, 0.4); background: rgba(148, 163, 184, 0.08); }
.pill.sev-info     { color: var(--sev-info);     border-color: rgba(100, 116, 139, 0.4); background: rgba(100, 116, 139, 0.08); }

.pill.tag { font-weight: 400; color: var(--text-muted); }
.pill.tag strong { color: var(--text); font-weight: 600; margin-right: 2px; }

/* Group cards */
.group {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 18px;
  overflow: hidden;
}
.group > summary {
  list-style: none;
  cursor: pointer;
  padding: 18px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
  user-select: none;
}
.group > summary::-webkit-details-marker { display: none; }
.group > summary::before {
  content: "▾";
  color: var(--text-dim);
  font-size: 13px;
  width: 12px;
  flex-shrink: 0;
  transition: transform 0.15s ease;
}
.group:not([open]) > summary::before { transform: rotate(-90deg); }
.group > summary:hover { background: var(--surface-2); }

.group-header {
  flex: 1;
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
  min-width: 0;
}
.group-num {
  color: var(--text-dim);
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.01em;
  flex-shrink: 0;
}
.group-cwe {
  font-weight: 600;
  font-size: 16px;
  color: var(--accent);
  font-family: ui-monospace, Consolas, monospace;
  flex-shrink: 0;
}
.group-title { color: var(--text); font-weight: 500; font-size: 16px; }

.group-body { padding: 22px 24px 26px; }

/* Metadata strip for each group */
.group-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 18px;
}
.group-summary-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.group-location {
  color: var(--text-muted);
  font-size: 13px;
}
.group-location .path { color: var(--text); }

/* Findings table */
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13.5px;
  margin-bottom: 22px;
}
thead th {
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-dim);
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
}
tbody td {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(42, 52, 65, 0.5);
  color: var(--text);
  vertical-align: top;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: var(--surface-2); }
tbody td.severity { white-space: nowrap; }
tbody td.file { color: var(--text); }

/* Plan section */
.plan-note {
  background: var(--accent-dim);
  border-left: 3px solid var(--accent);
  padding: 12px 16px;
  border-radius: 0 6px 6px 0;
  margin-bottom: 20px;
  color: var(--text);
  font-size: 14px;
}
.plan-section-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin: 20px 0 10px;
}
.plan-list { list-style: none; padding: 0; margin: 0; }
.plan-list .secondary {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 14px;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.plan-list .cft-id { font-family: ui-monospace, Consolas, monospace; color: var(--accent); font-weight: 500; }

/* CFT entry card */
.cft-entry {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 20px;
  margin-bottom: 12px;
}
.cft-entry-header {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 4px;
}
.cft-entry-header .cft-id {
  font-family: ui-monospace, Consolas, monospace;
  color: var(--accent);
  font-weight: 600;
  font-size: 14px;
}
.cft-entry-header .cft-name { font-size: 15px; font-weight: 600; color: var(--text); }
.cft-entry-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 10px 0 12px;
}
.cft-entry p.desc { margin: 0 0 12px; color: var(--text); }
.cft-entry .mapping-note {
  background: var(--accent-dim);
  border-left: 2px solid var(--accent);
  padding: 8px 12px;
  border-radius: 0 4px 4px 0;
  margin-bottom: 14px;
  font-size: 13.5px;
  color: var(--text);
}

.lang-block-label, .vrfy-label, .cm-label, .ref-label {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin: 14px 0 6px;
}
.lang-library { font-size: 13.5px; margin: 0 0 4px; color: var(--text-muted); }
.lang-library code { color: var(--text); }
.lang-notes { font-size: 13px; color: var(--text-muted); margin: 0 0 8px; font-style: italic; }
ul.checklist, ul.common-mistakes, ul.references {
  margin: 4px 0 0;
  padding-left: 22px;
  font-size: 13.5px;
  color: var(--text);
}
ul.checklist li, ul.common-mistakes li, ul.references li { margin: 3px 0; }

.empty {
  text-align: center;
  color: var(--text-muted);
  padding: 60px 20px;
  font-size: 14px;
}
.groups-heading {
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin: 28px 0 14px;
}

@media (max-width: 700px) {
  .container { padding: 20px 16px 60px; }
  .summary-stats { gap: 18px; }
  .summary-sev { margin-left: 0; width: 100%; }
  .group > summary, .group-body { padding-left: 16px; padding-right: 16px; }
}
"""


def _esc(text) -> str:
    """HTML-escape a value (None → empty string)."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


def _sev_pill(severity: str, count: Optional[int] = None) -> str:
    """Render a severity pill with optional count badge."""
    css = _SEVERITY_CSS_CLASS.get(severity, "sev-info")
    label = _esc(severity)
    inner = f'<span class="dot"></span>{label}'
    if count is not None:
        inner += f' <strong>{count}</strong>'
    return f'<span class="pill {css}">{inner}</span>'


def render_html(report: Report) -> str:
    """Render the Report as a single-file HTML document with dark theme."""
    parts: list[str] = []
    # ctx = report.scan_context

    title = "Veracode Remediation Fix Plan Report"

    parts.append(
        '<!DOCTYPE html>\n'
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<meta name="color-scheme" content="dark">\n'
        f'<title>{_esc(title)}</title>\n'
        f'<style>\n{_HTML_CSS}</style>\n'
        '</head>\n<body>\n<div class="container">\n'
    )

    parts.append(_render_html_header(report, title))
    parts.append(_render_html_summary(report))

    if not report.groups:
        parts.append('<div class="empty">No actionable findings after applying filters.</div>\n')
    else:
        parts.append('<div class="groups-heading">Fix groups</div>\n')
        for idx, g in enumerate(report.groups, start=1):
            parts.append(_render_html_group(idx, g))

    parts.append('</div>\n</body>\n</html>\n')
    return "".join(parts)


def _render_html_header(report: Report, title: str) -> str:
    ctx = report.scan_context
    subtitle_parts: list[str] = []
    if ctx.app_name:
        subtitle_parts.append(f"App: {_esc(ctx.app_name)}")
    if ctx.scan_type:
        subtitle_parts.append(_esc(ctx.scan_type))
    if ctx.tool_name:
        tv = f" {ctx.tool_version}" if ctx.tool_version else ""
        subtitle_parts.append(_esc(f"{ctx.tool_name}{tv}"))
    subtitle = " · ".join(subtitle_parts) if subtitle_parts else ""

    meta_bits: list[str] = []
    # if ctx.app_name:
        # meta_bits.append(f'<span><span class="meta-label">App Name:</span>{_esc(ctx.app_name)}</span>')
    if ctx.scanner:
        meta_bits.append(f'<span><span class="meta-label">Source:</span>{_esc(ctx.scanner)}</span>')
    if ctx.scan_id:
        meta_bits.append(f'<span><span class="meta-label">Scan ID:</span><code>{_esc(ctx.scan_id)}</code></span>')
    if ctx.sandbox:
        meta_bits.append(f'<span><span class="meta-label">Sandbox:</span>{_esc(ctx.sandbox)}</span>')
    if ctx.scan_date:
        meta_bits.append(f'<span><span class="meta-label">Scan date:</span>{_esc(ctx.scan_date)}</span>')

    meta_html = (
        f'<div class="meta-strip">{"".join(meta_bits)}</div>\n'
        if meta_bits else ""
    )

    return (
        '<header class="header">\n'
        f'<h1>{_esc(title)}</h1>\n'
        f'<div class="subtitle">{subtitle}</div>\n'
        f'{meta_html}'
        '</header>\n'
    )


def _render_html_summary(report: Report) -> str:
    sev_pills: list[str] = []
    for sev in ("VeryHigh", "High", "Medium", "Low", "VeryLow", "Informational"):
        count = report.severity_counts.get(sev)
        if count:
            sev_pills.append(_sev_pill(sev, count))

    skipped_lines: list[str] = []
    if report.skipped_mitigated:
        skipped_lines.append(f"<span>Skipped (already mitigated): {report.skipped_mitigated}</span>")
    if report.skipped_no_cwe:
        skipped_lines.append(f"<span>Skipped (no CWE on finding): {report.skipped_no_cwe}</span>")
    if report.skipped_below_severity:
        skipped_lines.append(
            f"<span>Skipped (below <code>{_esc(report.min_severity)}</code> threshold): "
            f"{report.skipped_below_severity}</span>"
        )
    skipped_html = (
        f'<div class="summary-skipped">{" · ".join(skipped_lines)}</div>'
        if skipped_lines else ""
    )

    return (
        '<section class="summary">\n'
        '<h2>Summary</h2>\n'
        '<p class="summary-intro">This report maps each Veracode finding to a concrete '
        'remediation plan from the CFT (Common Fix Taxonomy). Findings are grouped by CWE '
        'and location; expand any group below to see affected files and the recommended fix.'
        '</p>\n'
        '<div class="summary-stats">\n'
        f'<div class="summary-stat"><span class="num">{report.total_findings}'
        '</span><span class="label">Findings</span></div>\n'
        f'<div class="summary-stat"><span class="num">{len(report.groups)}'
        '</span><span class="label">Fix groups</span></div>\n'
        f'<div class="summary-sev">{"".join(sev_pills)}</div>\n'
        '</div>\n'
        f'{skipped_html}'
        '</section>\n'
    )


def _render_html_group(idx: int, g: FindingGroup) -> str:
    cwe = g.cwe_id or "(no CWE)"
    issue_type = _group_issue_type(g)

    meta_pills = (
        f'{_sev_pill(g.max_severity)}'
        f'<span class="pill tag"><strong>{g.count}</strong>finding{"s" if g.count != 1 else ""}</span>'
        f'<span class="pill tag"><strong>Language</strong><code>{_esc(g.language or "Unknown")}</code></span>'
    )

    location_html = (
        f'<div class="group-location"><span class="meta-label">Location: </span>'
        f'<code class="path">{_esc(g.file_root)}</code></div>\n'
    )

    rows: list[str] = []
    for f in sorted(g.findings, key=lambda x: (-SEVERITY_RANK.get(x.severity, -1), x.location.file_path or "")):
        file_path = _esc(f.location.file_path or "?")
        line = _esc(f.location.line) if f.location.line else "—"
        fid = _esc(f.veracode_flaw_id or f.finding_id)
        status = _esc(f.status) if f.status else "—"
        rows.append(
            "<tr>"
            f'<td class="severity">{_sev_pill(f.severity)}</td>'
            f'<td>{status}</td>'
            f'<td><code>{fid}</code></td>'
            f'<td>{_esc(f.title)}</td>'
            f'<td>{line}</td>'
            f'<td class="file"><code>{file_path}</code></td>'
            "</tr>"
        )

    findings_table = (
        '<table>\n'
        '<thead><tr><th>Severity</th><th>Status</th><th>Issue ID</th>'
        '<th>Title</th><th>Line</th><th>File</th></tr></thead>\n'
        f'<tbody>{"".join(rows)}</tbody>\n'
        '</table>\n'
    )

    plan_html = _render_html_plan(g.plan) if g.plan else (
        f'<div class="plan-note"><em>No CFT plan available for {_esc(cwe)}.</em> '
        "The taxonomy may not yet cover this CWE.</div>\n"
    )

    return (
        f'<details class="group" id="group-{idx}">\n'
        '<summary>\n'
        '<div class="group-summary-content">\n'
        '<div class="group-header">\n'
        f'<span class="group-num">Group {idx}:</span>\n'
        f'<span class="group-cwe">{_esc(cwe)}</span>\n'
        f'<span class="group-title">{_esc(issue_type)}</span>\n'
        '</div>\n'
        f'{location_html}'
        '</div>\n'
        f'{_sev_pill(g.max_severity)}\n'
        '</summary>\n'
        '<div class="group-body">\n'
        f'<div class="group-meta">{meta_pills}</div>\n'
        f'{findings_table}'
        f'{plan_html}'
        '</div>\n'
        '</details>\n'
    )


def _render_html_plan(plan) -> str:
    parts: list[str] = []
    if plan.notes:
        parts.append(f'<div class="plan-note">{_esc(plan.notes)}</div>\n')

    primary = list(plan.primary)
    necessary = list(plan.necessary)
    did = list(plan.defense_in_depth)
    partial = list(plan.partial)

    if primary:
        parts.append('<div class="plan-section-label">Primary fix (Sufficient — pick one)</div>\n')
        for e in primary:
            parts.append(_render_html_entry(e, plan.language))
    elif necessary:
        parts.append('<div class="plan-section-label">Necessary controls</div>\n')
        for e in necessary:
            parts.append(_render_html_entry(e, plan.language))

    if did:
        parts.append('<div class="plan-section-label">Defense in depth (additional layers)</div>\n')
        parts.append('<ul class="plan-list">\n')
        for e in did:
            parts.append(
                '<li class="secondary">'
                f'<span class="cft-id">{_esc(e.cft_id)}</span>'
                f'<span>{_esc(e.sub_technique.name)}</span>'
                f'<span class="pill tag" style="margin-left:auto"><strong>Effort</strong>{_esc(e.sub_technique.effort)}</span>'
                '</li>\n'
            )
        parts.append('</ul>\n')

    if partial:
        parts.append('<div class="plan-section-label">Partial fixes (apply alongside the primary)</div>\n')
        parts.append('<ul class="plan-list">\n')
        for e in partial:
            parts.append(
                '<li class="secondary">'
                f'<span class="cft-id">{_esc(e.cft_id)}</span>'
                f'<span>{_esc(e.sub_technique.name)}</span>'
                '</li>\n'
            )
        parts.append('</ul>\n')

    return "".join(parts)


def _render_html_entry(entry, language: Optional[str]) -> str:
    st = entry.sub_technique
    pills = (
        f'<span class="pill tag"><strong>Effort</strong>{_esc(st.effort)}</span>'
        f'<span class="pill tag"><strong>Control</strong>{_esc(st.control_type)}</span>'
        f'<span class="pill tag"><strong>Actor</strong>{_esc(st.actor)}</span>'
    )

    mapping_note_html = (
        f'<div class="mapping-note"><em>Mapping note:</em> {_esc(entry.notes)}</div>\n'
        if entry.notes else ""
    )

    # Language guidance — same rule as the markdown renderer: only render the
    # language the plan was resolved for. Avoids the dictionary-iteration bug
    # that previously rendered Java guidance for C# codebases.
    lang_html = ""
    guidance_map = getattr(st, "language_guidance", None) or {}
    if language and language in guidance_map:
        g = guidance_map[language]
        bits: list[str] = []
        if g.library:
            bits.append(f'<div class="lang-library">{_esc(g.library)}</div>')
        if g.notes:
            bits.append(f'<div class="lang-notes">{_esc(g.notes)}</div>')
        if g.example:
            bits.append(f'<pre><code>{_esc(g.example.rstrip())}</code></pre>')
        lang_html = (
            f'<div class="lang-block-label">Language guidance ({_esc(language)})</div>\n'
            + "".join(bits)
        )

    verification_html = ""
    if st.verification and st.verification.checklist:
        items = "".join(f"<li>{_esc(c)}</li>" for c in st.verification.checklist)
        verification_html = (
            '<div class="vrfy-label">Verification</div>\n'
            f'<ul class="checklist">{items}</ul>\n'
        )

    mistakes_html = ""
    if st.common_mistakes:
        items = "".join(f"<li>{_esc(cm)}</li>" for cm in st.common_mistakes[:3])
        mistakes_html = (
            '<div class="cm-label">Common mistakes</div>\n'
            f'<ul class="common-mistakes">{items}</ul>\n'
        )

    refs_html = ""
    if st.references:
        items = "".join(
            f'<li><a href="{_esc(r.url)}" target="_blank" rel="noopener">{_esc(r.title)}</a></li>'
            for r in st.references[:2]
        )
        refs_html = (
            '<div class="ref-label">References</div>\n'
            f'<ul class="references">{items}</ul>\n'
        )

    return (
        '<div class="cft-entry">\n'
        '<div class="cft-entry-header">'
        f'<span class="cft-id">{_esc(st.id)}</span>'
        f'<span class="cft-name">{_esc(st.name)}</span>'
        '</div>\n'
        f'<div class="cft-entry-pills">{pills}</div>\n'
        f'<p class="desc">{_esc(st.description)}</p>\n'
        f'{mapping_note_html}'
        f'{lang_html}'
        f'{verification_html}'
        f'{mistakes_html}'
        f'{refs_html}'
        '</div>\n'
    )
