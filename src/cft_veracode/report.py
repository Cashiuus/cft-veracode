"""Build and render the remediation report.

build_report() orchestrates: filter → dedupe → resolve CFT plans → assemble.
render_html() (default) / render_markdown() / render_json() emit the final output.
"""
from __future__ import annotations

import html
import json
import math
from dataclasses import asdict, dataclass
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
    skip_closed: bool = True,
    min_severity: Optional[str] = None,
) -> Report:
    """Group findings, resolve CFT plans, return a structured Report.

    Args:
        findings: List of Finding objects (already normalized).
        language: Optional override language code; otherwise inferred per group from file paths.
        effort_cap: Pass-through to cft.resolve (Low/Medium/High).
        skip_mitigated: Drop findings already marked ACCEPTED/MITIGATED in Veracode.
        skip_closed: Drop findings the scanner reports as CLOSED (REST API only).
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
    skipped_closed = 0
    min_rank = SEVERITY_RANK.get(min_severity, -1) if min_severity else -1

    kept: list[Finding] = []
    for f in findings:
        if skip_mitigated and f.is_mitigated:
            skipped_mitigated += 1
            continue
        # A finding the scanner reports CLOSED is no longer an open issue; drop
        # it before the CWE/severity filters so the count covers every closed
        # finding that wasn't already counted as mitigated.
        if skip_closed and f.is_closed:
            skipped_closed += 1
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
        skipped_closed=skipped_closed,
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
    add(f"- **Total findings (after filters):** {report.total_findings:,d}")
    add(f"- **Fix groups:** {len(report.groups):,d}")
    sev_counts = report.severity_counts
    if sev_counts:
        ordered = sorted(sev_counts.items(), key=lambda kv: -SEVERITY_RANK.get(kv[0], -1))
        sev_summary = ", ".join(f"{v:,d} {k}" for k, v in ordered)
        add(f"- **By severity:** {sev_summary}")
    if report.skipped_closed:
        add(f"- **Closed:** {report.skipped_closed:,d}")
    if report.skipped_mitigated:
        add(f"- _Skipped (already mitigated):_ {report.skipped_mitigated:,d}")
    if report.skipped_no_cwe:
        add(f"- _Skipped (no CWE on finding):_ {report.skipped_no_cwe:,d}")
    if report.skipped_below_severity:
        add(f"- _Skipped (below `{report.min_severity}` threshold):_ {report.skipped_below_severity:,d}")
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
            "skipped_closed": report.skipped_closed,
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

_SEVERITY_ORDER = ("VeryHigh", "High", "Medium", "Low", "VeryLow", "Informational")

# Effort label → relative weight for fix-first scoring. Lower effort ranks higher
# (a cheap fix for a serious issue is the best place to start).
_EFFORT_RANK = {"Low": 1, "Medium": 2, "High": 3}
_DEFAULT_EFFORT_WEIGHT = 2  # unknown/missing effort is treated as Medium

# The fix-first panel, filter controls, and findings index only render once a
# report is large enough to be hard to scroll. Smaller reports stay lean.
_LARGE_REPORT_GROUP_THRESHOLD = 10
_FIX_FIRST_LIMIT = 5


@dataclass(frozen=True)
class _GroupView:
    """Flattened, display-ready facts about one group.

    Computed once and shared by the fix-first panel, the index table, and the
    ``data-*`` attributes stamped on each group card so the client-side filter
    has a single source of truth.
    """
    idx: int
    severity: str
    severity_rank: int
    cwe: str            # display form, e.g. "CWE-89" or "(no CWE)"
    issue_type: str
    count: int
    language: str
    file_root: str
    effort: str         # "Low" | "Medium" | "High" | "Unknown"
    effort_rank: int
    score: float
    search_text: str    # lowercased blob for free-text matching


def _group_effort(g: FindingGroup) -> Optional[str]:
    """Effort of the group's recommended fix (primary, else necessary)."""
    plan = g.plan
    if plan is None:
        return None
    for attr in ("primary", "necessary"):
        entries = list(getattr(plan, attr, None) or [])
        if entries:
            return entries[0].sub_technique.effort
    return None


def _build_group_views(groups: list[FindingGroup]) -> list[_GroupView]:
    views: list[_GroupView] = []
    for idx, g in enumerate(groups, start=1):
        sev = g.max_severity
        sev_rank = SEVERITY_RANK.get(sev, -1)
        effort = _group_effort(g)
        effort_label = effort if effort in _EFFORT_RANK else "Unknown"
        effort_weight = _EFFORT_RANK.get(effort, _DEFAULT_EFFORT_WEIGHT)
        count = g.count
        # Severity dominates; finding count adds a damped (log) boost so a huge
        # low-severity group can't outrank a critical one; lower effort lifts the
        # score so quick wins surface first.
        score = (max(sev_rank, 0) * (1 + math.log10(count)) / effort_weight) if count else 0.0

        terms: list[str] = [g.cwe_id or "", _group_issue_type(g), g.language or "", g.file_root or ""]
        for f in g.findings:
            terms.append(f.title or "")
            terms.append(f.location.file_path or "")
            terms.append(f.veracode_flaw_id or f.finding_id or "")
        search_text = " ".join(t for t in terms if t).lower()

        views.append(_GroupView(
            idx=idx,
            severity=sev,
            severity_rank=sev_rank,
            cwe=g.cwe_id or "(no CWE)",
            issue_type=_group_issue_type(g),
            count=count,
            language=g.language or "Unknown",
            file_root=g.file_root or "",
            effort=effort_label,
            effort_rank=_EFFORT_RANK.get(effort, _DEFAULT_EFFORT_WEIGHT),
            score=score,
            search_text=search_text,
        ))
    return views

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

/* ---- Large-report enhancements: fix-first, controls, index ---- */
.fix-first {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 24px;
  margin-bottom: 24px;
}
.fix-first h2 {
  margin: 0 0 6px;
  font-size: 13px; font-weight: 600; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--text-dim);
}
.ff-intro { margin: 0 0 16px; font-size: 13.5px; color: var(--text-muted); }
.ff-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 12px;
}
.ff-card {
  display: block;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 16px;
  color: var(--text);
}
.ff-card:hover { border-color: var(--accent); text-decoration: none; }
.ff-card-top { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.ff-cwe { font-family: ui-monospace, Consolas, monospace; color: var(--accent); font-weight: 600; font-size: 13px; }
.ff-issue { font-weight: 600; font-size: 14.5px; margin-bottom: 6px; }
.ff-rationale { font-size: 12.5px; color: var(--text-muted); margin-bottom: 6px; }
.ff-loc { font-size: 12px; color: var(--text-dim); margin-bottom: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ff-loc code { background: transparent; padding: 0; color: var(--text-muted); }
.ff-jump { font-size: 12px; color: var(--accent); font-weight: 500; }

.controls {
  position: sticky; top: 0; z-index: 20;
  background: rgba(15, 20, 25, 0.92);
  backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px 18px;
  margin-bottom: 18px;
}
.controls-row { display: flex; flex-wrap: wrap; align-items: center; gap: 14px; }
.filter-group { display: flex; align-items: center; gap: 8px; }
.filter-group.grow { flex: 1; min-width: 180px; }
.filter-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-dim); }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  font: inherit; font-size: 12px;
  padding: 4px 12px; border-radius: 999px;
  background: var(--surface-2); color: var(--text-muted);
  border: 1px solid var(--border); cursor: pointer;
}
.chip:hover { color: var(--text); }
.chip.active { background: var(--accent-dim); color: var(--accent); border-color: var(--accent); }
.text-search, .cwe-search {
  width: 100%;
  font: inherit; font-size: 13px;
  padding: 7px 12px;
  background: var(--code-bg); color: var(--text);
  border: 1px solid var(--border); border-radius: 8px;
}
.text-search::placeholder, .cwe-search::placeholder { color: var(--text-dim); }
.dropdown { position: relative; }
.dropdown-toggle {
  font: inherit; font-size: 12.5px;
  padding: 6px 12px;
  background: var(--surface-2); color: var(--text);
  border: 1px solid var(--border); border-radius: 8px; cursor: pointer;
}
.dropdown-panel {
  position: absolute; top: calc(100% + 6px); left: 0; z-index: 30;
  width: 280px; max-height: 320px; overflow-y: auto;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 10px;
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
}
.dropdown-panel .cwe-search { margin-bottom: 8px; }
.cwe-options { display: flex; flex-direction: column; gap: 2px; }
.cwe-opt {
  display: flex; align-items: center; gap: 8px;
  padding: 5px 8px; border-radius: 6px; cursor: pointer; font-size: 13px;
}
.cwe-opt:hover { background: var(--surface-2); }
.cwe-opt > span:first-of-type { flex: 1; }
.cwe-count { color: var(--text-dim); font-size: 12px; }
.clear-btn {
  font: inherit; font-size: 12.5px;
  padding: 6px 12px; background: transparent; color: var(--text-muted);
  border: 1px solid var(--border); border-radius: 8px; cursor: pointer;
}
.clear-btn:hover { color: var(--text); border-color: var(--accent); }
.result-count { margin-top: 10px; font-size: 12.5px; color: var(--text-muted); }

.index-wrap {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 4px 8px; margin-bottom: 28px; overflow-x: auto;
}
table.index { margin: 0; font-size: 13px; }
table.index thead th[data-key] { cursor: pointer; user-select: none; white-space: nowrap; }
table.index thead th[data-key]:hover { color: var(--text-muted); }
table.index thead th[aria-sort="ascending"]::after { content: " ▲"; color: var(--accent); }
table.index thead th[aria-sort="descending"]::after { content: " ▼"; color: var(--accent); }
table.index td.num, table.index th.num { text-align: right; font-variant-numeric: tabular-nums; }
table.index .idx-num a { color: var(--text-dim); }
table.index .idx-loc code { background: transparent; padding: 0; color: var(--text-muted); }

.is-hidden { display: none !important; }

@media (max-width: 700px) {
  .container { padding: 20px 16px 60px; }
  .summary-stats { gap: 18px; }
  .summary-sev { margin-left: 0; width: 100%; }
  .group > summary, .group-body { padding-left: 16px; padding-right: 16px; }
  .controls { position: static; }
  .ff-grid { grid-template-columns: 1fr; }
}
"""

# Client-side filter / sort / navigation for large reports. Only emitted when
# the report exceeds the large-report threshold. Security notes:
#   * No innerHTML with dynamic data — all content is server-rendered and
#     escaped; JS only reads data-* attributes and toggles visibility classes.
#   * Free-text search uses String.indexOf, never a RegExp built from input.
#   * No eval, no inline handlers; everything wired via addEventListener.
_HTML_JS = """\
(function () {
  'use strict';
  var controls = document.querySelector('.controls');
  if (!controls) return;

  var groups = Array.prototype.slice.call(document.querySelectorAll('details.group'));
  var idxRows = Array.prototype.slice.call(document.querySelectorAll('tr.idx-row'));
  var groupByIdx = {};
  groups.forEach(function (g) { groupByIdx[g.dataset.idx] = g; });

  var state = { sev: Object.create(null), sevN: 0, cwe: Object.create(null), cweN: 0, q: '' };

  function matches(ds) {
    if (state.sevN && !state.sev[ds.severity]) return false;
    if (state.cweN && !state.cwe[ds.cwe]) return false;
    if (state.q && (ds.text || '').indexOf(state.q) === -1) return false;
    return true;
  }

  function apply() {
    var visGroups = 0, visFindings = 0;
    groups.forEach(function (g) {
      var ok = matches(g.dataset);
      g.classList.toggle('is-hidden', !ok);
      if (ok) { visGroups++; visFindings += (+g.dataset.count || 0); }
    });
    idxRows.forEach(function (r) { r.classList.toggle('is-hidden', !matches(r.dataset)); });

    var counter = controls.querySelector('.result-count');
    if (counter) {
      counter.textContent = 'Showing ' + visGroups.toLocaleString() + ' of ' +
        groups.length.toLocaleString() + ' groups \\u00b7 ' +
        visFindings.toLocaleString() + ' findings';
    }
    var clearBtn = controls.querySelector('.clear-btn');
    if (clearBtn) clearBtn.hidden = !(state.sevN || state.cweN || state.q);
  }

  controls.querySelectorAll('.chip[data-sev]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var s = btn.dataset.sev;
      if (state.sev[s]) { delete state.sev[s]; state.sevN--; btn.classList.remove('active'); btn.setAttribute('aria-pressed', 'false'); }
      else { state.sev[s] = true; state.sevN++; btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true'); }
      apply();
    });
  });

  var dd = controls.querySelector('[data-dropdown]');
  var toggle = dd && dd.querySelector('.dropdown-toggle');
  if (dd && toggle) {
    var panel = dd.querySelector('.dropdown-panel');
    toggle.addEventListener('click', function () {
      var willOpen = panel.hidden;
      panel.hidden = !willOpen;
      toggle.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
    });
    document.addEventListener('click', function (e) {
      if (!dd.contains(e.target)) { panel.hidden = true; toggle.setAttribute('aria-expanded', 'false'); }
    });
    var updateToggleLabel = function () {
      toggle.textContent = (state.cweN ? state.cweN + ' CWE' + (state.cweN > 1 ? 's' : '') + ' selected' : 'All CWEs') + ' \\u25be';
    };
    dd.querySelectorAll('.cwe-opt input[type=checkbox]').forEach(function (cb) {
      cb.addEventListener('change', function () {
        if (cb.checked) { state.cwe[cb.value] = true; state.cweN++; }
        else { delete state.cwe[cb.value]; state.cweN--; }
        updateToggleLabel();
        apply();
      });
    });
    var cweSearch = dd.querySelector('.cwe-search');
    if (cweSearch) {
      cweSearch.addEventListener('input', function () {
        var term = cweSearch.value.toLowerCase();
        dd.querySelectorAll('.cwe-opt').forEach(function (opt) {
          opt.style.display = opt.textContent.toLowerCase().indexOf(term) === -1 ? 'none' : '';
        });
      });
    }
  }

  var search = controls.querySelector('.text-search');
  if (search) {
    search.addEventListener('input', function () {
      state.q = search.value.trim().toLowerCase();
      apply();
    });
  }

  var clearBtn = controls.querySelector('.clear-btn');
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      state.sev = Object.create(null); state.sevN = 0;
      state.cwe = Object.create(null); state.cweN = 0;
      state.q = '';
      controls.querySelectorAll('.chip.active').forEach(function (b) { b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); });
      controls.querySelectorAll('.cwe-opt input[type=checkbox]').forEach(function (cb) { cb.checked = false; });
      if (search) search.value = '';
      if (toggle) toggle.textContent = 'All CWEs \\u25be';
      apply();
    });
  }

  function jumpTo(idx) {
    var g = groupByIdx[idx];
    if (!g) return;
    g.open = true;
    g.classList.remove('is-hidden');
    g.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  document.querySelectorAll('[data-jump]').forEach(function (el) {
    el.addEventListener('click', function (e) { e.preventDefault(); jumpTo(el.dataset.jump); });
  });

  var index = document.querySelector('table.index');
  if (index) {
    var tbody = index.querySelector('tbody');
    var numeric = { idx: 1, sevrank: 1, count: 1, effortrank: 1 };
    var access = function (key, r) {
      if (numeric[key]) return +r.dataset[key];
      return (r.dataset[key] || '').toLowerCase();
    };
    var sortState = { key: null, dir: 1 };
    index.querySelectorAll('th[data-key]').forEach(function (th) {
      th.addEventListener('click', function () {
        var key = th.dataset.key;
        if (sortState.key === key) sortState.dir *= -1;
        else { sortState.key = key; sortState.dir = 1; }
        var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr.idx-row'));
        rows.sort(function (a, b) {
          var va = access(key, a), vb = access(key, b);
          if (va < vb) return -sortState.dir;
          if (va > vb) return sortState.dir;
          return 0;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
        index.querySelectorAll('th[data-key]').forEach(function (h) { h.removeAttribute('aria-sort'); });
        th.setAttribute('aria-sort', sortState.dir > 0 ? 'ascending' : 'descending');
      });
    });
  }

  apply();
})();
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
        inner += f' <strong>{count:,d}</strong>'
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

    views = _build_group_views(report.groups)
    large = len(report.groups) > _LARGE_REPORT_GROUP_THRESHOLD

    parts.append(_render_html_header(report, title))
    parts.append(_render_html_summary(report))

    if not report.groups:
        parts.append('<div class="empty">No actionable findings after applying filters.</div>\n')
    else:
        if large:
            parts.append(_render_html_fix_first(views))
            parts.append(_render_html_controls(views))
            parts.append(_render_html_index(views))
        parts.append('<div class="groups-heading">Fix groups</div>\n')
        for view, g in zip(views, report.groups):
            parts.append(_render_html_group(view, g))

    parts.append('</div>\n')
    if large:
        parts.append(f'<script>\n{_HTML_JS}</script>\n')
    parts.append('</body>\n</html>\n')
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
    if report.skipped_closed:
        skipped_lines.append(f"<span>Closed: {report.skipped_closed:,d}</span>")
    if report.skipped_mitigated:
        skipped_lines.append(f"<span>Skipped (already mitigated): {report.skipped_mitigated:,d}</span>")
    if report.skipped_no_cwe:
        skipped_lines.append(f"<span>Skipped (no CWE on finding): {report.skipped_no_cwe:,d}</span>")
    if report.skipped_below_severity:
        skipped_lines.append(
            f"<span>Skipped (below <code>{_esc(report.min_severity)}</code> threshold): "
            f"{report.skipped_below_severity:,d}</span>"
        )
    skipped_html = (
        f'<div class="summary-skipped">{" · ".join(skipped_lines)}</div>'
        if skipped_lines else ""
    )

    # Open-finding label clarifies the count is open-only whenever we excluded
    # closed findings; otherwise keep the original neutral "Findings" wording.
    open_label = "Open findings" if report.skipped_closed else "Findings"
    closed_stat = (
        f'<div class="summary-stat"><span class="num">{report.skipped_closed:,d}'
        '</span><span class="label">Closed</span></div>\n'
        if report.skipped_closed else ""
    )

    return (
        '<section class="summary">\n'
        '<h2>Summary</h2>\n'
        '<p class="summary-intro">This report maps each Veracode finding to a concrete '
        'remediation plan from the CFT (Common Fix Taxonomy). Findings are grouped by CWE '
        'and location; expand any group below to see affected files and the recommended fix.'
        '</p>\n'
        '<div class="summary-stats">\n'
        f'<div class="summary-stat"><span class="num">{report.total_findings:,d}'
        f'</span><span class="label">{open_label}</span></div>\n'
        f'{closed_stat}'
        f'<div class="summary-stat"><span class="num">{len(report.groups):,d}'
        '</span><span class="label">Fix groups</span></div>\n'
        f'<div class="summary-sev">{"".join(sev_pills)}</div>\n'
        '</div>\n'
        f'{skipped_html}'
        '</section>\n'
    )


def _render_html_fix_first(views: list[_GroupView]) -> str:
    """Top groups by impact score — the report's decision surface."""
    ranked = sorted(
        views, key=lambda v: (v.score, v.severity_rank, v.count), reverse=True
    )[:_FIX_FIRST_LIMIT]

    cards: list[str] = []
    for v in ranked:
        effort_bit = f"{v.effort} effort" if v.effort != "Unknown" else "Effort unknown"
        plural = "s" if v.count != 1 else ""
        rationale = f"{v.severity} severity · {effort_bit} · {v.count:,d} finding{plural}"
        loc_html = (
            f'<div class="ff-loc"><code>{_esc(v.file_root)}</code></div>'
            if v.file_root else ""
        )
        cards.append(
            f'<a class="ff-card" href="#group-{v.idx}" data-jump="{v.idx}">'
            f'<div class="ff-card-top">{_sev_pill(v.severity)}'
            f'<span class="ff-cwe">{_esc(v.cwe)}</span></div>'
            f'<div class="ff-issue">{_esc(v.issue_type)}</div>'
            f'<div class="ff-rationale">{_esc(rationale)}</div>'
            f'{loc_html}'
            '<span class="ff-jump">Jump to group ↓</span>'
            '</a>'
        )

    return (
        '<section class="fix-first">\n'
        '<h2>Fix first</h2>\n'
        '<p class="ff-intro">Highest-impact groups, ranked by severity and finding '
        'count and weighted toward lower-effort fixes. Start here.</p>\n'
        f'<div class="ff-grid">{"".join(cards)}</div>\n'
        '</section>\n'
    )


def _render_html_controls(views: list[_GroupView]) -> str:
    """Sticky filter bar: severity chips, CWE multi-select, free-text search."""
    sev_chips = "".join(
        f'<button type="button" class="chip" data-sev="{_esc(s)}" '
        f'aria-pressed="false">{_esc(s)}</button>'
        for s in _SEVERITY_ORDER
        if any(v.severity == s for v in views)
    )

    # Distinct CWEs with their finding totals, ordered by severity then name.
    cwe_meta: dict[str, list[int]] = {}
    for v in views:
        m = cwe_meta.setdefault(v.cwe, [0, -1])  # [finding_total, max_sev_rank]
        m[0] += v.count
        m[1] = max(m[1], v.severity_rank)
    cwe_items = sorted(cwe_meta.items(), key=lambda kv: (-kv[1][1], kv[0]))
    cwe_opts = "".join(
        f'<label class="cwe-opt"><input type="checkbox" value="{_esc(cwe)}">'
        f'<span>{_esc(cwe)}</span><span class="cwe-count">{total:,d}</span></label>'
        for cwe, (total, _rank) in cwe_items
    )

    return (
        '<section class="controls">\n'
        '<div class="controls-row">\n'
        '<div class="filter-group"><span class="filter-label">Severity</span>'
        f'<div class="chips">{sev_chips}</div></div>\n'
        '<div class="filter-group"><span class="filter-label">CWE</span>'
        '<div class="dropdown" data-dropdown>'
        '<button type="button" class="dropdown-toggle" aria-expanded="false">All CWEs ▾</button>'
        '<div class="dropdown-panel" hidden>'
        '<input type="text" class="cwe-search" placeholder="Filter CWEs…" aria-label="Filter CWE list">'
        f'<div class="cwe-options">{cwe_opts}</div>'
        '</div></div></div>\n'
        '<div class="filter-group grow">'
        '<input type="search" class="text-search" '
        'placeholder="Search issue, file, CWE, or ID…" aria-label="Search findings"></div>\n'
        '<button type="button" class="clear-btn" hidden>Clear</button>\n'
        '</div>\n'
        '<div class="result-count" aria-live="polite"></div>\n'
        '</section>\n'
    )


def _render_html_index(views: list[_GroupView]) -> str:
    """Scannable one-row-per-group index that links down to each group."""
    rows: list[str] = []
    for v in views:
        rows.append(
            f'<tr class="idx-row" data-idx="{v.idx}" data-severity="{_esc(v.severity)}" '
            f'data-sevrank="{v.severity_rank}" data-cwe="{_esc(v.cwe)}" '
            f'data-effort="{_esc(v.effort)}" data-effortrank="{v.effort_rank}" '
            f'data-count="{v.count}" data-issue="{_esc(v.issue_type)}" '
            f'data-lang="{_esc(v.language)}" data-loc="{_esc(v.file_root)}" '
            f'data-text="{_esc(v.search_text)}">'
            f'<td class="idx-num"><a href="#group-{v.idx}" data-jump="{v.idx}">{v.idx}</a></td>'
            f'<td>{_sev_pill(v.severity)}</td>'
            f'<td class="idx-cwe"><a href="#group-{v.idx}" data-jump="{v.idx}">{_esc(v.cwe)}</a></td>'
            f'<td>{_esc(v.issue_type)}</td>'
            f'<td class="num">{v.count:,d}</td>'
            f'<td>{_esc(v.language)}</td>'
            f'<td>{_esc(v.effort)}</td>'
            f'<td class="idx-loc"><code>{_esc(v.file_root)}</code></td>'
            '</tr>'
        )

    return (
        '<div class="groups-heading">Findings index</div>\n'
        '<div class="index-wrap">\n'
        '<table class="index">\n'
        '<thead><tr>'
        '<th data-key="idx">#</th>'
        '<th data-key="sevrank">Severity</th>'
        '<th data-key="cwe">CWE</th>'
        '<th data-key="issue">Issue</th>'
        '<th data-key="count" class="num">Findings</th>'
        '<th data-key="lang">Language</th>'
        '<th data-key="effortrank">Effort</th>'
        '<th data-key="loc">Location</th>'
        '</tr></thead>\n'
        f'<tbody>{"".join(rows)}</tbody>\n'
        '</table>\n'
        '</div>\n'
    )


def _render_html_group(view: _GroupView, g: FindingGroup) -> str:
    idx = view.idx
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
        f'<details class="group" id="group-{idx}"'
        f' data-idx="{idx}"'
        f' data-severity="{_esc(view.severity)}"'
        f' data-sevrank="{view.severity_rank}"'
        f' data-cwe="{_esc(view.cwe)}"'
        f' data-effort="{_esc(view.effort)}"'
        f' data-count="{view.count}"'
        f' data-text="{_esc(view.search_text)}">\n'
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
