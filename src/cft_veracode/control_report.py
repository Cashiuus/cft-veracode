"""Render a fix-first control plan as single-file HTML.

The findings report in `report.py` answers "what is broken, and how do I fix each
one?" This answers the portfolio question instead: "which techniques, applied
where, retire the most risk per unit of effort — and what must a human confirm
before acting?"

It reuses the findings report's stylesheet and escaping so both documents look
like one product, adding only the rules the plan table needs.
"""
from __future__ import annotations

from typing import Optional

from cft.portfolio import CoverPlan, Portfolio
from cft_veracode.report import _HTML_CSS, _esc
from cft_veracode.types import ScanContext

_PLAN_CSS = """
.plan-table { width:100%; border-collapse:collapse; margin:8px 0 20px; font-size:13px; }
.plan-table th { text-align:left; padding:8px 10px; border-bottom:2px solid #2a3140;
  color:#8b97ab; font-weight:600; font-size:11px; text-transform:uppercase;
  letter-spacing:.04em; white-space:nowrap; }
.plan-table td { padding:9px 10px; border-bottom:1px solid #1e242f; vertical-align:top; }
.plan-table tr:hover td { background:#161b23; }
.plan-rank { color:#5c6675; font-variant-numeric:tabular-nums; width:1%; }
.plan-tech code { color:#7fd1e8; }
.plan-name { color:#c9d3e0; }
.plan-num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
.tag { display:inline-block; padding:1px 7px; border-radius:9px; font-size:10.5px;
  font-weight:600; letter-spacing:.02em; white-space:nowrap; }
.tag-elim { background:#123524; color:#5ddc9a; }
.tag-recur { background:#2e2415; color:#e0b567; }
.tag-part { background:#2a1f36; color:#c79ae8; }
.tag-conj { background:#1c2740; color:#8fb4f0; }
.tag-pref { background:#14303a; color:#6fc9e0; }
.tag-plain { background:#21262f; color:#8b97ab; }
.plan-bar { height:5px; border-radius:3px; background:#1e242f; overflow:hidden;
  min-width:64px; margin-top:5px; }
.plan-bar span { display:block; height:100%; background:linear-gradient(90deg,#2f7f5b,#5ddc9a); }
.confirm { border-left:3px solid #b98a2e; background:#1c1a14; padding:12px 16px;
  border-radius:0 6px 6px 0; margin:14px 0; }
.confirm h3 { margin:0 0 6px; font-size:14px; color:#e0b567; }
.confirm p { margin:0 0 8px; color:#a9b4c4; font-size:13px; line-height:1.55; }
.confirm ul { margin:6px 0 0 18px; padding:0; color:#a9b4c4; font-size:12.5px; }
.confirm li { margin:3px 0; }
.confirm code { color:#7fd1e8; }
.plan-stats { display:flex; flex-wrap:wrap; gap:10px; margin:14px 0 18px; }
.plan-stat { background:#141922; border:1px solid #222834; border-radius:8px;
  padding:10px 14px; min-width:120px; }
.plan-stat .v { font-size:20px; font-weight:650; color:#e6edf6;
  font-variant-numeric:tabular-nums; }
.plan-stat .k { font-size:10.5px; color:#8b97ab; text-transform:uppercase;
  letter-spacing:.05em; margin-top:2px; }
.residual { color:#8b97ab; font-size:12.5px; }
.residual code { color:#9fb0c6; }
"""


def _selection_tag(task) -> str:
    if task.kind == "partition":
        return '<span class="tag tag-part">whole partition</span>'
    if task.kind == "conjunction":
        return '<span class="tag tag-conj">all required</span>'
    if task.preference == 1:
        return '<span class="tag tag-pref">preferred</span>'
    if task.preference:
        return f'<span class="tag tag-plain">pref {task.preference}</span>'
    if task.group_id:
        return '<span class="tag tag-plain">interchangeable</span>'
    return '<span class="tag tag-plain">sole fix</span>'


def _durability_tag(task) -> str:
    if task.is_recurring:
        return '<span class="tag tag-recur">recurring</span>'
    return '<span class="tag tag-elim">eliminates class</span>'


def render_control_plan_html(
    portfolio: Portfolio,
    cover: CoverPlan,
    scan_context: Optional[ScanContext] = None,
    title: str = "CFT Control Plan",
) -> str:
    """Render the pivoted portfolio and its cover plan as one standalone page."""
    p: list[str] = []
    ctx = scan_context

    p.append(
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<meta name="color-scheme" content="dark">\n'
        f'<title>{_esc(title)}</title>\n'
        f'<style>\n{_HTML_CSS}{_PLAN_CSS}</style>\n'
        '</head>\n<body>\n<div class="container">\n'
    )

    sub: list[str] = []
    if ctx and ctx.app_name:
        sub.append(f"App: {_esc(ctx.app_name)}")
    if ctx and ctx.scan_type:
        sub.append(_esc(ctx.scan_type))
    if ctx and ctx.scanner:
        sub.append(_esc(ctx.scanner))
    p.append(
        f'<h1>{_esc(title)}</h1>\n'
        + (f'<div class="subtitle">{" · ".join(sub)}</div>\n' if sub else "")
        + '<p class="ff-intro">Ranked by weighted risk retired per unit of effort. '
        'The unit of work is the fix technique, not the finding — each row is one '
        'change applied at the listed number of sites.</p>\n'
    )

    # --- headline numbers ---
    stats = [
        (f"{cover.covered_pct:.0f}%", "weighted risk retired"),
        (str(len(cover.steps)), "techniques"),
        (f"{cover.total_cost:.1f}", "effort units"),
        (str(len(portfolio.items)), "findings addressed"),
    ]
    if portfolio.uncoverable:
        stats.append((str(len(portfolio.uncoverable)), "no closing fix"))
    p.append('<div class="plan-stats">')
    for v, k in stats:
        p.append(f'<div class="plan-stat"><div class="v">{_esc(v)}</div>'
                 f'<div class="k">{_esc(k)}</div></div>')
    p.append('</div>\n')

    # --- the plan ---
    if not cover.steps:
        p.append('<div class="empty">No coverable findings after applying filters.</div>\n')
    else:
        p.append('<table class="plan-table">\n<thead><tr>'
                 '<th>#</th><th>Technique</th><th>Selection</th><th>Durability</th>'
                 '<th class="plan-num">Effort</th><th class="plan-num">Sites</th>'
                 '<th class="plan-num">Findings</th><th class="plan-num">Cost</th>'
                 '<th>Cumulative</th></tr></thead>\n<tbody>\n')
        for s in cover.steps:
            t = s.task
            p.append(
                f'<tr><td class="plan-rank">{s.rank}</td>'
                f'<td class="plan-tech"><code>{_esc(t.key)}</code>'
                f'<div class="plan-name">{_esc(t.name)}</div></td>'
                f'<td>{_selection_tag(t)}</td>'
                f'<td>{_durability_tag(t)}</td>'
                f'<td class="plan-num">{_esc(t.effort)}</td>'
                f'<td class="plan-num">{len(s.sites)}</td>'
                f'<td class="plan-num">{len(s.newly_retired):,d}</td>'
                f'<td class="plan-num">{s.cost:.1f}</td>'
                f'<td class="plan-num">{s.cum_pct:.0f}%'
                f'<div class="plan-bar"><span style="width:{min(100.0, s.cum_pct):.1f}%"></span></div>'
                f'</td></tr>\n'
            )
        p.append('</tbody>\n</table>\n')

        for s in cover.steps:
            if s.task.applies_when:
                for cond in s.task.applies_when:
                    p.append(f'<p class="residual"><code>{_esc(s.task.key)}</code> '
                             f'applies when {_esc(cond)}</p>\n')

    # --- what a human must confirm ---
    if cover.context_gaps:
        p.append('<div class="confirm"><h3>Narrowable with sink context</h3>'
                 '<p>These techniques partition an axis and must be matched to each site '
                 'rather than chosen. The findings carried no context, so the plan applies '
                 'the whole partition — sound for any context, but more work than necessary.</p>'
                 '<ul>')
        for g in cover.context_gaps:
            p.append(f'<li><strong>{_esc(g.cwe_id)}</strong> · group <code>{_esc(g.group_id)}</code> '
                     f'on <code>{_esc(g.discriminator)}</code> — {g.item_count} findings; '
                     f'contexts: {", ".join(f"<code>{_esc(c)}</code>" for c in g.contexts)}</li>')
        p.append('</ul></div>\n')

    if cover.group_choices:
        p.append('<div class="confirm"><h3>Confirm which situation applies</h3>'
                 '<p>These CWEs cover several distinct situations, each with its own fix, and '
                 'the taxonomy states the distinction in prose that cannot be evaluated '
                 'automatically. A cheaper group may fix a different problem than the one '
                 'reported.</p><ul>')
        for c in cover.group_choices:
            p.append(f'<li><strong>{_esc(c.cwe_id)}</strong> — {c.item_count} findings'
                     '<ul>'
                     + "".join(f'<li>{_esc(a)}</li>' for a in c.applies_when)
                     + '</ul></li>')
        p.append('</ul></div>\n')

    if cover.legacy_ambiguous:
        p.append('<div class="confirm"><h3>Unverified technique choices</h3>'
                 '<p>These CWEs offer several techniques with no declared selection group, so '
                 'the choice was made on cost. This indicates a taxonomy artifact older than '
                 'v0.3 — re-bundle to remove the ambiguity.</p><ul>')
        for a in cover.legacy_ambiguous:
            p.append(f'<li><strong>{_esc(a.cwe_id)}</strong>: '
                     + ", ".join(f"<code>{_esc(o)}</code>" for o in a.options) + '</li>')
        p.append('</ul></div>\n')

    # --- what the plan does not cover ---
    if cover.residual or portfolio.uncoverable:
        p.append('<div class="groups-heading">Not covered</div>\n')
    if portfolio.uncoverable:
        cwes = sorted({i.cwe_id for i in portfolio.uncoverable})
        p.append(f'<p class="residual"><strong>{len(portfolio.uncoverable)} findings have no '
                 f'closing fix in the taxonomy</strong> — '
                 f'{", ".join(_esc(c) for c in cwes)}. These are umbrella or '
                 f'infrastructure-layer CWEs where no single technique closes the finding.</p>\n')
    if cover.residual:
        cwes = sorted({i.cwe_id for i in cover.residual})
        p.append(f'<p class="residual">{len(cover.residual)} coverable findings fell outside '
                 f'the plan\'s budget or target — {", ".join(_esc(c) for c in cwes)}.</p>\n')

    p.append('</div>\n</body>\n</html>\n')
    return "".join(p)
