"""Adapt normalized findings to the scanner-agnostic portfolio planner.

This is the Layer 3 half of the fix-first reporting path: it decides what a
Veracode finding is *worth* (weight) and *where* its fix lands (site), then hands
off to `cft.portfolio`, which knows nothing about Veracode.

    findings ──► Item[] ──► pivot() ──► Portfolio ──► plan_cover() ──► CoverPlan
    (here)      (here)         └────────── cft-resolver, Layer 2 ──────────┘

Any other adapter — SARIF from Argus, Snyk, a control-gap scanner — supplies its
own `to_items()` and gets the same planning and reporting for free.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from cft.portfolio import (
    CostModel,
    CoverPlan,
    Item,
    Portfolio,
    plan_cover,
    pivot,
    render_cover_markdown,
    render_portfolio_markdown,
)
from cft_veracode.dedupe import _file_root
from cft_veracode.language import infer_language
from cft_veracode.types import Finding

# Severity → weight. Superlinear on purpose: the linear 5..0 Veracode scale
# understates criticals, and a planner optimizing a linear scale will happily
# trade one VeryHigh for two Mediums.
SEVERITY_WEIGHT: dict[str, float] = {
    "VeryHigh": 16.0,
    "High": 8.0,
    "Medium": 4.0,
    "Low": 2.0,
    "VeryLow": 1.0,
    "Informational": 0.5,
}

# Findings that break policy block a release, so they are worth more than their
# severity alone suggests.
POLICY_MULTIPLIER = 1.5


def to_items(
    findings: Iterable[Finding],
    *,
    severity_weight: Optional[dict[str, float]] = None,
    policy_multiplier: float = POLICY_MULTIPLIER,
    skip_mitigated: bool = True,
    site_of=None,
    context_of=None,
) -> list[Item]:
    """Reduce findings to planner Items.

    Findings without a CWE are dropped — the planner is CWE-keyed and the
    existing report already accounts for them via `skipped_no_cwe`.

    Args:
        findings: Normalized findings from any ingest path.
        severity_weight: Override the severity → weight table.
        policy_multiplier: Multiplier for findings with `violates_policy` true.
        skip_mitigated: Drop findings with an accepted mitigation.
        site_of: Optional callable Finding -> str, to choose fix-site
            granularity. Defaults to the finding's parent directory. Coarser
            sites (module or service root) produce fewer, larger fix tasks;
            finer sites produce more precise but more numerous ones.
        context_of: Optional callable Finding -> str|None returning the sink
            context on the relevant taxonomy discriminator axis (e.g.
            "html_body", "at_rest"). Left unset by default and deliberately so:
            Veracode findings do not report sink context, and a file extension
            cannot distinguish an HTML-body sink from a JS-string sink inside the
            same .jsp. Without it the planner applies whole partitions rather
            than guessing, which is the correct trade. Supply this only where the
            scanner genuinely carries the signal — a dataflow-aware producer such
            as Argus is the natural source.
    """
    weights = severity_weight or SEVERITY_WEIGHT
    out: list[Item] = []
    for f in findings:
        if not f.cwe_id:
            continue
        if skip_mitigated and f.is_mitigated:
            continue
        if f.is_closed:
            continue
        w = weights.get(f.severity, 1.0)
        if f.violates_policy:
            w *= policy_multiplier
        site = site_of(f) if site_of else _file_root(f.location.file_path)
        loc = f.location.file_path or "?"
        if f.location.line:
            loc = f"{loc}:{f.location.line}"
        out.append(Item(
            key=f.finding_id,
            cwe_id=f.cwe_id,
            site=site,
            weight=w,
            label=f"{f.title} ({loc})",
            context=context_of(f) if context_of else None,
        ))
    return out


def language_resolver(findings: Iterable[Finding]):
    """Build a per-Item language lookup from finding file paths.

    Mixed-language monorepos are the normal case, so language is resolved per
    item rather than once for the whole scan.
    """
    by_key: dict[str, Optional[str]] = {}
    for f in findings:
        if f.cwe_id:
            by_key[f.finding_id] = infer_language(f.location.file_path)

    def _lookup(item: Item) -> Optional[str]:
        return by_key.get(item.key)

    return _lookup


@dataclass(frozen=True)
class ControlPlan:
    """Fix-first view of a scan: the pivoted portfolio plus a sequenced cover."""
    portfolio: Portfolio
    cover: CoverPlan
    scan_context: Optional[object] = None   # ScanContext; kept loose to avoid a cycle

    def to_markdown(self) -> str:
        return (
            render_cover_markdown(self.cover)
            + "\n\n---\n\n"
            + render_portfolio_markdown(self.portfolio)
        )

    def to_html(self) -> str:
        from cft_veracode.control_report import render_control_plan_html
        return render_control_plan_html(
            self.portfolio, self.cover, self.scan_context
        )

    def to_json(self) -> str:
        import json

        def _task(t):
            return {
                "key": t.key,
                "members": [m.id for m in t.members],
                "name": t.name,
                "kind": t.kind,
                "group": t.group_id,
                "preference": t.preference,
                "strength": t.strength,
                "effort": t.effort,
                "recurring": t.is_recurring,
                "cwe_ids": list(t.cwe_ids),
                "applies_when": list(t.applies_when),
            }

        return json.dumps({
            "summary": {
                "techniques": len(self.cover.steps),
                "covered_pct": round(self.cover.covered_pct, 2),
                "total_cost": round(self.cover.total_cost, 3),
                "findings_addressed": len(self.portfolio.items),
                "uncoverable": len(self.portfolio.uncoverable),
                "unmapped": len(self.portfolio.unmapped),
            },
            "steps": [
                {
                    "rank": s.rank,
                    "task": _task(s.task),
                    "sites": list(s.sites),
                    "findings": [i.key for i in s.newly_retired],
                    "weight": round(s.new_weight, 3),
                    "cost": round(s.cost, 3),
                    "cumulative_pct": round(s.cum_pct, 2),
                }
                for s in self.cover.steps
            ],
            "confirm": {
                "context_gaps": [
                    {
                        "cwe_id": g.cwe_id, "group": g.group_id,
                        "discriminator": g.discriminator,
                        "contexts": list(g.contexts), "findings": g.item_count,
                    }
                    for g in self.cover.context_gaps
                ],
                "group_choices": [
                    {
                        "cwe_id": c.cwe_id, "groups": list(c.groups),
                        "applies_when": list(c.applies_when), "findings": c.item_count,
                    }
                    for c in self.cover.group_choices
                ],
                "legacy_ambiguous": [
                    {"cwe_id": a.cwe_id, "options": list(a.options)}
                    for a in self.cover.legacy_ambiguous
                ],
            },
            "not_covered": {
                "residual": [
                    {"key": i.key, "cwe_id": i.cwe_id, "site": i.site}
                    for i in self.cover.residual
                ],
                "uncoverable": [
                    {"key": i.key, "cwe_id": i.cwe_id, "site": i.site}
                    for i in self.portfolio.uncoverable
                ],
            },
        }, indent=2)


def build_control_plan(
    findings: Iterable[Finding],
    *,
    language: Optional[str] = None,
    effort_cap: Optional[str] = None,
    budget: Optional[float] = None,
    target_pct: Optional[float] = None,
    cost_model: Optional[CostModel] = None,
    skip_mitigated: bool = True,
    site_of=None,
    context_of=None,
    **item_kwargs,
) -> ControlPlan:
    """Pivot a scan onto the fix axis and sequence the work.

    Args:
        findings: Normalized findings.
        language: Force one language instead of inferring per file path.
        effort_cap: Exclude sub-techniques above this effort level.
        budget: Effort budget for the cover plan, in cost-model units.
        target_pct: Stop the cover once this share of weighted risk is retired —
            usually more useful than a budget for the "what's the 80% move?"
            question.
        cost_model: Override effort costs or the multi-site exponent.
        site_of: Fix-site granularity callable (see `to_items`).
    """
    findings = list(findings)
    items = to_items(
        findings,
        skip_mitigated=skip_mitigated,
        site_of=site_of,
        context_of=context_of,
        **item_kwargs,
    )
    portfolio = pivot(
        items,
        language=language,
        effort_cap=effort_cap,
        language_of=None if language else language_resolver(findings),
    )
    cover = plan_cover(
        portfolio,
        budget=budget,
        target_pct=target_pct,
        cost_model=cost_model,
    )
    ctx = findings[0].scan_context if findings else None
    return ControlPlan(portfolio=portfolio, cover=cover, scan_context=ctx)
