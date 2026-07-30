"""Layer 3: turning Veracode findings into planner Items, and the control-plan outputs.

The adapter owns two judgments the scanner-agnostic planner cannot make: what a
finding is WORTH (weight) and WHERE its fix lands (site). Everything else is
delegated, so these tests focus on those two plus the output surfaces.
"""
from __future__ import annotations

import json

import pytest

from cft_veracode.portfolio_adapter import (
    POLICY_MULTIPLIER,
    SEVERITY_WEIGHT,
    build_control_plan,
    language_resolver,
    to_items,
)
from cft_veracode.types import Finding, Location, ScanContext

CTX = ScanContext(scanner="veracode-pipeline", app_name="TestApp", scan_type="STATIC")


def finding(
    fid="F1",
    cwe="CWE-89",
    severity="High",
    path="src/main/java/com/example/dao/UserDao.java",
    line=42,
    **kw,
):
    return Finding(
        finding_id=fid,
        cwe_id=cwe,
        severity=severity,
        title=kw.pop("title", "SQL Injection"),
        location=Location(file_path=path, line=line),
        scanner="veracode-pipeline",
        scan_context=CTX,
        **kw,
    )


# --- weighting -------------------------------------------------------------

@pytest.mark.parametrize("severity", list(SEVERITY_WEIGHT))
def test_severity_maps_to_its_declared_weight(severity):
    item = to_items([finding(severity=severity)])[0]
    assert item.weight == SEVERITY_WEIGHT[severity]


def test_severity_weighting_is_superlinear():
    """A linear 5..0 scale lets a planner trade one critical for two mediums."""
    w = SEVERITY_WEIGHT
    assert w["VeryHigh"] > 2 * w["High"] - 1e-9
    assert w["High"] > 2 * w["Medium"] - 1e-9


def test_policy_violation_raises_weight():
    plain = to_items([finding(fid="a")])[0]
    breach = to_items([finding(fid="b", violates_policy=True)])[0]
    assert breach.weight == pytest.approx(plain.weight * POLICY_MULTIPLIER)


def test_severity_weight_override_is_honored():
    items = to_items([finding(severity="High")], severity_weight={"High": 99.0})
    assert items[0].weight == 99.0


# --- what gets dropped -----------------------------------------------------

def test_findings_without_a_cwe_are_dropped():
    assert to_items([finding(cwe=None)]) == []


def test_mitigated_findings_are_dropped_by_default_and_kept_on_request():
    f = finding(mitigation_status="ACCEPTED")
    assert to_items([f]) == []
    assert len(to_items([f], skip_mitigated=False)) == 1


def test_closed_findings_are_always_dropped():
    assert to_items([finding(status="CLOSED")]) == []
    assert to_items([finding(status="CLOSED")], skip_mitigated=False) == []


# --- site and context ------------------------------------------------------

def test_site_defaults_to_the_parent_directory():
    item = to_items([finding(path="src/main/java/com/example/dao/UserDao.java")])[0]
    assert item.site == "src/main/java/com/example/dao"


def test_site_of_override_controls_fix_granularity():
    coarse = to_items([finding()], site_of=lambda f: "monolith")[0]
    assert coarse.site == "monolith"


def test_context_is_absent_unless_a_resolver_supplies_it():
    """Veracode does not report sink context; guessing it is the bug we avoid."""
    assert to_items([finding()])[0].context is None
    tagged = to_items([finding()], context_of=lambda f: "html_body")[0]
    assert tagged.context == "html_body"


def test_label_carries_file_and_line():
    item = to_items([finding(path="a/b/C.java", line=17)])[0]
    assert "a/b/C.java:17" in item.label
    assert "SQL Injection" in item.label


def test_language_resolver_infers_per_finding():
    fs = [
        finding(fid="j", path="src/A.java"),
        finding(fid="t", path="ui/B.tsx"),
        finding(fid="p", path="svc/c.py"),
    ]
    lookup = language_resolver(fs)
    items = {i.key: i for i in to_items(fs)}
    assert lookup(items["j"]) == "java"
    assert lookup(items["t"]) == "typescript"
    assert lookup(items["p"]) == "python"


def test_language_resolver_returns_none_for_unknown_items():
    assert language_resolver([finding()])(to_items([finding(fid="other")])[0]) is None


# --- end to end ------------------------------------------------------------

def scan(n_per_cwe=4):
    out = []
    i = 0
    for cwe, sev, path in (
        ("CWE-89", "VeryHigh", "src/main/java/com/example/dao/D.java"),
        ("CWE-79", "High", "src/main/webapp/views/V.jsp"),
        ("CWE-327", "Medium", "src/main/java/com/example/crypto/C.java"),
    ):
        for _ in range(n_per_cwe):
            i += 1
            out.append(finding(fid=f"F{i}", cwe=cwe, severity=sev, path=path))
    return out


def test_build_control_plan_produces_a_covering_sequence():
    plan = build_control_plan(scan())
    assert plan.cover.steps
    assert plan.cover.covered_pct > 0
    assert len(plan.portfolio.items) == 12


def test_control_plan_carries_scan_context_for_the_report_header():
    plan = build_control_plan(scan())
    assert plan.scan_context is not None
    assert plan.scan_context.app_name == "TestApp"


def test_target_pct_stops_early_and_budget_bounds_cost():
    full = build_control_plan(scan())
    capped = build_control_plan(scan(), target_pct=50)
    assert len(capped.cover.steps) <= len(full.cover.steps)
    budgeted = build_control_plan(scan(), budget=3.0)
    assert budgeted.cover.total_cost <= 3.0


def test_xss_partition_is_not_reduced_to_one_encoder():
    """The regression that motivated taxonomy v0.3, guarded at Layer 3."""
    plan = build_control_plan(scan())
    xss = [s.task for s in plan.cover.steps if "CWE-79" in s.task.cwe_ids]
    assert xss
    assert all(t.key != "CFT018.03" for t in xss)


def test_supplying_context_narrows_the_xss_plan():
    ctx_of = lambda f: "html_body" if (f.location.file_path or "").endswith(".jsp") else None
    narrow = build_control_plan(scan(), context_of=ctx_of)
    assert narrow.cover.total_cost < build_control_plan(scan()).cover.total_cost
    assert not any(g.cwe_id == "CWE-79" for g in narrow.portfolio.context_gaps)


# --- output surfaces -------------------------------------------------------

def test_markdown_output_names_techniques_and_confirmations():
    md = build_control_plan(scan()).to_markdown()
    assert "# Remediation cover plan" in md
    assert "CFT021.01" in md
    assert "Narrowable with sink context" in md


def test_html_output_is_self_contained():
    html = build_control_plan(scan()).to_html()
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html and "plan-table" in html
    # A strict-CSP-safe single file: no external fetches of any kind.
    for forbidden in ("http://", "https://", "<link", "src="):
        assert forbidden not in html


def test_json_output_round_trips_and_reports_confirmations():
    doc = json.loads(build_control_plan(scan()).to_json())
    assert doc["summary"]["techniques"] == len(doc["steps"])
    assert doc["summary"]["findings_addressed"] == 12
    assert set(doc["confirm"]) == {"context_gaps", "group_choices", "legacy_ambiguous"}
    assert doc["steps"][0]["task"]["key"]
    assert doc["steps"][0]["cumulative_pct"] > 0


def test_empty_scan_does_not_crash_any_output():
    plan = build_control_plan([])
    assert plan.cover.steps == ()
    assert "No coverable findings" in plan.to_html()
    assert plan.to_markdown()
    assert json.loads(plan.to_json())["summary"]["techniques"] == 0
