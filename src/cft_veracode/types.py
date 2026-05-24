"""Common data model for normalized Veracode findings + grouped reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Veracode severity numeric scale → label
VERACODE_SEVERITY = {
    5: "VeryHigh",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "VeryLow",
    0: "Informational",
}
SEVERITY_RANK = {
    "VeryHigh": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "VeryLow": 1,
    "Informational": 0,
}


@dataclass(frozen=True)
class Location:
    file_path: Optional[str]
    line: Optional[int] = None
    column: Optional[int] = None
    function_name: Optional[str] = None
    snippet: Optional[str] = None


@dataclass(frozen=True)
class ScanContext:
    """Top-of-scan metadata (which Veracode artifact produced these findings)."""
    scanner: str                    # "veracode-pipeline" | "veracode-api" | "sarif"
    scan_id: Optional[str] = None
    app_name: Optional[str] = None
    sandbox: Optional[str] = None
    scan_type: Optional[str] = None   # "STATIC" | "DYNAMIC" | "SCA" | None
    scan_date: Optional[str] = None
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None


@dataclass(frozen=True)
class Finding:
    """Normalized finding model — all three input formats produce this shape."""
    finding_id: str                 # stable per-scanner ID for dedupe across scans
    cwe_id: Optional[str]           # "CWE-89" or None if scanner didn't tag a CWE
    severity: str                   # one of VERACODE_SEVERITY values
    title: str                      # scanner's finding title (e.g. "SQL Injection")
    location: Location
    scanner: str                    # "veracode-pipeline" | "veracode-api" | "sarif"
    scan_context: ScanContext
    description: Optional[str] = None
    severity_score: Optional[float] = None     # CVSS or vendor score
    # Veracode-specific (None for SARIF or other-scanner inputs):
    veracode_flaw_id: Optional[str] = None
    mitigation_status: Optional[str] = None    # e.g. "ACCEPTED" | "PROPOSED" | "REJECTED"
    mitigation_review: Optional[str] = None
    violates_policy: Optional[bool] = None
    # Raw record preserved for debugging / round-trip:
    scanner_native: dict = field(default_factory=dict)

    @property
    def is_mitigated(self) -> bool:
        return self.mitigation_status in ("ACCEPTED", "APPROVED")


@dataclass
class FindingGroup:
    """A set of findings sharing (CWE, file root) — typically one fix covers them all."""
    cwe_id: Optional[str]
    file_root: str                  # directory holding the findings (heuristic)
    language: Optional[str]
    findings: list[Finding]
    # Resolved later, when the report is built:
    plan: object = None             # cft.Plan; left as `object` to avoid hard import here

    @property
    def max_severity(self) -> str:
        return max(
            (f.severity for f in self.findings),
            key=lambda s: SEVERITY_RANK.get(s, -1),
            default="Informational",
        )

    @property
    def count(self) -> int:
        return len(self.findings)


@dataclass
class Report:
    """Result of grouping + plan resolution; renders to markdown/JSON."""
    scan_context: ScanContext
    groups: list[FindingGroup]
    skipped_mitigated: int = 0
    skipped_no_cwe: int = 0
    skipped_below_severity: int = 0
    language_default: Optional[str] = None
    effort_cap: Optional[str] = None
    min_severity: Optional[str] = None

    @property
    def total_findings(self) -> int:
        return sum(g.count for g in self.groups)

    @property
    def severity_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for g in self.groups:
            for f in g.findings:
                out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_markdown(self) -> str:
        from cft_veracode.report import render_markdown
        return render_markdown(self)

    def to_json(self) -> str:
        from cft_veracode.report import render_json
        return render_json(self)
