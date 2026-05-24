# cft-veracode-bridge

Turn Veracode scanner output into actionable [**CFT (CWE Fix Technique)**](https://github.com/Cashiuus/cft-taxonomy) remediation plans.

This is **Layer 3** of the CFT integration architecture:

```
Layer 3 — cft-veracode-bridge   (THIS package — Veracode-aware adapter)
Layer 2 — cft-resolver           (CWE → Plan; https://github.com/Cashiuus/cft-resolver)
Layer 1 — cft-taxonomy           (the taxonomy data; https://github.com/Cashiuus/cft-taxonomy)
```

The bridge:
1. Ingests Veracode output (three supported formats — see below)
2. Normalizes each finding to a common `Finding` model
3. Infers the affected language from the file path
4. Deduplicates findings into fix groups
5. Calls `cft-resolver` to produce a `Plan` for each group
6. Emits a structured Markdown remediation report

The bridge **never invents fixes** — it sources every recommendation from the CFT taxonomy. Same source of truth, scanner-specific delivery.

## Supported input formats

| Format | Source | Notes |
|---|---|---|
| Veracode Pipeline Scan JSON | `veracode-pipeline-scan` CLI output | Best for CI integration; simplest schema |
| Veracode Findings v2 REST API JSON | `GET /findings/v2/applications/<id>/findings` | Rich metadata (mitigation history, scan context); needs API auth to fetch |
| SARIF 2.1.0 | Veracode SAST SARIF export, or any other SARIF-emitting scanner | Industry standard; future-proofs the adapter |

All three normalize to the same internal `Finding` model — downstream logic is format-agnostic.

## Install

```
pip install cft-veracode-bridge
# or from source (dev):
pip install -e .
```

`cft-veracode-bridge` depends on [`cft-resolver`](https://github.com/Cashiuus/cft-resolver), which bundles a versioned copy of the CFT taxonomy. No separate taxonomy install is required.

## CLI

```
# Ingest a Pipeline Scan JSON file and produce a Markdown report
cft-veracode ingest scan.json --format pipeline --output report.md

# Ingest Findings v2 API JSON
cft-veracode ingest findings.json --format api --output report.md

# Ingest a SARIF file
cft-veracode ingest scan.sarif --format sarif --output report.md

# Override inferred language for the whole scan
cft-veracode ingest scan.json --format pipeline --language java

# Filter by minimum severity
cft-veracode ingest scan.json --format pipeline --min-severity High

# Cap remediation effort (skip High-effort architectural changes)
cft-veracode ingest scan.json --format pipeline --effort-cap Medium

# Skip findings already mitigated in Veracode
cft-veracode ingest findings.json --format api --skip-mitigated

# Output JSON for downstream tooling
cft-veracode ingest scan.json --format pipeline --output-format json
```

## Library usage

```python
from cft_veracode import ingest, build_report

# Load a Veracode export and parse into normalized Findings
findings = ingest("scan.json", format="pipeline")

# Or call format-specific normalizers directly:
from cft_veracode.ingest import parse_pipeline_scan, parse_findings_api, parse_sarif

# Build a structured remediation report (groups findings + resolves CFT plans)
report = build_report(findings, language=None, effort_cap=None, skip_mitigated=True)

# Render to markdown
print(report.to_markdown())
# or JSON
print(report.to_json())
```

## What's in the Markdown report

Per scan, grouped by (severity → fix family → CWE):

- Executive summary: counts by severity, top fix families
- Per-group section:
  - The CFT primary fix (with language-specific code snippet when language is known)
  - Verification checklist (so reviewers know what "done" looks like)
  - Common mistakes / anti-patterns to watch for
  - Effort estimate
  - List of affected findings (file:line, severity, Veracode issue_id)
  - Defense-in-depth additions (optional)
- References section (OWASP, NIST, RFC, CERT)

## Versioning

This adapter pins to a `cft-resolver` major version, which in turn bundles a specific CFT taxonomy version. When the taxonomy moves (v0.2 → v0.3 → v1.0), this adapter releases a matching version.

- `cft-veracode-bridge 0.1.x` requires `cft-resolver ~= 0.1` (CFT taxonomy v0.2)

## Related repos

- [`cft-taxonomy`](https://github.com/Cashiuus/cft-taxonomy) — the source taxonomy (Layer 1)
- [`cft-resolver`](https://github.com/Cashiuus/cft-resolver) — CWE → Plan library (Layer 2)
