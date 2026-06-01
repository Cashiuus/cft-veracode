# cft-veracode

Turn Veracode scanner output into actionable [**CFT (CWE Fix Technique)**](https://github.com/Cashiuus/cft-taxonomy) remediation plans.

This is **Layer 3** of the CFT integration architecture:

```
Layer 3 — cft-veracode   (THIS package — Veracode-aware adapter)
Layer 2 — cft-resolver           (CWE → Plan; https://github.com/Cashiuus/cft-resolver)
Layer 1 — cft-taxonomy           (the taxonomy data; https://github.com/Cashiuus/cft-taxonomy)
```

The bridge:
1. Ingests Veracode output (three supported formats — see below)
2. Normalizes each finding to a common `Finding` model
3. Infers the affected language from the file path
4. Deduplicates findings into fix groups
5. Calls `cft-resolver` to produce a `Plan` for each group
6. Emits a structured remediation report — **HTML (default)**, Markdown, or JSON

The bridge **never invents fixes** — it sources every recommendation from the CFT taxonomy. Same source of truth, scanner-specific delivery.

## Scope: sound fixes, not vendor acceptance

This adapter recommends remediations that fix the underlying CWE — sourced from the [CFT taxonomy](https://github.com/Cashiuus/cft-taxonomy). It deliberately does **not** embed Veracode's mitigation policy or approved-cleanser catalog. Whether a specific library/API call is auto-recognized by Veracode (or requires a mitigation submission for human review) is a separate concern, governed by Veracode's own policy.

For Veracode-specific acceptance criteria — supported cleansers, mitigation workflow, and policy configuration — consult Veracode's documentation: [Veracode Docs](https://docs.veracode.com/) (search for "cleansers", "mitigations", or "remediation acceptance" for the topic you need).

## Supported input formats

| Format | Source | Notes |
|---|---|---|
| Veracode Pipeline Scan JSON | `veracode-pipeline-scan` CLI output | Best for CI integration; simplest schema |
| Veracode Findings v2 REST API JSON | `GET /findings/v2/applications/<id>/findings` | Rich metadata (mitigation history, scan context); needs API auth to fetch |
| SARIF 2.1.0 | Veracode SAST SARIF export, or any other SARIF-emitting scanner | Industry standard; future-proofs the adapter |

All three normalize to the same internal `Finding` model — downstream logic is format-agnostic.

## Install

```
pip install cft-veracode
# or from source (dev):
pip install -e .
```

`cft-veracode` depends on [`cft-resolver`](https://github.com/Cashiuus/cft-resolver), which bundles a versioned copy of the CFT taxonomy. No separate taxonomy install is required.

## CLI

Two subcommands: `fetch` (live API call) and `ingest` (file-based).

### `fetch` — pull findings live from the Veracode REST API

```
# Fetch the latest STATIC policy-scan findings for an app and produce an HTML report
# (writes ./CFT-Report-DemoApp.html by default)
cft-veracode fetch --app DemoApp

# Fetch from a specific sandbox instead of the policy scan
# (writes ./CFT-Report-DemoApp-DevSandbox.html)
cft-veracode fetch --app DemoApp --sandbox DevSandbox

# Identify the app by GUID instead of name
cft-veracode fetch --app 11111111-2222-3333-4444-555555555555

# Override language, cap effort, filter severity
cft-veracode fetch --app DemoApp --language java --effort-cap Medium --min-severity High

# Get the older Markdown format instead (writes ./CFT-Report-DemoApp.md)
cft-veracode fetch --app DemoApp --output-format markdown

# Write to a specific file, or stream to stdout with '-'
cft-veracode fetch --app DemoApp --output my-report.html
cft-veracode fetch --app DemoApp --output -
```

**Credentials** are discovered automatically in this order:
1. `--api-id` / `--api-secret` CLI flags (not recommended)
2. Environment variables `VERACODE_API_KEY_ID` and `VERACODE_API_KEY_SECRET`
3. `~/.veracode/credentials` file (standard Veracode tooling location with `[default]` section)

If you already use the official Veracode CLI tools (`veracode-pipeline-scan`, etc.), `~/.veracode/credentials` is likely already set up and this adapter will pick it up.

Pagination is handled internally — large apps with hundreds of findings are fetched in full across HAL `_links.next` pages before the report is built.

### `ingest` — file-based (when you already have an export)

```
# Pipeline Scan JSON — writes ./CFT-Report-scan.html by default
cft-veracode ingest scan.json --format pipeline

# Findings v2 API JSON (already exported) — writes ./CFT-Report-findings.html
cft-veracode ingest findings.json --format api

# SARIF (from Veracode SAST export, or any SARIF-emitting scanner)
cft-veracode ingest scan.sarif --format sarif

# Markdown output (writes ./CFT-Report-scan.md)
cft-veracode ingest scan.json --format pipeline --output-format markdown

# JSON output streamed to stdout (e.g. piped into downstream tooling)
cft-veracode ingest scan.json --format pipeline --output-format json --output -

# Explicit output path
cft-veracode ingest scan.json --format pipeline --output my-report.html
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

# Render to HTML (default — single-file, dark theme, offline-viewable)
pathlib.Path("report.html").write_text(report.to_html(), encoding="utf-8")

# Or Markdown (for PR comments, terminal preview)
print(report.to_markdown())

# Or JSON (for downstream tooling)
print(report.to_json())
```

## Output formats

### HTML (default)

A single-file, standalone HTML document — no external CSS, no JavaScript, no font fetches. Viewable offline, email-able, drop-able in Slack or onto a static site. Dark theme by default; severity-colored pills (red / orange / yellow / blue / grey) flag risk at a glance. Each fix group is a collapsible card with the affected-findings table on top and the CFT remediation block below.

### Markdown

The original output — best for PR comments, terminal preview, or any pipeline that already consumes Markdown. Same content structure as HTML, just monospace-friendly.

### JSON

Machine-readable structured output — for piping into downstream automation (ticketing, SOAR, dashboards). Preserves every field the report depends on: scan context, groupings, per-finding metadata, full CFT plan partitioned by mapping strength.

### What's in every report

Per scan, grouped by (CWE × file-root directory):

- Executive summary: counts by severity, fix groups, skipped-finding accounting
- Per-group section (in this order):
  - Group header — CWE + finding title
  - Metadata strip — count, max severity, language, location
  - **Affected findings table first** — severity, file, line, Veracode issue ID, deep link
  - **Recommended remediation second** — plan notes, primary fix (or necessary controls), defense-in-depth, partial fixes
  - For each CFT entry — effort / control / actor pills, description, language-specific code example, verification checklist, common mistakes, references (OWASP, NIST, RFC, CERT)

## Versioning

This adapter pins to a `cft-resolver` major version, which in turn bundles a specific CFT taxonomy version. When the taxonomy moves (v0.2 → v0.3 → v1.0), this adapter releases a matching version.

- `cft-veracode 0.1.x` requires `cft-resolver ~= 0.1` (CFT taxonomy v0.2)

## Related repos

- [`cft-taxonomy`](https://github.com/Cashiuus/cft-taxonomy) — the source taxonomy (Layer 1)
- [`cft-resolver`](https://github.com/Cashiuus/cft-resolver) — CWE → Plan library (Layer 2)
