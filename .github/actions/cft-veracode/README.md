# CFT Remediation Plan — Veracode Pipeline Action

A GitHub composite Action that turns **Veracode Pipeline Scan** output into a [**CFT (CWE Fix Technique)**](https://github.com/Cashiuus/cft-taxonomy) remediation plan and surfaces it on the PR and the Actions job summary.

Wraps [`cft-veracode`](https://github.com/Cashiuus/cft-veracode) — no extra config; install Python on the runner is handled for you.

## Quick start

```yaml
permissions:
  contents: read
  pull-requests: write          # required for the sticky PR comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Veracode Pipeline Scan
        uses: veracode/veracode-pipeline-scan-action@v1
        with:
          vid: ${{ secrets.VERACODE_API_KEY_ID }}
          vkey: ${{ secrets.VERACODE_API_KEY_SECRET }}
          file: app.jar
          # produces results.json by default

      - name: CFT Remediation Plan
        uses: Cashiuus/cft-veracode/.github/actions/cft-veracode@main
        with:
          scan-json: results.json

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cft-report
          path: cft-report.md
```

On a PR, this posts a sticky comment with the remediation plan and appends the same content to the Actions job summary. No findings? The Action still runs cleanly and the comment summary will reflect that.

## What the PR comment looks like

The comment opens with a severity table and collapses each fix group behind a `<details>` element — keeps large reports scannable.

```markdown
## Veracode remediation report

**Total findings:** 12 · **Fix groups:** 3 · **Max severity:** VeryHigh

### Group 1: CWE-89 — SQL Injection
**Findings:** 4 | **Max severity:** VeryHigh | **Language:** java
…
```

On subsequent runs against the same PR, the Action **updates the existing comment** rather than posting again (via [`marocchino/sticky-pull-request-comment`](https://github.com/marocchino/sticky-pull-request-comment)).

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `scan-json` | yes | — | Path to the Veracode Pipeline Scan results JSON |
| `language` | no | (auto-infer) | Override language detection — `java`, `python`, `javascript`, `go`, `csharp`, etc. |
| `effort-cap` | no | (no cap) | Cap fix-technique effort: `Low`, `Medium`, `High` |
| `min-severity` | no | `Low` | Skip findings below this — `VeryLow` \| `Low` \| `Medium` \| `High` \| `VeryHigh` |
| `output-format` | no | `markdown` | Format written to disk: `markdown`, `html`, `json`. PR comments are always markdown. |
| `output-path` | no | `cft-report.<ext>` | Path to write the report file |
| `job-summary` | no | `true` | Append the markdown report to `$GITHUB_STEP_SUMMARY` |
| `comment-on-pr` | no | `true` | Post a sticky PR comment (markdown). Ignored on non-PR events. |
| `comment-tag` | no | `default` | Disambiguator when running the Action multiple times on one PR — see [Multiple invocations](#multiple-invocations-on-one-pr) |
| `fail-on` | no | (off) | Exit non-zero if any finding meets/exceeds this severity. Default: informational only, never fails. |
| `python-version` | no | `3.11` | Python version for the runner |
| `cft-veracode-version` | no | `~=0.1` | pip version specifier for the underlying package |

## Outputs

| Output | Description |
|---|---|
| `total-findings` | Number of findings after `min-severity` filtering |
| `groups` | Number of fix groups in the report |
| `max-severity` | Highest severity present (or empty if no findings) |
| `report-path` | Path to the written report in the requested `output-format` |
| `markdown-path` | Path to the markdown copy of the report (always written; used for the PR comment) |

Use these for downstream logic — e.g. fan out to Slack only when something serious lands:

```yaml
      - name: CFT Remediation Plan
        id: cft
        uses: Cashiuus/cft-veracode/.github/actions/cft-veracode@main
        with:
          scan-json: results.json

      - name: Notify on serious findings
        if: ${{ steps.cft.outputs.max-severity == 'VeryHigh' || steps.cft.outputs.max-severity == 'High' }}
        uses: slackapi/slack-github-action@v1
        with:
          payload: '{"text":"${{ steps.cft.outputs.total-findings }} findings, max ${{ steps.cft.outputs.max-severity }}"}'
```

## Permissions

The caller workflow needs:

```yaml
permissions:
  contents: read
  pull-requests: write     # only required if comment-on-pr is true (default)
```

Without `pull-requests: write`, the PR comment step fails with a 403. Set `comment-on-pr: false` if you don't want PR comments and only want the job summary + artifact.

## Patterns

### Multiple invocations on one PR

If you scan more than one app or module in the same workflow, give each invocation a unique `comment-tag`. Without that, the second run's comment overwrites the first.

```yaml
      - name: CFT plan — API
        uses: Cashiuus/cft-veracode/.github/actions/cft-veracode@main
        with:
          scan-json: api-scan.json
          comment-tag: api

      - name: CFT plan — Web
        uses: Cashiuus/cft-veracode/.github/actions/cft-veracode@main
        with:
          scan-json: web-scan.json
          comment-tag: web
```

Result: two persistent comments on the PR, each updated in place on subsequent pushes.

### Gating PRs on severity

`fail-on` defaults to off so the Action is purely informational on initial rollout. Once teams trust the plan, opt into a gate:

```yaml
      - name: CFT Remediation Plan
        uses: Cashiuus/cft-veracode/.github/actions/cft-veracode@main
        with:
          scan-json: results.json
          fail-on: VeryHigh        # block merge if any VeryHigh finding remains
```

The Action still produces the report and posts the comment before failing — reviewers can see exactly what to fix without re-running.

### HTML report as a downloadable artifact

The markdown report renders inline in the PR comment and job summary. For a richer offline view (dark theme, severity pills, collapsible groups), request HTML and upload it as an artifact:

```yaml
      - name: CFT Remediation Plan
        uses: Cashiuus/cft-veracode/.github/actions/cft-veracode@main
        with:
          scan-json: results.json
          output-format: html

      - uses: actions/upload-artifact@v4
        with:
          name: cft-report-html
          path: cft-report.html
```

You still get the markdown PR comment (the Action writes a sidecar `cft-report.md` for that).

### Non-PR events

`on: push`, `on: schedule`, manual `workflow_dispatch` etc. all work — the PR comment step is silently skipped (it requires a `pull_request` event), but the job summary and artifact are still produced.

## Caveats

- Composite Actions run as a sequence of steps on the caller's runner — they share the runner's Python install. If you set `python-version` here and elsewhere in the workflow to different versions, the last `actions/setup-python` step wins.
- `cft-veracode` is currently a 0.1.x preview. The default version specifier `~=0.1` allows any 0.1.x; pin tighter (`==0.1.3`) once you have a known-good combination.
- The Action assumes Pipeline Scan JSON. Findings v2 API JSON and SARIF ingestion are exposed by the `cft-veracode` CLI directly but not yet by this Action — file an issue if you need them wrapped.

## See also

- [`cft-veracode`](https://github.com/Cashiuus/cft-veracode) — the underlying Python package
- [`cft-resolver`](https://github.com/Cashiuus/cft-resolver) — the CWE→Plan resolver
- [`cft-taxonomy`](https://github.com/Cashiuus/cft-taxonomy) — the source taxonomy
