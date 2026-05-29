#!/usr/bin/env python3
"""Entry point for the cft-veracode GitHub composite Action.

Reads INPUT_* environment variables, runs ingest + build_report, writes the
report file(s), appends the markdown copy to the Actions job summary, and
sets the exit code from the optional fail-on threshold.

Writes the requested format to ``output-path`` (or ``cft-report.<ext>``)
and always writes a markdown copy alongside it for the sticky PR comment
step. The action.yml exposes both paths as outputs so callers can wire
artifact uploads or downstream notifications.
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

from cft_veracode import build_report, ingest

SEVERITY_RANK = {
    "VeryHigh": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "VeryLow": 1,
    "Informational": 0,
}

FORMAT_EXT = {"markdown": "md", "html": "html", "json": "json"}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def write_output(key: str, value: str) -> None:
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as f:
        if "\n" in value:
            delim = f"EOF_{key}_{secrets.token_hex(4)}"
            f.write(f"{key}<<{delim}\n{value}\n{delim}\n")
        else:
            f.write(f"{key}={value}\n")


def append_summary(text: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(text)
        if not text.endswith("\n"):
            f.write("\n")


def max_severity_present(severity_counts: dict[str, int]) -> str:
    present = [s for s, n in severity_counts.items() if n > 0]
    if not present:
        return ""
    return max(present, key=lambda s: SEVERITY_RANK.get(s, -1))


def main() -> int:
    scan_json = env("INPUT_SCAN_JSON")
    if not scan_json:
        print("::error::scan-json input is required", file=sys.stderr)
        return 1
    if not Path(scan_json).is_file():
        print(f"::error::scan-json path does not exist: {scan_json}", file=sys.stderr)
        return 1

    language = env("INPUT_LANGUAGE") or None
    effort_cap = env("INPUT_EFFORT_CAP") or None
    min_severity = env("INPUT_MIN_SEVERITY") or "Low"
    output_format = env("INPUT_OUTPUT_FORMAT", "markdown").lower()
    output_path_input = env("INPUT_OUTPUT_PATH")
    job_summary = env("INPUT_JOB_SUMMARY", "true").lower() == "true"
    fail_on = env("INPUT_FAIL_ON")

    if output_format not in FORMAT_EXT:
        print(
            f"::error::output-format must be one of {sorted(FORMAT_EXT)}; got {output_format!r}",
            file=sys.stderr,
        )
        return 1

    output_path = Path(output_path_input) if output_path_input else Path(f"cft-report.{FORMAT_EXT[output_format]}")
    markdown_path = output_path if output_format == "markdown" else output_path.with_suffix(".md")

    findings = ingest(scan_json, format="pipeline")
    report = build_report(
        findings,
        language=language,
        effort_cap=effort_cap,
        min_severity=min_severity,
    )

    renderers = {
        "markdown": report.to_markdown,
        "html": report.to_html,
        "json": report.to_json,
    }
    rendered = renderers[output_format]()
    output_path.write_text(rendered, encoding="utf-8")

    markdown_text = rendered if output_format == "markdown" else report.to_markdown()
    if markdown_path != output_path:
        markdown_path.write_text(markdown_text, encoding="utf-8")

    severity_counts = report.severity_counts
    total = report.total_findings
    group_count = len(report.groups)
    max_sev = max_severity_present(severity_counts)

    write_output("total-findings", str(total))
    write_output("groups", str(group_count))
    write_output("max-severity", max_sev)
    write_output("report-path", str(output_path))
    write_output("markdown-path", str(markdown_path))

    if job_summary:
        append_summary(markdown_text)

    if fail_on:
        threshold = SEVERITY_RANK.get(fail_on)
        if threshold is None:
            print(
                f"::warning::fail-on {fail_on!r} is not a known severity; gate skipped",
                file=sys.stderr,
            )
        else:
            triggering = max(
                (SEVERITY_RANK.get(s, -1) for s, n in severity_counts.items() if n > 0),
                default=-1,
            )
            if triggering >= threshold:
                print(
                    f"::error::Findings at or above {fail_on} present (max: {max_sev}); failing per fail-on input.",
                    file=sys.stderr,
                )
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
