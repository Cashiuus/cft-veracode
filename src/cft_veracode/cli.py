"""Command-line entry point: cft-veracode."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from cft_veracode import __version__
from cft_veracode.ingest import ingest, parse_findings_api
from cft_veracode.report import build_report

_EXT_FOR_FORMAT = {"html": "html", "markdown": "md", "json": "json"}


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cft-veracode",
        description="Convert Veracode scanner output into CFT-based remediation plans.",
    )
    parser.add_argument("--version", action="version", version=f"cft-veracode {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # --- ingest (file-based) ----------------------------------------------
    p_ingest = sub.add_parser("ingest", help="Ingest a Veracode finding export from a file")
    p_ingest.add_argument("source", help="Path to the input file (JSON or SARIF)")
    p_ingest.add_argument("--format", "-f", required=True, choices=["pipeline", "api", "sarif"],
                          help="Input format")
    _add_common_filters(p_ingest)

    # --- fetch (API-based) ------------------------------------------------
    p_fetch = sub.add_parser(
        "fetch",
        help="Fetch findings live from the Veracode REST API and produce a report",
    )
    p_fetch.add_argument("--app", "-a", required=True,
                         help="Application name or GUID (name will be resolved via the API)")
    p_fetch.add_argument("--sandbox", default=None,
                         help="Optional sandbox name (default: policy scan)")
    p_fetch.add_argument("--scan-type", default="STATIC",
                         choices=["STATIC", "DYNAMIC", "SCA"],
                         help="Scan type to fetch (default: STATIC)")
    p_fetch.add_argument("--api-id", default=None,
                         help="Veracode API ID (prefer env var VERACODE_API_KEY_ID or ~/.veracode/credentials)")
    p_fetch.add_argument("--api-secret", default=None,
                         help="Veracode API secret (prefer env var VERACODE_API_KEY_SECRET or ~/.veracode/credentials)")
    _add_common_filters(p_fetch)

    args = parser.parse_args(argv)

    if args.cmd == "ingest":
        return _cmd_ingest(args)
    if args.cmd == "fetch":
        return _cmd_fetch(args)
    return 2


def _add_common_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("--output", "-o", default=None,
                   help="Output file. Default: CFT-Report-<source-or-app>.<ext> in cwd. "
                        "Use '-' to write to stdout.")
    p.add_argument("--output-format", default="html", choices=["html", "markdown", "json"],
                   help="Report format (default: html)")
    p.add_argument("--language", "-l", default=None,
                   help="Override inferred language (java, python, javascript, go, csharp, ...)")
    p.add_argument("--effort-cap", "-e", default=None, choices=["Low", "Medium", "High"],
                   help="Drop CFT sub-techniques above this effort level")
    p.add_argument("--min-severity", default=None,
                   choices=["VeryHigh", "High", "Medium", "Low", "VeryLow", "Informational"],
                   help="Drop findings below this severity")
    p.add_argument("--include-mitigated", action="store_true",
                   help="Include findings already marked mitigated (default: skip)")
    p.add_argument("--include-closed", action="store_true",
                   help="Include findings the scanner reports as CLOSED (default: skip)")
    p.add_argument("--view", default="findings", choices=["findings", "control-plan"],
                   help="findings: one section per fix group, remediation attached "
                        "(default). control-plan: pivot onto the fix axis and sequence "
                        "the work by risk retired per unit of effort.")
    p.add_argument("--budget", type=float, default=None, metavar="UNITS",
                   help="control-plan only: stop planning once this much effort is spent")
    p.add_argument("--target-pct", type=float, default=None, metavar="PCT",
                   help="control-plan only: stop once this share of weighted risk is "
                        "retired. Usually more useful than --budget for the "
                        "'what is the 80%% move?' question.")
    p.add_argument("--recurrence-penalty", type=float, default=0.0, metavar="X",
                   help="control-plan only: price the ongoing cost of controls a "
                        "developer must remember at every future call site, so "
                        "class-eliminating fixes compete fairly (try 1.0)")


def _cmd_ingest(args) -> int:
    try:
        findings = ingest(args.source, format=args.format)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    return _emit(args, findings)


def _cmd_fetch(args) -> int:
    # Import lazily so file-based `ingest` works without requests/veracode-api-signing installed
    try:
        from cft_veracode.ingest.api_fetch import (
            CredentialsNotFound,
            VeracodeAPIError,
            fetch_findings,
        )
    except ImportError as e:
        print(
            "error: the 'fetch' subcommand requires the 'requests' and 'veracode-api-signing' packages.\n"
            f"       (import failed: {e})",
            file=sys.stderr,
        )
        return 4

    try:
        doc = fetch_findings(
            args.app,
            sandbox=args.sandbox,
            scan_type=args.scan_type,
            api_id=args.api_id,
            api_key=args.api_secret,
        )
    except CredentialsNotFound as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except VeracodeAPIError as e:
        print(f"error: {e}", file=sys.stderr)
        return 5

    findings = parse_findings_api(doc)
    return _emit(args, findings)


def _emit(args, findings) -> int:
    if getattr(args, "view", "findings") == "control-plan":
        doc = _build_control_plan(args, findings)
    else:
        doc = build_report(
            findings,
            language=args.language,
            effort_cap=args.effort_cap,
            skip_mitigated=not args.include_mitigated,
            skip_closed=not args.include_closed,
            min_severity=args.min_severity,
        )

    if args.output_format == "html":
        out = doc.to_html()
    elif args.output_format == "markdown":
        out = doc.to_markdown()
    else:
        out = doc.to_json()

    if args.output == "-":
        print(out)
        return 0

    target = args.output or _default_output_path(args)
    Path(target).write_text(out, encoding="utf-8")
    print(f"wrote {target}", file=sys.stderr)
    return 0


def _build_control_plan(args, findings):
    """Pivot the scan onto the fix axis instead of grouping by finding."""
    from cft.portfolio import CostModel
    from cft_veracode.portfolio_adapter import build_control_plan

    if args.min_severity:
        from cft_veracode.types import SEVERITY_RANK
        floor = SEVERITY_RANK.get(args.min_severity, -1)
        findings = [f for f in findings if SEVERITY_RANK.get(f.severity, -1) >= floor]

    return build_control_plan(
        findings,
        language=args.language,
        effort_cap=args.effort_cap,
        budget=args.budget,
        target_pct=args.target_pct,
        cost_model=CostModel(recurrence_penalty=args.recurrence_penalty),
        skip_mitigated=not args.include_mitigated,
    )


def _default_output_path(args) -> str:
    ext = _EXT_FOR_FORMAT.get(args.output_format, args.output_format)
    if getattr(args, "view", "findings") == "control-plan":
        prefix = "CFT-ControlPlan"
    else:
        prefix = "CFT-Report"
    if args.cmd == "ingest":
        label = Path(args.source).stem
    else:
        label = args.app
        if getattr(args, "sandbox", None):
            label = f"{label}-{args.sandbox}"
    return f"{prefix}-{_slugify(label)}.{ext}"


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned or "report"


if __name__ == "__main__":
    sys.exit(main())
