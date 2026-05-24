"""Command-line entry point: cft-veracode."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cft_veracode import __version__
from cft_veracode.ingest import ingest
from cft_veracode.report import build_report


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cft-veracode",
        description="Convert Veracode scanner output into CFT-based remediation plans.",
    )
    parser.add_argument("--version", action="version", version=f"cft-veracode-bridge {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="Ingest a Veracode finding export and emit a report")
    p_ingest.add_argument("source", help="Path to the input file (JSON or SARIF)")
    p_ingest.add_argument("--format", "-f", required=True, choices=["pipeline", "api", "sarif"],
                          help="Input format")
    p_ingest.add_argument("--output", "-o", default=None,
                          help="Output file (default: stdout)")
    p_ingest.add_argument("--output-format", default="markdown", choices=["markdown", "json"],
                          help="Report format (default: markdown)")
    p_ingest.add_argument("--language", "-l", default=None,
                          help="Override inferred language (java, python, javascript, go, csharp, ...)")
    p_ingest.add_argument("--effort-cap", "-e", default=None, choices=["Low", "Medium", "High"],
                          help="Drop CFT sub-techniques above this effort level")
    p_ingest.add_argument("--min-severity", default=None,
                          choices=["VeryHigh", "High", "Medium", "Low", "VeryLow", "Informational"],
                          help="Drop findings below this severity")
    p_ingest.add_argument("--include-mitigated", action="store_true",
                          help="Include findings already marked mitigated (default: skip)")

    args = parser.parse_args(argv)

    if args.cmd == "ingest":
        return _cmd_ingest(args)
    return 2


def _cmd_ingest(args) -> int:
    try:
        findings = ingest(args.source, format=args.format)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    report = build_report(
        findings,
        language=args.language,
        effort_cap=args.effort_cap,
        skip_mitigated=not args.include_mitigated,
        min_severity=args.min_severity,
    )

    out = report.to_markdown() if args.output_format == "markdown" else report.to_json()

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
