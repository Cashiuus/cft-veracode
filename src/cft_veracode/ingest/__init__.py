"""Veracode finding ingestion — three input formats, one Finding model."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from cft_veracode.types import Finding

from cft_veracode.ingest.pipeline import parse_pipeline_scan
from cft_veracode.ingest.findings_api import parse_findings_api
from cft_veracode.ingest.sarif import parse_sarif

__all__ = ["ingest", "parse_pipeline_scan", "parse_findings_api", "parse_sarif"]


def ingest(source: Union[str, Path, dict], format: str) -> list[Finding]:
    """Load Veracode output and return normalized Findings.

    Args:
        source: Path to a JSON/SARIF file, or an already-parsed dict.
        format: 'pipeline' | 'api' | 'sarif'.

    Returns:
        List of Finding objects.

    Raises:
        ValueError: if format is unknown or document does not match the schema.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        with path.open("r", encoding="utf-8") as f:
            doc = json.load(f)
    else:
        doc = source

    if format == "pipeline":
        return parse_pipeline_scan(doc)
    if format == "api":
        return parse_findings_api(doc)
    if format == "sarif":
        return parse_sarif(doc)
    raise ValueError(f"Unknown format: {format!r} (expected 'pipeline', 'api', or 'sarif')")
