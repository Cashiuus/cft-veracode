"""Group raw findings into fix-equivalent buckets.

Heuristic: findings with the same CWE-ID and the same source directory
typically share a root cause and one fix. We group at the directory level
(not file) so a scan reporting 30 SQLi findings across 4 files in
`src/main/java/com/example/dao/` becomes one group with 30 entries.
"""
from __future__ import annotations

import os
from collections import defaultdict

from cft_veracode.language import infer_language, majority_language
from cft_veracode.types import Finding, FindingGroup


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    buckets: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        key = (f.cwe_id, _file_root(f.location.file_path))
        buckets[key].append(f)

    groups: list[FindingGroup] = []
    for (cwe, root), fs in buckets.items():
        # Best-effort language inference from the bucket's file paths
        paths = [f.location.file_path for f in fs if f.location.file_path]
        lang = majority_language(paths) if paths else None
        groups.append(FindingGroup(
            cwe_id=cwe,
            file_root=root,
            language=lang,
            findings=fs,
        ))

    # Sort groups by max severity desc, then count desc
    from cft_veracode.types import SEVERITY_RANK
    groups.sort(
        key=lambda g: (-SEVERITY_RANK.get(g.max_severity, -1), -g.count),
    )
    return groups


def _file_root(path: "str | None") -> str:
    """Return the directory portion of a path (or '?' if unknown)."""
    if not path:
        return "?"
    # Normalize separators
    norm = path.replace("\\", "/")
    parent = os.path.dirname(norm)
    # Bugfix: DLL module paths via REST API may not always have a parent directory
    return parent or norm or "."
