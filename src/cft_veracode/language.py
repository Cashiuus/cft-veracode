"""Infer language code from a file path."""
from __future__ import annotations

from typing import Optional

# Extension → cft-resolver language code (must match keys in language_guidance)
EXT_MAP: dict[str, str] = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".groovy": "java",          # close enough; Java idioms apply
    ".scala": "scala",
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".cs": "csharp",
    ".vb": "csharp",            # Veracode tags VB.NET; map to csharp for guidance proximity
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".c": "c",
    ".h": "c",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".m": "objc",
    ".mm": "objc",
}


def infer_language(file_path: Optional[str]) -> Optional[str]:
    """Return a language code for the given path, or None if unknown."""
    if not file_path:
        return None
    lower = file_path.lower()
    # Multi-dot extensions (.html.erb, .blade.php) — check last extension only
    if "." not in lower:
        return None
    ext = "." + lower.rsplit(".", 1)[1]
    return EXT_MAP.get(ext)


def majority_language(paths: list[str]) -> Optional[str]:
    """Return the most common language across a list of paths."""
    counts: dict[str, int] = {}
    for p in paths:
        lang = infer_language(p)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return None
    return max(counts, key=counts.get)
