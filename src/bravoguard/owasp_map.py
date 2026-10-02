"""CWE -> OWASP Top 10:2025 + LLM Top 10:2026 mapping (versioned JSON fronted).

Tables live in owasp_2025.json and llm_2026.json. This module is a thin
loader so scanner output stays accurate when OWASP renumbers categories
(e.g. Injection A03 in 2021 -> A05 in 2025).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def _load_owasp() -> dict:
    with (_DATA_DIR / "owasp_2025.json").open(encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_llm() -> dict:
    with (_DATA_DIR / "llm_2026.json").open(encoding="utf-8") as f:
        return json.load(f)


def explain_cwe(cwe_id: str) -> dict:
    """Return the OWASP 2025 category for a CWE id, or unknown."""
    data = _load_owasp()
    normalized = cwe_id.strip().upper()
    if not normalized.startswith("CWE-"):
        return {"cwe": cwe_id, "owasp_2025": "unknown", "note": "invalid CWE format"}
    category = data["cwe_map"].get(normalized)
    if category is None:
        return {"cwe": normalized, "owasp_2025": "unknown", "note": "unknown CWE id"}
    return {
        "cwe": normalized,
        "owasp_2025": category,
        "owasp_title": data["categories"][category],
        "note": data["notes"].get(normalized, ""),
    }


def explain_llm(risk_id: str) -> dict:
    """Return LLM Top 10:2026 context for an LLMxx:2026 id."""
    data = _load_llm()
    normalized = risk_id.strip().upper()
    for risk in data["risks"]:
        if risk["id"].upper() == normalized:
            return risk
    return {"id": risk_id, "title": "unknown", "summary": "unknown LLM risk id"}
