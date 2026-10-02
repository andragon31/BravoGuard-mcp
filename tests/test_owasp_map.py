"""Full OWASP Top 10:2025 coverage (W1): 249 mapped CWEs, loader branches.

Note policy: only the 7 seed CWEs carry notes (byte-identical to the seed
file); new entries carry no note and the loader defaults to "".
CWE-307 maps to A07 per the official A07 list (not A05).
"""

import json
from pathlib import Path

from bravoguard.owasp_map import explain_cwe

DATA_PATH = Path(__file__).resolve().parent.parent / "src" / "bravoguard" / "owasp_2025.json"

EXPECTED_COUNTS = {
    "A01": 40,
    "A02": 16,
    "A03": 6,
    "A04": 32,
    "A05": 37,
    "A06": 39,
    "A07": 36,
    "A08": 14,
    "A09": 5,
    "A10": 24,
}

SEED_NOTES = {
    "CWE-79": "XSS — Injection (A05:2025, was A03 in 2021)",
    "CWE-89": "SQL injection — Injection (A05:2025)",
    "CWE-78": "OS command injection — Injection (A05:2025)",
    "CWE-95": "Eval injection — Injection (A05:2025)",
    "CWE-502": "Deserialization of untrusted data — A08:2025",
    "CWE-798": "Hard-coded credentials — A07:2025",
    "CWE-918": "SSRF — A01:2025 (was A10 in 2021)",
}

# Every CWE our scanners can emit: semgrep rules + bandit/normalizer paths
# (79/89/78/95/502/798), trivy/osv-common examples (22/307/327/330/338/918).
SCANNER_CWES = {
    "CWE-22": "A01",
    "CWE-78": "A05",
    "CWE-79": "A05",
    "CWE-89": "A05",
    "CWE-95": "A05",
    "CWE-307": "A07",
    "CWE-327": "A04",
    "CWE-330": "A04",
    "CWE-338": "A04",
    "CWE-502": "A08",
    "CWE-798": "A07",
    "CWE-918": "A01",
}


def _load_data() -> dict:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def test_json_valid_with_packaged_shape() -> None:
    data = _load_data()
    assert data["version"] == "2025"
    assert set(data["categories"]) == set(EXPECTED_COUNTS)
    assert isinstance(data["cwe_map"], dict)
    assert isinstance(data["notes"], dict)
    assert "coverage" in data


def test_total_count_matches_coverage() -> None:
    data = _load_data()
    total = sum(EXPECTED_COUNTS.values())
    assert len(data["cwe_map"]) == total == 249


def test_per_category_counts_exact() -> None:
    data = _load_data()
    counts: dict[str, int] = {}
    for category in data["cwe_map"].values():
        counts[category] = counts.get(category, 0) + 1
    assert counts == EXPECTED_COUNTS


def test_seed_notes_byte_identical() -> None:
    assert _load_data()["notes"] == SEED_NOTES


def test_scanner_cwes_map_non_unknown() -> None:
    for cwe, category in SCANNER_CWES.items():
        result = explain_cwe(cwe)
        assert result["owasp_2025"] == category, cwe


def test_spot_checks() -> None:
    assert explain_cwe("CWE-22")["owasp_2025"] == "A01"
    assert explain_cwe("CWE-307")["owasp_2025"] == "A07"
    assert explain_cwe("CWE-918")["owasp_2025"] == "A01"


def test_unknown_cwe_branch() -> None:
    result = explain_cwe("CWE-9999")
    assert result["owasp_2025"] == "unknown"
    assert result["note"] == "unknown CWE id"


def test_invalid_format_branch() -> None:
    result = explain_cwe("not-a-cwe")
    assert result["owasp_2025"] == "unknown"
    assert result["note"] == "invalid CWE format"
