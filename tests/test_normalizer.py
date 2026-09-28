"""T2 normalizer tests: one schema, per-scanner parsers, dedup, sort, redaction."""

import json

from bravoguard.normalizer import (
    FINDING_KEYS,
    dedup_findings,
    make_finding,
    normalize_bandit,
    normalize_betterleaks,
    normalize_findings,
    normalize_semgrep,
    sort_findings,
)

EXPECTED_KEYS = {
    "rule_id",
    "cwe",
    "path",
    "line",
    "severity",
    "message",
    "fix_hint",
    "epss",
    "kev",
    "reachability_note",
}


def test_finding_keys_extended_backward_compat() -> None:
    assert set(FINDING_KEYS) == EXPECTED_KEYS
    assert {"rule_id", "cwe", "path", "line", "severity", "message", "fix_hint"} < set(
        FINDING_KEYS
    )


def test_semgrep_parser_with_risk_metadata() -> None:
    payload = {
        "results": [
            {
                "check_id": "bravoguard-python-pickle-load",
                "path": "app.py",
                "start": {"line": 3},
                "extra": {
                    "message": "Avoid pickle.load on untrusted input.",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-502"],
                        "fix_hint": "Use json.load.",
                        "epss": 0.82,
                        "kev": True,
                        "reachability_note": "Reachable from request handler.",
                    },
                },
            }
        ]
    }
    (finding,) = normalize_semgrep(payload)
    assert set(finding) == EXPECTED_KEYS
    assert finding["rule_id"] == "bravoguard-python-pickle-load"
    assert finding["cwe"] == "CWE-502"
    assert finding["line"] == 3
    assert finding["epss"] == 0.82
    assert finding["kev"] is True
    assert finding["reachability_note"] == "Reachable from request handler."


def test_semgrep_parser_defaults_without_risk_metadata() -> None:
    payload = {
        "results": [
            {
                "check_id": "rule-x",
                "path": "a.py",
                "start": {"line": 1},
                "extra": {"message": "msg", "severity": "warning", "metadata": {}},
            }
        ]
    }
    (finding,) = normalize_semgrep(payload)
    assert finding["epss"] is None
    assert finding["kev"] is False
    assert finding["reachability_note"] == ""


def test_bandit_parser_shape() -> None:
    payload = {
        "results": [
            {
                "filename": "app.py",
                "line_number": 3,
                "test_id": "B301",
                "issue_severity": "MEDIUM",
                "issue_text": "Pickle can be unsafe.",
                "issue_cwe": {"id": 502},
            }
        ]
    }
    (finding,) = normalize_bandit(payload)
    assert set(finding) == EXPECTED_KEYS
    assert finding["rule_id"] == "B301"
    assert finding["cwe"] == "CWE-502"
    assert finding["epss"] is None
    assert finding["kev"] is False


def test_betterleaks_parser_shape_and_redaction() -> None:
    payload = [
        {
            "Description": "Generic API Key",
            "RuleID": "generic-api-key",
            "File": "app.py",
            "StartLine": 2,
            "Secret": "sk-live-abcdef123456",
            "Match": "api_key = 'sk-live-abcdef123456'",
        }
    ]
    (finding,) = normalize_betterleaks(payload)
    assert set(finding) == EXPECTED_KEYS
    assert finding["cwe"] == "CWE-798"
    assert finding["severity"] == "HIGH"
    assert "sk-live-abcdef123456" not in json.dumps(finding)


def test_betterleaks_dict_payload_shape() -> None:
    payload = {"results": [{"RuleID": "r", "File": "f.py", "StartLine": 1}]}
    (finding,) = normalize_betterleaks(payload)
    assert finding["rule_id"] == "r"
    assert finding["cwe"] == "CWE-798"


def test_dedup_drops_repeats_first_wins() -> None:
    first = make_finding("rule-a", "CWE-79", "app.py", 3, "HIGH", "Same message.", "hint-1")
    repeat = make_finding("rule-a", "CWE-79", "app.py", 3, "HIGH", "Same message.", "hint-2")
    other_line = make_finding("rule-a", "CWE-79", "app.py", 4, "HIGH", "Same message.", "")
    assert dedup_findings([first, repeat, other_line]) == [first, other_line]


def test_sort_kev_first_then_epss_desc() -> None:
    low = make_finding("low", "", "a.py", 1, "LOW", "m1", "", epss=0.1)
    high = make_finding("high", "", "a.py", 2, "HIGH", "m2", "", epss=0.9)
    kev = make_finding("kev", "", "a.py", 3, "HIGH", "m3", "", epss=0.01, kev=True)
    unknown = make_finding("unknown", "", "a.py", 4, "LOW", "m4", "")
    assert [f["rule_id"] for f in sort_findings([low, unknown, high, kev])] == [
        "kev",
        "high",
        "low",
        "unknown",
    ]


def test_normalize_findings_dedups_and_sorts() -> None:
    dup = make_finding("r", "", "a.py", 1, "HIGH", "same", "", epss=0.5)
    assert normalize_findings([dup, dup]) == [dup]
