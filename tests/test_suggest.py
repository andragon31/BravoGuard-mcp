"""T5 suggest_fix templates: one template per seed rule, generic fallback, guards."""

import asyncio

import pytest

from bravoguard.normalizer import make_finding
from bravoguard.suggest import suggest_for_finding


def _finding(rule_id: str, cwe: str, fix_hint: str = "") -> dict:
    return make_finding(rule_id, cwe, "app.py", 1, "HIGH", "Seeded message.", fix_hint)


def test_eval_template_points_to_literal_eval() -> None:
    result = suggest_for_finding(_finding("bravoguard-python-eval-exec", "CWE-95"))
    assert "ast.literal_eval" in result["suggestion"]
    assert result["rule_id"] == "bravoguard-python-eval-exec"
    assert result["cwe"] == "CWE-95"
    assert result["owasp_ref"] == "A05"


def test_eval_alias_template() -> None:
    result = suggest_for_finding(_finding("bravoguard-python-eval", "CWE-95"))
    assert "ast.literal_eval" in result["suggestion"]
    assert result["owasp_ref"] == "A05"


@pytest.mark.parametrize("rule_id", ["bravoguard-python-pickle-load", "B301"])
def test_pickle_template_points_to_json(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-502"))
    assert "json" in result["suggestion"]
    assert result["cwe"] == "CWE-502"
    assert result["owasp_ref"] == "A08"


@pytest.mark.parametrize(
    "rule_id", ["bravoguard-frontend-dangerous-html", "bravoguard-js-innerhtml"]
)
def test_innerhtml_template_points_to_textcontent_or_sanitizer(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-79"))
    assert "textContent" in result["suggestion"] or "sanitize" in result["suggestion"]
    assert result["owasp_ref"] == "A05"


def test_api_key_template_points_to_env_var() -> None:
    result = suggest_for_finding(_finding("generic-api-key", "CWE-798"))
    assert "os.environ" in result["suggestion"]
    assert result["owasp_ref"] == "A07"


def test_cwe_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-scanner-rule", "CWE-95"))
    assert "ast.literal_eval" in result["suggestion"]
    assert result["rule_id"] == "some-new-scanner-rule"


def test_generic_fallback_carries_owasp_ref() -> None:
    result = suggest_for_finding(_finding("unknown-rule", "CWE-89", "Use parameters."))
    assert result["suggestion"] != ""
    assert result["rule_id"] == "unknown-rule"
    assert result["cwe"] == "CWE-89"
    assert result["owasp_ref"] == "A05"
    assert "Use parameters." in result["suggestion"]


def test_generic_fallback_unknown_cwe() -> None:
    result = suggest_for_finding(_finding("unknown-rule", ""))
    assert result["suggestion"] != ""
    assert result["owasp_ref"] == "unknown"


def test_empty_finding_guard() -> None:
    assert suggest_for_finding({}) == {
        "suggestion": "",
        "rule_id": "unknown",
        "cwe": "",
        "owasp_ref": "unknown",
    }


@pytest.mark.parametrize("rule_id", ["B603", "B604", "B605", "B606", "B607"])
def test_subprocess_bandit_rules_use_argv_template(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-78"))
    assert "shell=False" in result["suggestion"]
    assert "shlex.quote" in result["suggestion"]
    assert result["cwe"] == "CWE-78"
    assert result["owasp_ref"] == "A05"


def test_cwe78_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-shell-rule", "CWE-78"))
    assert "shell=False" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_bravoguard_subprocess_equivalent() -> None:
    result = suggest_for_finding(_finding("bravoguard-python-subprocess-shell", "CWE-78"))
    assert "shell=False" in result["suggestion"]


def test_server_suggest_fix_wired_to_templates() -> None:
    import bravoguard.server as server

    wired = asyncio.run(server.suggest_fix(_finding("generic-api-key", "CWE-798")))
    assert wired["status"] == "ok"
    assert "os.environ" in wired["suggestion"]
    assert wired["rule_id"] == "generic-api-key"
    assert wired["cwe"] == "CWE-798"
    assert wired["owasp_ref"] == "A07"
    assert "not-implemented" not in wired["status"]

    empty = asyncio.run(server.suggest_fix({}))
    assert empty == {"status": "empty-finding", "suggestion": ""}
