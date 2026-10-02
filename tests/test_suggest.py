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
    result = suggest_for_finding(_finding("unknown-rule", "CWE-94", "Use parameters."))
    assert result["suggestion"] != ""
    assert result["rule_id"] == "unknown-rule"
    assert result["cwe"] == "CWE-94"
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


@pytest.mark.parametrize("rule_id", ["B602", "B603", "B604", "B605", "B606"])
def test_subprocess_bandit_rules_use_argv_template(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-78"))
    assert "shell=False" in result["suggestion"]
    assert "shlex.quote" in result["suggestion"]
    assert result["cwe"] == "CWE-78"
    assert result["owasp_ref"] == "A05"


def test_b607_partial_path_points_to_absolute_path() -> None:
    result = suggest_for_finding(_finding("B607", "CWE-78"))
    assert "shutil.which" in result["suggestion"]
    assert "shell=False" in result["suggestion"]
    assert "shlex.quote" in result["suggestion"]
    assert result["owasp_ref"] == "A05"


def test_b102_exec_points_to_allowlist_not_shell_template() -> None:
    result = suggest_for_finding(_finding("B102", "CWE-78"))
    assert "allowlist" in result["suggestion"]
    assert "ast.literal_eval" in result["suggestion"]
    assert result["owasp_ref"] == "A05"


def test_b104_bind_all_points_to_loopback() -> None:
    result = suggest_for_finding(_finding("B104", "CWE-605"))
    assert "127.0.0.1" in result["suggestion"]
    assert "0.0.0.0" in result["suggestion"]
    # Honest exception: bandit maps B104 to CWE-605, which OWASP Top 10:2025
    # does not list (verified against our 249-CWE table), so owasp_ref stays
    # unknown instead of an invented category.
    assert result["owasp_ref"] == "unknown"


def test_cwe605_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-bind-rule", "CWE-605"))
    assert "127.0.0.1" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


@pytest.mark.parametrize("rule_id", ["B105", "B106", "B107"])
def test_hardcoded_password_points_to_env(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-259"))
    assert "os.environ" in result["suggestion"]
    assert "rotate" in result["suggestion"]
    assert result["owasp_ref"] == "A07"


def test_cwe259_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-secret-rule", "CWE-259"))
    assert "os.environ" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_b110_except_pass_points_to_logging() -> None:
    result = suggest_for_finding(_finding("B110", "CWE-703"))
    assert "logger.exception" in result["suggestion"]
    assert "pass" in result["suggestion"]
    assert result["owasp_ref"] == "A10"


def test_cwe703_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-except-rule", "CWE-703"))
    assert "logger.exception" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_b310_urlopen_points_to_scheme_allowlist() -> None:
    result = suggest_for_finding(_finding("B310", "CWE-22"))
    assert "urlparse" in result["suggestion"]
    assert "https" in result["suggestion"]
    assert result["owasp_ref"] == "A01"


def test_cwe22_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-url-rule", "CWE-22"))
    assert "urlparse" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_b311_random_points_to_secrets() -> None:
    result = suggest_for_finding(_finding("B311", "CWE-330"))
    assert "secrets." in result["suggestion"]
    assert result["owasp_ref"] == "A04"


def test_cwe330_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-random-rule", "CWE-330"))
    assert "secrets." in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_b608_sql_points_to_parameters() -> None:
    result = suggest_for_finding(_finding("B608", "CWE-89"))
    assert "cursor.execute" in result["suggestion"]
    assert "%s" in result["suggestion"]
    assert result["owasp_ref"] == "A05"


def test_cwe89_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-sql-rule", "CWE-89"))
    assert "cursor.execute" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


@pytest.mark.parametrize("rule_id", ["B303", "B324"])
def test_weak_hash_points_to_sha256(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-327"))
    assert "sha256" in result["suggestion"]
    assert "pbkdf2" in result["suggestion"]
    assert result["owasp_ref"] == "A04"


@pytest.mark.parametrize("rule_id", ["B304", "B305", "B413"])
def test_weak_cipher_points_to_aead(rule_id: str) -> None:
    result = suggest_for_finding(_finding(rule_id, "CWE-327"))
    assert "AES-GCM" in result["suggestion"] or "Fernet" in result["suggestion"]
    assert result["owasp_ref"] == "A04"


def test_cwe327_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-crypto-rule", "CWE-327"))
    assert "sha256" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_b302_marshal_points_to_json() -> None:
    result = suggest_for_finding(_finding("B302", "CWE-502"))
    assert "marshal" in result["suggestion"]
    assert "json.loads" in result["suggestion"]
    assert result["owasp_ref"] == "A08"


def test_b403_pickle_import_flags_capability() -> None:
    result = suggest_for_finding(_finding("B403", "CWE-502"))
    assert "import" in result["suggestion"]
    assert "json.loads" in result["suggestion"]
    assert result["owasp_ref"] == "A08"


def test_cwe502_fallback_stays_non_generic() -> None:
    result = suggest_for_finding(_finding("some-new-deser-rule", "CWE-502"))
    assert "json" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]
    assert result["owasp_ref"] == "A08"


@pytest.mark.parametrize(
    ("rule_id", "cwe"),
    [
        ("B102", "CWE-78"),
        ("B105", "CWE-259"),
        ("B106", "CWE-259"),
        ("B107", "CWE-259"),
        ("B110", "CWE-703"),
        ("B302", "CWE-502"),
        ("B303", "CWE-327"),
        ("B304", "CWE-327"),
        ("B305", "CWE-327"),
        ("B310", "CWE-22"),
        ("B311", "CWE-330"),
        ("B324", "CWE-327"),
        ("B403", "CWE-502"),
        ("B413", "CWE-327"),
        ("B602", "CWE-78"),
        ("B607", "CWE-78"),
        ("B608", "CWE-89"),
    ],
)
def test_new_templates_carry_known_owasp_ref(rule_id: str, cwe: str) -> None:
    result = suggest_for_finding(_finding(rule_id, cwe))
    assert "No rule-specific template" not in result["suggestion"]
    assert result["owasp_ref"] != "unknown"


def test_cwe78_fallback_when_rule_unknown() -> None:
    result = suggest_for_finding(_finding("some-new-shell-rule", "CWE-78"))
    assert "shell=False" in result["suggestion"]
    assert "No rule-specific template" not in result["suggestion"]


def test_bravoguard_subprocess_equivalent() -> None:
    result = suggest_for_finding(_finding("bravoguard-python-subprocess-shell", "CWE-78"))
    assert "shell=False" in result["suggestion"]


def test_server_suggest_fix_wired_to_templates() -> None:
    from bravoguard import server

    wired = asyncio.run(server.suggest_fix(_finding("generic-api-key", "CWE-798")))
    assert wired["status"] == "ok"
    assert "os.environ" in wired["suggestion"]
    assert wired["rule_id"] == "generic-api-key"
    assert wired["cwe"] == "CWE-798"
    assert wired["owasp_ref"] == "A07"
    assert "not-implemented" not in wired["status"]

    empty = asyncio.run(server.suggest_fix({}))
    assert empty == {"status": "empty-finding", "suggestion": ""}
