"""Template-first fix suggestions for normalized findings (Phase 1, T5).

Rule-aware templates keyed by ``finding["rule_id"]`` with a CWE fallback;
unknown rules get a generic template carrying the OWASP reference from
``bravoguard.owasp_map``. No LLM calls — templates first per the PRD.
"""

from __future__ import annotations

from typing import Any

from bravoguard.owasp_map import explain_cwe

EVAL_SUGGESTION = (
    "Replace eval()/exec() on dynamic input with ast.literal_eval() for literal "
    "data, or dispatch through an explicit allowlist of callables. "
    "Never pass untrusted input to eval/exec. "
    "Example: result = ast.literal_eval(user_input)  # literals only"
)

PICKLE_SUGGESTION = (
    "Replace pickle.load()/loads() on untrusted input with json.load()/loads() "
    "or another safe format. If you must unpickle, only load data you produced "
    "and validate its source first. Example: obj = json.loads(data)"
)

INNERHTML_SUGGESTION = (
    "Avoid innerHTML/dangerouslySetInnerHTML with untrusted data. Use textContent "
    "for plain text, or sanitize with DOMPurify.sanitize() before injecting HTML. "
    "Example: el.textContent = userInput; "
    "// or el.innerHTML = DOMPurify.sanitize(userInput)"
)

API_KEY_SUGGESTION = (
    "Remove the hard-coded secret and rotate it immediately — assume it is "
    "exposed. Load it from an environment variable or a secret manager instead. "
    'Example: api_key = os.environ["API_KEY"]'
)

EVAL_RULES = frozenset({"bravoguard-python-eval", "bravoguard-python-eval-exec", "b307"})
PICKLE_RULES = frozenset({"bravoguard-python-pickle-load", "b301"})
INNERHTML_RULES = frozenset(
    {
        "bravoguard-frontend-innerhtml",
        "bravoguard-frontend-dangerous-html",
        "bravoguard-frontend-bypass-security-trust",
        "bravoguard-js-innerhtml",
    }
)
API_KEY_RULES = frozenset({"generic-api-key"})

_RULE_TEMPLATES: dict[str, str] = {
    rule: EVAL_SUGGESTION for rule in EVAL_RULES
} | {
    rule: PICKLE_SUGGESTION for rule in PICKLE_RULES
} | {
    rule: INNERHTML_SUGGESTION for rule in INNERHTML_RULES
} | {
    rule: API_KEY_SUGGESTION for rule in API_KEY_RULES
}

_CWE_TEMPLATES = {
    "CWE-95": EVAL_SUGGESTION,
    "CWE-502": PICKLE_SUGGESTION,
    "CWE-79": INNERHTML_SUGGESTION,
    "CWE-798": API_KEY_SUGGESTION,
}


def _normalize_cwe(value: Any) -> str:
    text = str(value or "").strip()
    if text.isdigit():
        return f"CWE-{text}"
    return text.upper() if text.upper().startswith("CWE-") else text


def _owasp_ref(cwe: str) -> str:
    if not cwe:
        return "unknown"
    return str(explain_cwe(cwe).get("owasp_2025", "unknown"))


def _generic_suggestion(rule_id: str, cwe: str, owasp: str, fix_hint: str) -> str:
    label = f"'{rule_id}' ({cwe or 'unknown CWE'}, OWASP {owasp})"
    hint = f" {fix_hint.strip()}" if fix_hint.strip() else ""
    return (
        f"No rule-specific template for {label}.{hint} "
        f"Fix at the source: validate untrusted input and avoid the unsafe sink. "
        f"See OWASP {owasp} for the category guidance."
    )


def suggest_for_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a template fix for one normalized finding.

    Output keys: ``suggestion, rule_id, cwe, owasp_ref``. Empty input yields
    an empty suggestion; unknown rules fall back to the generic template.
    """
    if not finding:
        return {"suggestion": "", "rule_id": "unknown", "cwe": "", "owasp_ref": "unknown"}
    rule_id = str(finding.get("rule_id") or "unknown")
    cwe = _normalize_cwe(finding.get("cwe"))
    owasp = _owasp_ref(cwe)
    template = _RULE_TEMPLATES.get(rule_id.strip().lower()) or _CWE_TEMPLATES.get(cwe)
    suggestion = template or _generic_suggestion(
        rule_id, cwe, owasp, str(finding.get("fix_hint") or "")
    )
    return {"suggestion": suggestion, "rule_id": rule_id, "cwe": cwe, "owasp_ref": owasp}
