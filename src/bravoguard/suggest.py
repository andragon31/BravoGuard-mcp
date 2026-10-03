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

SUBPROCESS_SUGGESTION = (
    "Avoid shell=True, os.system(), and string commands with untrusted input "
    "(CWE-78). Pass an argv list with shell=False and validate any dynamic "
    "argument against an explicit allowlist. "
    'Example: subprocess.run(["git", "show", safe_ref], shell=False)  '
    "# quote with shlex.quote() only when a shell string is unavoidable"
)

EXEC_SUGGESTION = (
    "Replace exec() on dynamic input (CWE-78) with dispatch through an "
    "explicit allowlist of callables, or a fixed argv list with shell=False. "
    "Parse data with ast.literal_eval(), never exec(). "
    "Example: ALLOWED[name]()  # name checked against an allowlist first"
)

BIND_ALL_SUGGESTION = (
    "Do not bind 0.0.0.0 (all interfaces, CWE-605): bind 127.0.0.1 for "
    "local-only services, or make the bind address explicit configuration. "
    'Example: sock.bind(("127.0.0.1", port))  # never "0.0.0.0" by default'
)

PASSWORD_SUGGESTION = (
    "Remove the hard-coded password (CWE-259) and rotate it — assume it is "
    "exposed. Read it from an environment variable or a secrets manager; "
    "prompt with getpass for interactive use. "
    'Example: password = os.environ["DB_PASSWORD"]  # or getpass.getpass()'
)

EXCEPT_PASS_SUGGESTION = (
    "Do not silently pass (CWE-703): catch the narrowest exception you can "
    "handle and log it, so failures stay visible. "
    'Example: except (ValueError, KeyError): logger.exception("load failed")'
)

URLLIB_SUGGESTION = (
    "Restrict urlopen to http/https (CWE-22): parse with "
    "urllib.parse.urlparse and reject other schemes before the call — the "
    "same allow-list shape as cli._check_release_url. "
    'Example: if urlparse(url).scheme not in {"http", "https"}: '
    "raise ValueError"
)

RANDOM_SUGGESTION = (
    "Replace random with secrets for security purposes (CWE-330): the "
    "random module is predictable. "
    "Example: token = secrets.token_urlsafe(32)  # secrets.randbelow(n) "
    "for ranges"
)

PARTIAL_PATH_SUGGESTION = (
    "Resolve the executable to an absolute path (CWE-78 partial-path risk): "
    "look it up with shutil.which() and pass an argv list with shell=False. "
    'Example: exe = shutil.which("git"); '
    'subprocess.run([exe, "show", safe_ref], shell=False)  '
    "# quote with shlex.quote() only when a shell string is unavoidable"
)

SQL_SUGGESTION = (
    "Parameterize the query (CWE-89): never interpolate values into SQL "
    "strings — pass parameters to the driver instead. "
    'Example: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
)

HASH_SUGGESTION = (
    "Replace MD5/SHA1 with SHA-256 for integrity (CWE-327); for passwords "
    "use a password hasher (pbkdf2/bcrypt/argon2), never a fast digest. "
    "Example: hashlib.sha256(data).hexdigest()  "
    "# passwords: hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)"
)

CIPHER_SUGGESTION = (
    "Replace DES/3DES/ECB with a modern AEAD (CWE-327): AES-GCM via the "
    "cryptography package, with a fresh random nonce per message. "
    "Example: from cryptography.fernet import Fernet; "
    "Fernet(key).encrypt(data)"
)

MARSHAL_SUGGESTION = (
    "Replace marshal.loads() on untrusted input with json.loads() "
    "(CWE-502): marshal builds arbitrary objects like pickle. "
    "Example: obj = json.loads(data)  # only unmarshal data you produced"
)

SUPPLY_SUGGESTION = (
    "Quarantine this package: do not install or import it — install-time "
    "code runs with your privileges. Remove it from requirements/lockfiles, "
    "inspect setup.py for hidden payloads, rotate any exposed secrets, and "
    "report the package to the registry. "
    "Example: pip uninstall suspect-pkg  # then pin a trusted version"
)

TYPOSQUAT_SUGGESTION = (
    "Verify the exact package name on PyPI before installing — typosquats "
    "run install-time code with your privileges. Delete the suspect entry, "
    "pin the correct name and version (pip freeze / hash-checking mode), "
    "and audit recent installs for payloads. "
    "Example: pip install requests==2.32.3  # exact name, pinned version"
)

BUNDLED_BINARY_SUGGESTION = (
    "Review the bundled binary before trusting it: confirm provenance "
    "against the publisher release (hash/signature), prefer rebuilding "
    "from source, and keep binaries out of git (release artifacts instead). "
    "Example: sha256sum tools/app.exe  # compare with the publisher checksum"
)

PICKLE_IMPORT_SUGGESTION = (
    "The pickle import flags deserialization capability (CWE-502): keep it "
    "only if no untrusted input reaches pickle.load/loads — prefer json for "
    "external data. Example: obj = json.loads(data)  "
    "# audit every pickle.load/loads call site"
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
SUBPROCESS_RULES = frozenset(
    {
        "b602",
        "b603",
        "b604",
        "b605",
        "b606",
        "bravoguard-python-subprocess-shell",
        "bravoguard-python-os-system",
    }
)
# B404 (import subprocess) intentionally has no rule entry: the import alone
# is not a flaw (informational LOW), so it keeps the generic path. A B404
# finding still carries CWE-78 from bandit, so the CWE-78 fallback below may
# match it — that is pre-existing fallback behavior, not a B404 template.
PARTIAL_PATH_RULES = frozenset({"b607"})
EXEC_RULES = frozenset({"b102"})
BIND_ALL_RULES = frozenset({"b104"})
PASSWORD_RULES = frozenset({"b105", "b106", "b107"})
EXCEPT_PASS_RULES = frozenset({"b110"})
URLLIB_RULES = frozenset({"b310"})
RANDOM_RULES = frozenset({"b311"})
SQL_RULES = frozenset({"b608"})
HASH_RULES = frozenset({"b303", "b324"})
CIPHER_RULES = frozenset({"b304", "b305", "b413"})
MARSHAL_RULES = frozenset({"b302"})
PICKLE_IMPORT_RULES = frozenset({"b403"})
SUPPLY_RULES = frozenset(
    {
        "bravoguard-supply-install-exec",
        "bravoguard-supply-exfil",
        "bravoguard-supply-obfuscated-payload",
        "bravoguard-supply-remote-download",
    }
)
# H1 supply-plus rules get their own templates: typosquat needs pinning
# guidance (quarantine alone does not fix a misspelled dep) and bundled
# binaries need review-not-guilty guidance (binaries can be legitimate).
# No CWE fallbacks added: CWE-1357/CWE-506 stay on the generic path for
# unknown rule ids, so existing fallback behavior is unchanged.
TYPOSQUAT_RULES = frozenset({"bravoguard-supply-typosquat"})
BUNDLED_BIN_RULES = frozenset({"bravoguard-supply-bundled-binary"})

_RULE_TEMPLATES: dict[str, str] = {
    rule: EVAL_SUGGESTION for rule in EVAL_RULES
} | {
    rule: PICKLE_SUGGESTION for rule in PICKLE_RULES
} | {
    rule: INNERHTML_SUGGESTION for rule in INNERHTML_RULES
} | {
    rule: API_KEY_SUGGESTION for rule in API_KEY_RULES
} | {
    rule: SUBPROCESS_SUGGESTION for rule in SUBPROCESS_RULES
} | {
    rule: PARTIAL_PATH_SUGGESTION for rule in PARTIAL_PATH_RULES
} | {
    rule: EXEC_SUGGESTION for rule in EXEC_RULES
} | {
    rule: BIND_ALL_SUGGESTION for rule in BIND_ALL_RULES
} | {
    rule: PASSWORD_SUGGESTION for rule in PASSWORD_RULES
} | {
    rule: EXCEPT_PASS_SUGGESTION for rule in EXCEPT_PASS_RULES
} | {
    rule: URLLIB_SUGGESTION for rule in URLLIB_RULES
} | {
    rule: RANDOM_SUGGESTION for rule in RANDOM_RULES
} | {
    rule: SQL_SUGGESTION for rule in SQL_RULES
} | {
    rule: HASH_SUGGESTION for rule in HASH_RULES
} | {
    rule: CIPHER_SUGGESTION for rule in CIPHER_RULES
} | {
    rule: MARSHAL_SUGGESTION for rule in MARSHAL_RULES
} | {
    rule: PICKLE_IMPORT_SUGGESTION for rule in PICKLE_IMPORT_RULES
} | {
    rule: SUPPLY_SUGGESTION for rule in SUPPLY_RULES
} | {
    rule: TYPOSQUAT_SUGGESTION for rule in TYPOSQUAT_RULES
} | {
    rule: BUNDLED_BINARY_SUGGESTION for rule in BUNDLED_BIN_RULES
}

_CWE_TEMPLATES = {
    "CWE-95": EVAL_SUGGESTION,
    "CWE-502": PICKLE_SUGGESTION,
    "CWE-79": INNERHTML_SUGGESTION,
    "CWE-798": API_KEY_SUGGESTION,
    "CWE-78": SUBPROCESS_SUGGESTION,
    "CWE-605": BIND_ALL_SUGGESTION,
    "CWE-259": PASSWORD_SUGGESTION,
    "CWE-703": EXCEPT_PASS_SUGGESTION,
    "CWE-22": URLLIB_SUGGESTION,
    "CWE-330": RANDOM_SUGGESTION,
    "CWE-89": SQL_SUGGESTION,
    "CWE-327": HASH_SUGGESTION,
    # Shared fallbacks (documented, not collisions): B304/B305/B413 cipher
    # findings and B302 marshal / B403 pickle-import findings resolve their
    # OWASP refs through CWE-327 and CWE-502, while their rule keys above
    # select the more specific text.
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
