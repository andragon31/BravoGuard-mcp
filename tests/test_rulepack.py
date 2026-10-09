"""Z1 rule-pack: semgrep validate green, metadata convention, live sinks fire.

T10 extends the pack with 6 portable ERROR rules in the python/frontend
families (bandit-thin areas): JWT alg=none, yaml.load without SafeLoader,
random.* for tokens, requests SSRF, CORS wildcard, fetch SSRF. Loader
checks always run; live checks need semgrep and skip without it.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from bravoguard.owasp_map import explain_cwe

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
RULE_FIXTURES = ROOT / "tests" / "fixtures" / "rules"

EXPECTED_FRONTEND_IDS = {
    "bravoguard-frontend-dangerous-html",
    "bravoguard-frontend-bypass-security-trust",
}

# T10: 6 new portable ERROR rules (4 python + 2 frontend).
EXPECTED_T10_IDS = {
    "bravoguard-python-jwt-none",
    "bravoguard-python-yaml-unsafe-load",
    "bravoguard-python-weak-random",
    "bravoguard-python-ssrf-requests",
    "bravoguard-frontend-cors-wildcard",
    "bravoguard-frontend-ssrf-fetch",
}

EXPECTED_T10_CWE = {
    # jwt-none: forged tokens via alg=none -> CWE-347/A04 (signature
    # verification is a crypto failure, not an auth bypass).
    "bravoguard-python-jwt-none": ("CWE-347", "A04"),
    # yaml-unsafe-load: single-arg yaml.load builds arbitrary objects ->
    # CWE-502/A08 (same as the seed pickle rule).
    "bravoguard-python-yaml-unsafe-load": ("CWE-502", "A08"),
    # weak-random: predictable PRNG for tokens -> CWE-330/A04.
    "bravoguard-python-weak-random": ("CWE-330", "A04"),
    # ssrf-requests / ssrf-fetch: server-side request forgery -> CWE-918/A01.
    "bravoguard-python-ssrf-requests": ("CWE-918", "A01"),
    # cors-wildcard: permissive ACAO:* -> CWE-942/A02 (misconfiguration).
    "bravoguard-frontend-cors-wildcard": ("CWE-942", "A02"),
    "bravoguard-frontend-ssrf-fetch": ("CWE-918", "A01"),
}

EXPECTED_T10_LANGUAGES = {
    "bravoguard-python-jwt-none": ["python"],
    "bravoguard-python-yaml-unsafe-load": ["python"],
    "bravoguard-python-weak-random": ["python"],
    "bravoguard-python-ssrf-requests": ["python"],
    "bravoguard-frontend-cors-wildcard": ["javascript", "typescript"],
    "bravoguard-frontend-ssrf-fetch": ["javascript", "typescript"],
}

T10_FIXTURES = {
    "bravoguard-python-jwt-none": ("jwt_none_vuln.py", "jwt_none_fixed.py"),
    "bravoguard-python-yaml-unsafe-load": ("yaml_unsafe_vuln.py", "yaml_unsafe_fixed.py"),
    "bravoguard-python-weak-random": ("weak_random_vuln.py", "weak_random_fixed.py"),
    "bravoguard-python-ssrf-requests": ("ssrf_requests_vuln.py", "ssrf_requests_fixed.py"),
    "bravoguard-frontend-cors-wildcard": ("cors_wildcard_vuln.js", "cors_wildcard_fixed.js"),
    "bravoguard-frontend-ssrf-fetch": ("ssrf_fetch_vuln.js", "ssrf_fetch_fixed.js"),
}

SEMGREP = shutil.which("semgrep")
semgrep_missing = SEMGREP is None


def _load_all_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        rules.extend(yaml.safe_load(path.read_text(encoding="utf-8"))["rules"])
    return rules


def _rule_file_of(rule_id: str) -> Path:
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            if rule["id"] == rule_id:
                return path
    raise AssertionError(f"rule file not found: {rule_id}")


def test_rule_count_and_metadata_convention() -> None:
    rules = _load_all_rules()
    assert len(rules) == 14  # 2 python + 2 frontend + 4 supply-chain + 6 T10
    ids = {rule["id"] for rule in rules}
    assert EXPECTED_FRONTEND_IDS <= ids
    assert EXPECTED_T10_IDS <= ids
    for rule in rules:
        assert rule["metadata"]["cwe"]
        assert rule["metadata"]["owasp_2025"]
        assert rule["metadata"]["fix_hint"]
    frontend = [rule for rule in rules if rule["id"] in EXPECTED_FRONTEND_IDS]
    assert {rule["metadata"]["cwe"] for rule in frontend} == {"CWE-79"}


def test_t10_one_rule_per_file_and_prefix() -> None:
    for rule_id in EXPECTED_T10_IDS:
        path = _rule_file_of(rule_id)
        assert rule_id.startswith("bravoguard-")
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
        assert len(loaded) == 1
        assert loaded[0]["id"] == rule_id


def test_t10_metadata_and_owasp_resolve() -> None:
    by_id = {rule["id"]: rule for rule in _load_all_rules()}
    for rule_id, (cwe, owasp) in EXPECTED_T10_CWE.items():
        rule = by_id[rule_id]
        assert rule["severity"] == "ERROR"
        assert rule["languages"] == EXPECTED_T10_LANGUAGES[rule_id]
        assert rule["message"]
        assert rule["metadata"]["cwe"] == cwe
        assert rule["metadata"]["owasp_2025"] == owasp
        assert rule["metadata"]["fix_hint"]
        assert explain_cwe(cwe).get("owasp_2025") == owasp != "unknown"


def test_t10_portable_constructs_only() -> None:
    for rule_id in EXPECTED_T10_IDS:
        raw = _rule_file_of(rule_id).read_text(encoding="utf-8")
        assert "taint" not in raw
        assert "metavariable-regex" not in raw
        assert "metavariable-pattern" not in raw
    by_id = {rule["id"]: rule for rule in _load_all_rules()}
    for rule_id in EXPECTED_T10_IDS:
        rule = by_id[rule_id]
        assert "pattern" in rule or "patterns" in rule


def test_t10_family_dirs() -> None:
    for rule_id in EXPECTED_T10_IDS:
        path = _rule_file_of(rule_id)
        if rule_id.startswith("bravoguard-python-"):
            assert path.parent.name == "python", path
        else:
            assert path.parent.name == "frontend", path


def test_t10_fixtures_exist_and_differ() -> None:
    for rule_id, (vuln, fixed) in T10_FIXTURES.items():
        vuln_text = (RULE_FIXTURES / vuln).read_text(encoding="utf-8")
        fixed_text = (RULE_FIXTURES / fixed).read_text(encoding="utf-8")
        assert vuln_text.strip()
        assert fixed_text.strip()
        assert vuln_text != fixed_text, rule_id


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_semgrep_validate_green() -> None:
    proc = subprocess.run(
        [SEMGREP, "--metrics=off", "--validate", "--config", str(RULES_DIR)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def _scan_target(target: Path) -> dict:
    proc = subprocess.run(
        [SEMGREP, "--metrics=off", "--config", str(RULES_DIR), "--json", "--quiet", str(target)],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return json.loads(proc.stdout)


def _check_ids(payload: dict) -> set[str]:
    return {result["check_id"].split(".")[-1] for result in payload["results"]}


@pytest.fixture
def repo_probe_dir():
    """Live-scan targets live under the repo tree: semgrep hangs on %TEMP%
    targets on this Windows box (observed), repo targets scan in ~0.3s."""
    probe = ROOT / "probe-tmp"
    probe.mkdir(exist_ok=True)
    yield probe
    shutil.rmtree(probe, ignore_errors=True)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_innerhtml_seed_returns_finding(repo_probe_dir: Path) -> None:
    target = repo_probe_dir / "probe.js"
    target.write_text("el.innerHTML = userInput;\n", encoding="utf-8")
    payload = _scan_target(target)
    assert payload["errors"] == []
    ids = [result["check_id"] for result in payload["results"]]
    assert any("bravoguard-frontend-dangerous-html" in check_id for check_id in ids)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_dangerously_set_inner_html_returns_finding(repo_probe_dir: Path) -> None:
    target = repo_probe_dir / "probe.jsx"
    target.write_text(
        "const e = <div dangerouslySetInnerHTML={{ __html: userHtml }} />;\n",
        encoding="utf-8",
    )
    payload = _scan_target(target)
    assert payload["errors"] == []
    ids = [result["check_id"] for result in payload["results"]]
    assert any("bravoguard-frontend-dangerous-html" in check_id for check_id in ids)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_T10_IDS))
def test_live_t10_vuln_fixture_fires(repo_probe_dir: Path, rule_id: str) -> None:
    vuln, _ = T10_FIXTURES[rule_id]
    target = repo_probe_dir / vuln
    target.write_text((RULE_FIXTURES / vuln).read_text(encoding="utf-8"), encoding="utf-8")
    payload = _scan_target(target)
    assert payload["errors"] == []
    assert rule_id in _check_ids(payload)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_T10_IDS))
def test_live_t10_fixed_fixture_stays_silent(repo_probe_dir: Path, rule_id: str) -> None:
    _, fixed = T10_FIXTURES[rule_id]
    target = repo_probe_dir / fixed
    target.write_text((RULE_FIXTURES / fixed).read_text(encoding="utf-8"), encoding="utf-8")
    payload = _scan_target(target)
    assert payload["errors"] == []
    assert rule_id not in _check_ids(payload)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_python_rules_never_fire_on_js(repo_probe_dir: Path) -> None:
    """T2 split guard: python T10 rules must not fire on JS inputs."""
    py_ids = {r for r in EXPECTED_T10_IDS if r.startswith("bravoguard-python-")}
    for vuln in ("cors_wildcard_vuln.js", "ssrf_fetch_vuln.js"):
        target = repo_probe_dir / vuln
        target.write_text((RULE_FIXTURES / vuln).read_text(encoding="utf-8"), encoding="utf-8")
        assert not (_check_ids(_scan_target(target)) & py_ids)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_frontend_rules_never_fire_on_python(repo_probe_dir: Path) -> None:
    """T2 split guard: frontend T10 rules must not fire on python inputs."""
    fe_ids = {r for r in EXPECTED_T10_IDS if r.startswith("bravoguard-frontend-")}
    for vuln in (
        "jwt_none_vuln.py",
        "yaml_unsafe_vuln.py",
        "weak_random_vuln.py",
        "ssrf_requests_vuln.py",
    ):
        target = repo_probe_dir / vuln
        target.write_text((RULE_FIXTURES / vuln).read_text(encoding="utf-8"), encoding="utf-8")
        assert not (_check_ids(_scan_target(target)) & fe_ids)
