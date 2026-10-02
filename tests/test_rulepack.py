"""Z1 rule-pack: semgrep validate green, metadata convention, live sinks fire."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"

EXPECTED_FRONTEND_IDS = {
    "bravoguard-frontend-dangerous-html",
    "bravoguard-frontend-bypass-security-trust",
}

SEMGREP = shutil.which("semgrep")
semgrep_missing = SEMGREP is None


def _load_all_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(RULES_DIR.rglob("*.yaml")):
        rules.extend(yaml.safe_load(path.read_text(encoding="utf-8"))["rules"])
    return rules


def test_rule_count_and_metadata_convention() -> None:
    rules = _load_all_rules()
    assert len(rules) == 8  # 2 python + 2 frontend + 4 supply-chain
    ids = {rule["id"] for rule in rules}
    assert EXPECTED_FRONTEND_IDS <= ids
    for rule in rules:
        assert rule["metadata"]["cwe"]
        assert rule["metadata"]["owasp_2025"]
        assert rule["metadata"]["fix_hint"]
    frontend = [rule for rule in rules if rule["id"] in EXPECTED_FRONTEND_IDS]
    assert {rule["metadata"]["cwe"] for rule in frontend} == {"CWE-79"}


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
