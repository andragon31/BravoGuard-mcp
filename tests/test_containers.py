"""T8 containers-lane tests: hadolint, kics (compose/dockerfile only), dockle/dive opt-in.

All subprocesses are mocked; no real hadolint/kics/dockle/dive binary is
invoked and no image is ever built or pulled (the opt-in matrix asserts
no-build explicitly). Fixtures under ``tests/fixtures/containers/``:

- Dockerfile.bad / Dockerfile.good (real files; the .bad findings below
  were RECORDED live: hadolint 2.15.1 ``--format json`` on this file).
- hadolint.json (live-recorded hadolint 2.15.1 output; ``--format json``
  verified live in ``hadolint --help``: ``-f,--format [tty | json | ...]``).
- docker-compose.yml (compose with privileged + latest + creds).
- kics.json (documented source: kics ``scan -p <file> -o <out>
  --report-formats json`` writes ``results.json`` with a ``queries`` array;
  binary absent in this env, so live ``--help`` re-verification owed).
- dockle.json (documented source: dockle README ``-f json`` envelope with
  ``summary`` + ``details``; ``-f/--format (list, json, sarif)`` and
  ``--input`` verified live in ``dockle --help``; daemon-gated live run
  owed, so the runner is never invoked for real here).
- dive.txt (documented source: ``dive --ci`` prints efficiency /
  wastedBytes / ``Result:`` lines; ``--ci`` + ``--source
  docker|podman|docker-archive`` verified live in ``dive --help``;
  daemon-gated live run owed).

Design decisions (documented cuts, per spec):

- kics NEVER runs on Terraform/K8s (checkov owns those): discovery yields
  only compose + dockerfile basenames, and the runner re-filters targets
  defensively (a .tf path passed programmatically still never spawns).
- dive feeds ``recommendations[]``, NOT findings: image efficiency is not a
  vulnerability (contract asserted below).
- dockle/dive only run with ``container_image=<tar|ref>`` (default None =
  skipped + reason); scan_diff has no image param so both lanes always skip
  there. NEVER auto-build (no ``dive build``, no registry push/pull).
"""

import asyncio
import json
import shutil
from pathlib import Path

from bravoguard import orchestrator
from bravoguard.languages import LANE_GATES, SKIP_REASONS, detect_languages, lanes_for
from bravoguard.normalizer import (
    FINDING_KEYS,
    dive_recommendations,
    normalize_dockle,
    normalize_hadolint,
    normalize_kics,
    parse_dive_output,
)
from bravoguard.owasp_map import explain_cwe
from bravoguard.suggest import suggest_for_finding

FIXTURES = Path(__file__).parent / "fixtures" / "containers"
HADOLINT_FIXTURE = FIXTURES / "hadolint.json"
KICS_FIXTURE = FIXTURES / "kics.json"
DOCKLE_FIXTURE = FIXTURES / "dockle.json"
DIVE_FIXTURE = FIXTURES / "dive.txt"

PY_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import os
+print(os.name)
"""

JS_DIFF = """\
diff --git a/app.js b/app.js
index 1111111..2222222 100644
--- a/app.js
+++ b/app.js
@@ -0,0 +1,2 @@
+const x = eval(userInput);
+debugger;
"""

DOCKERFILE_DIFF = """\
diff --git a/Dockerfile b/Dockerfile
index 1111111..2222222 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -0,0 +1,3 @@
+FROM ubuntu:latest
+RUN apt-get update && apt-get install -y curl
+CMD service app start
"""


class FakeProcess:
    """Minimal stand-in for asyncio.subprocess.Process."""

    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self, input_data=None):
        return (self._stdout, self._stderr)

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def install_fake(monkeypatch, responses: dict, calls: list) -> None:
    """Patch create_subprocess_exec so each binary returns canned output.

    ``responses`` maps lane label -> ``(stdout, returncode)``. The kics leg
    writes ``results.json`` (gitleaks/deptry tmpfile pattern): the fake
    finds the ``-o`` outdir in argv and drops the fixture there, proving
    the runner reads the report file (stdout is progress logs only).
    Unknown binaries raise FileNotFoundError (absent).
    """

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        arglist = [str(a) for a in argv]
        if first == "uv" and "checkov" in names:
            label = "checkov"
        elif first == "kics":
            outdir = Path(arglist[arglist.index("-o") + 1])
            (outdir / "results.json").write_bytes(KICS_FIXTURE.read_bytes())
            return FakeProcess(b"", b"", 0)
        elif first in ("hadolint", "dockle", "dive"):
            label = first
        elif first == "npm" and "audit" in arglist:
            label = "npm-audit"
        else:
            label = first
        if label not in responses:
            raise FileNotFoundError(label)
        stdout, returncode = responses[label]
        return FakeProcess(stdout, b"", returncode)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)


def quiet_responses(**overrides: object) -> dict:
    responses: dict = {
        "semgrep": (b'{"results": []}', 0),
        "opengrep": (b'{"results": []}', 0),
        "bandit": (b'{"results": []}', 0),
        "betterleaks": (b"[]", 0),
        "gitleaks": (b"[]", 0),
        "oxlint": (b'{"diagnostics": []}', 0),
        "cmd": (b'{"diagnostics": []}', 0),
        "trivy": (b"{}", 0),
        "uv": (b'{"results": {"failed_checks": []}}', 0),
        "ruff": (b"[]", 0),
        "vulture": (b"", 0),
        "eslint": (b"[]", 0),
        "knip": (b'{"issues": []}', 0),
        "lockfile-lint": (b"", 0),
        "npm-audit": (b'{"vulnerabilities": {}}', 0),
        "hadolint": (HADOLINT_FIXTURE.read_bytes(), 1),
        "dockle": (DOCKLE_FIXTURE.read_bytes(), 0),
        "dive": (DIVE_FIXTURE.read_bytes(), 0),
    }
    responses.update(overrides)
    return responses


def patch_binaries(
    monkeypatch,
    *,
    hadolint=True,
    kics=True,
    dockle=True,
    dive=True,
) -> None:
    """Control shutil.which for the T8 presence matrix (rest pass through)."""
    wanted = {
        "hadolint": hadolint,
        "kics": kics,
        "dockle": dockle,
        "dive": dive,
    }
    real_which = shutil.which

    def fake_which(name: str):
        if name in wanted:
            return f"/usr/bin/{name}" if wanted[name] else None
        if name in (
            "syft",
            "grype",
            "guarddog",
            "ruff",
            "vulture",
            "deptry",
            "eslint",
            "knip",
            "lockfile-lint",
            "npm",
        ):
            return None
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)


def spawned_binaries(calls: list) -> set[str]:
    labels = set()
    for argv, _ in calls:
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        arglist = [str(a) for a in argv]
        if first == "uv" and "checkov" in names:
            labels.add("checkov")
        elif first == "npm" and "audit" in arglist:
            labels.add("npm-audit")
        else:
            labels.add(first)
    return labels


def spawn_count(calls: list, binary: str) -> int:
    return sum(1 for argv, _ in calls if Path(str(argv[0])).name == binary)


def hadolint_payload() -> list:
    return json.loads(HADOLINT_FIXTURE.read_text(encoding="utf-8"))


def kics_payload() -> dict:
    return json.loads(KICS_FIXTURE.read_text(encoding="utf-8"))


def dockle_payload() -> dict:
    return json.loads(DOCKLE_FIXTURE.read_text(encoding="utf-8"))


# --- discovery -------------------------------------------------------------


def test_container_discovery_finds_dockerfiles_and_variants(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "Dockerfile.prod").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "Containerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    found = {p.name for p in orchestrator._container_dockerfiles(tmp_path, ())}
    assert found == {"Dockerfile", "Dockerfile.prod", "Containerfile"}


def test_container_discovery_honors_excludes(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    sub = tmp_path / "vendor"
    sub.mkdir()
    (sub / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    found = {p.name for p in orchestrator._container_dockerfiles(tmp_path, ("vendor/",))}
    assert found == {"Dockerfile"}
    assert all("vendor" not in str(p) for p in orchestrator._container_dockerfiles(tmp_path, ("vendor/",)))


def test_compose_discovery_finds_compose_only(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    (tmp_path / "deploy.yaml").write_text("kind: Pod\n", encoding="utf-8")
    found = {p.name for p in orchestrator._container_compose_files(tmp_path)}
    assert found == {"docker-compose.yml", "compose.yaml"}


def test_kics_targets_never_include_terraform(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    (tmp_path / "k8s.yaml").write_text("kind: Deployment\n", encoding="utf-8")
    targets = orchestrator._kics_targets(tmp_path, ())
    assert {p.name for p in targets} == {"Dockerfile", "docker-compose.yml"}
    assert not any(p.suffix == ".tf" for p in targets)


# --- argv shapes -----------------------------------------------------------


def test_hadolint_argv_format_json_over_files() -> None:
    argv = orchestrator.hadolint_argv(["/repo/Dockerfile", "/repo/Dockerfile.prod"])
    assert argv[0] == "hadolint"
    assert argv[argv.index("--format") + 1] == "json"
    assert "/repo/Dockerfile" in argv
    assert "/repo/Dockerfile.prod" in argv


def test_kics_argv_scan_path_out_report_json() -> None:
    argv = orchestrator.kics_argv("/repo/docker-compose.yml", "/tmp/kics-out")
    assert argv[:2] == ["kics", "scan"]
    assert argv[argv.index("-p") + 1] == "/repo/docker-compose.yml"
    assert argv[argv.index("-o") + 1] == "/tmp/kics-out"
    assert argv[argv.index("--report-formats") + 1] == "json"
    assert "--no-progress" in argv


def test_dockle_argv_tar_uses_input_flag_and_ref_is_positional(tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_bytes(b"fake-tar")
    argv = orchestrator.dockle_argv(str(tar))
    assert argv[0] == "dockle"
    assert argv[argv.index("-f") + 1] == "json"
    assert argv[argv.index("--input") + 1] == str(tar)
    ref_argv = orchestrator.dockle_argv("myapp:latest")
    assert ref_argv == ["dockle", "-f", "json", "myapp:latest"]


def test_dive_argv_ci_and_tar_uses_docker_archive(tmp_path: Path) -> None:
    tar = tmp_path / "img.tar"
    tar.write_bytes(b"fake-tar")
    argv = orchestrator.dive_argv(str(tar))
    assert argv[0] == "dive"
    assert "--ci" in argv
    assert argv[argv.index("--source") + 1] == "docker-archive"
    assert str(tar) in argv
    ref_argv = orchestrator.dive_argv("myapp:latest")
    assert ref_argv == ["dive", "--ci", "myapp:latest"]


# --- hadolint normalize ----------------------------------------------------


def test_normalize_hadolint_mapping_live_recorded() -> None:
    findings = normalize_hadolint(hadolint_payload())
    assert len(findings) == 6
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["hadolint-DL3007"]["path"] == "Dockerfile.bad"
    assert by_rule["hadolint-DL3007"]["line"] == 1
    assert "latest" in by_rule["hadolint-DL3007"]["message"]
    assert by_rule["hadolint-DL4000"]["severity"] == "MEDIUM"
    assert by_rule["hadolint-DL3007"]["severity"] == "LOW"
    assert by_rule["hadolint-DL3015"]["severity"] == "LOW"


def test_normalize_hadolint_severity_map_and_high_cap() -> None:
    payload = [
        {"code": "DL4000", "file": "Dockerfile", "line": 1, "level": "error", "message": "m"},
        {"code": "DL3007", "file": "Dockerfile", "line": 2, "level": "warning", "message": "m"},
        {"code": "DL3015", "file": "Dockerfile", "line": 3, "level": "info", "message": "m"},
        {"code": "DL3002", "file": "Dockerfile", "line": 4, "level": "error", "message": "m"},
        {"code": "DL3002", "file": "Dockerfile", "line": 5, "level": "warning", "message": "m"},
    ]
    by_line = {f["line"]: f for f in normalize_hadolint(payload)}
    assert by_line[1]["severity"] == "MEDIUM"
    assert by_line[2]["severity"] == "LOW"
    assert by_line[3]["severity"] == "LOW"
    # DL3002 is security-elevated (last-user-root) but capped at HIGH max.
    assert by_line[4]["severity"] == "HIGH"
    assert by_line[5]["severity"] == "HIGH"
    assert all(f["severity"] != "CRITICAL" for f in normalize_hadolint(payload))


def test_normalize_hadolint_dl_to_cwe_verified() -> None:
    findings = normalize_hadolint(hadolint_payload())
    by_rule = {f["rule_id"]: f for f in findings}
    # Spec floor: DL3002 -> CWE-250 (explain_cwe has no OWASP category for
    # it — recorded honestly here, not fabricated into a category).
    assert explain_cwe("CWE-250")["owasp_2025"] == "unknown"
    elevated = normalize_hadolint(
        [{"code": "DL3002", "file": "D", "line": 1, "level": "warning", "message": "m"}]
    )
    assert elevated[0]["cwe"] == "CWE-250"
    # Every other mapped CWE must resolve to a real OWASP category.
    from bravoguard.normalizer import HADOLINT_CWE_BY_CODE

    for code, cwe in HADOLINT_CWE_BY_CODE.items():
        if cwe == "CWE-250":
            continue
        assert explain_cwe(cwe)["owasp_2025"] != "unknown", f"{code} -> {cwe} unverified"
    assert by_rule["hadolint-DL3007"]["cwe"] == "CWE-829"
    assert by_rule["hadolint-DL3008"]["cwe"] == "CWE-829"
    assert by_rule["hadolint-DL3025"]["cwe"] == "CWE-78"
    assert by_rule["hadolint-DL3015"]["cwe"] == ""


def test_normalize_hadolint_fix_hint_per_code() -> None:
    findings = normalize_hadolint(hadolint_payload())
    by_rule = {f["rule_id"]: f for f in findings}
    assert "USER" in by_rule["hadolint-DL3007"]["fix_hint"] or "tag" in by_rule[
        "hadolint-DL3007"
    ]["fix_hint"].lower()
    assert by_rule["hadolint-DL3008"]["fix_hint"] != ""
    assert by_rule["hadolint-DL3025"]["fix_hint"] != ""
    # Unknown codes fall back to a docs-link hint, never empty.
    unknown = normalize_hadolint(
        [{"code": "DL9999", "file": "D", "line": 1, "level": "info", "message": "m"}]
    )
    assert unknown[0]["rule_id"] == "hadolint-DL9999"
    assert unknown[0]["fix_hint"] != ""


def test_normalize_hadolint_tolerates_empty_and_garbage() -> None:
    assert normalize_hadolint({}) == []
    assert normalize_hadolint([]) == []
    assert normalize_hadolint(None) == []
    assert normalize_hadolint([{"nope": True}, "garbage", None]) == []


# --- kics normalize + restriction ------------------------------------------


def test_normalize_kics_mapping() -> None:
    findings = normalize_kics(kics_payload())
    assert len(findings) == 2
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    by_rule = {f["rule_id"]: f for f in findings}
    assert "kics-c98a953d" in next(iter(by_rule)).lower() or any(
        "Privileged" in f["message"] or "privileged" in f["message"].lower()
        for f in findings
    )
    priv = next(f for f in findings if "ocker" in f["path"] or "compose" in f["path"])
    assert priv["path"] == "docker-compose.yml"
    assert priv["line"] == 4
    assert priv["severity"] == "HIGH"


def test_normalize_kics_severity_capped_at_high() -> None:
    findings = normalize_kics(kics_payload())
    creds = next(f for f in findings if f["severity"] == "HIGH" and "Credential" in f["message"])
    assert creds["severity"] == "HIGH"
    assert all(f["severity"] != "CRITICAL" for f in findings)


def test_normalize_kics_fix_hint_from_remediation() -> None:
    findings = normalize_kics(kics_payload())
    priv = next(f for f in findings if "Privileged" in f["message"])
    assert "privileged" in priv["fix_hint"].lower()
    # Queries without remediation fall back to the docs URL, never empty.
    creds = next(f for f in findings if "Credential" in f["message"])
    assert creds["fix_hint"] != ""


def test_normalize_kics_tolerates_empty_payload() -> None:
    assert normalize_kics({}) == []
    assert normalize_kics({"queries": []}) == []
    assert normalize_kics([]) == []


def test_kics_runner_refuses_terraform_targets(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator._run_kics(["/repo/main.tf"], 10.0))
    assert result == ("kics", {"queries": []})
    assert spawn_count(calls, "kics") == 0


# --- dockle normalize ------------------------------------------------------


def test_normalize_dockle_mapping() -> None:
    findings = normalize_dockle(dockle_payload())
    assert len(findings) == 2
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["dockle-CIS-DI-0001"]["severity"] == "MEDIUM"
    assert by_rule["dockle-CIS-DI-0006"]["severity"] == "LOW"
    assert all(f["severity"] != "CRITICAL" for f in findings)


def test_normalize_dockle_tolerates_empty_payload() -> None:
    assert normalize_dockle({}) == []
    assert normalize_dockle({"details": []}) == []


# --- dive recommendations (NOT findings) -----------------------------------


def test_parse_dive_output_extracts_score_and_waste() -> None:
    parsed = parse_dive_output(DIVE_FIXTURE.read_text(encoding="utf-8"))
    assert parsed["efficiency"] == 94.20
    assert parsed["wasted_bytes"] == 15728640
    assert parsed["result"] == "FAIL"


def test_dive_recommendations_split_from_findings() -> None:
    recs = dive_recommendations({"image": "myapp:latest", "output": DIVE_FIXTURE.read_text()})
    assert len(recs) == 2
    for rec in recs:
        assert set(rec) == {"source", "rule_id", "message", "image"}
        assert rec["source"] == "dive"
    by_rule = {r["rule_id"]: r for r in recs}
    assert "dive-efficiency" in by_rule
    assert "dive-wasted-space" in by_rule
    assert "94.2" in by_rule["dive-efficiency"]["message"]
    # Efficiency is not a vulnerability: no finding-shaped keys, no severity.
    assert all("severity" not in r and "cwe" not in r for r in recs)


def test_dive_recommendations_empty_on_clean_parse() -> None:
    assert dive_recommendations({"image": "x", "output": ""}) == []
    assert dive_recommendations({}) == []


# --- suggest templates -----------------------------------------------------


def test_suggest_templates_per_dl_code() -> None:
    expectations = {
        "hadolint-DL3002": ("USER", "root"),
        "hadolint-DL3006": ("tag",),
        "hadolint-DL3007": ("latest",),
        "hadolint-DL3008": ("version",),
        "hadolint-DL3025": ("exec", "JSON"),
        "hadolint-DL3015": ("install-recommends",),
    }
    for rule_id, keywords in expectations.items():
        out = suggest_for_finding({"rule_id": rule_id, "cwe": "", "fix_hint": ""})
        assert out["rule_id"] == rule_id
        assert any(k.lower() in out["suggestion"].lower() for k in keywords), rule_id


def test_suggest_generic_fallback_preserved() -> None:
    out = suggest_for_finding({"rule_id": "hadolint-DL9999", "cwe": "", "fix_hint": ""})
    assert "No rule-specific template" in out["suggestion"]


# --- lane registration -----------------------------------------------------


def test_lane_gates_containers_signal_and_image_param() -> None:
    assert LANE_GATES["hadolint"] == {"kind": "suffix", "languages": ("containers",)}
    assert LANE_GATES["kics"] == {"kind": "suffix", "languages": ("containers",)}
    assert LANE_GATES["dockle"]["kind"] == "image"
    assert LANE_GATES["dive"]["kind"] == "image"
    assert {"hadolint", "kics", "dockle", "dive"} <= set(SKIP_REASONS)


def test_lanes_for_image_lanes_always_skip_without_param(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    skips = lanes_for(detect_languages(tmp_path))
    assert "hadolint" not in skips
    assert "kics" not in skips
    # Image lanes stay skipped even with containers detected: the opt-in
    # param (not detection) lifts them in the orchestrator.
    assert "dockle" in skips
    assert "dive" in skips


# --- missing-binary skips --------------------------------------------------


def test_missing_container_binaries_skip_repo_lanes(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (repo / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    patch_binaries(monkeypatch, hadolint=False, kics=False, dockle=False, dive=False)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    for lane in ("hadolint", "kics"):
        assert lane in result["skipped"]
        assert "not installed" in result["skipped"][lane].lower()
        assert lane not in result.get("errors", {})
    assert "hadolint" not in spawned_binaries(calls)
    assert "kics" not in spawned_binaries(calls)


# --- opt-in skip matrix (no image -> skipped, no build) --------------------


def test_no_image_skips_dockle_dive_without_spawn(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "dockle" in result["skipped"]
    assert "dive" in result["skipped"]
    assert "container_image" in result["skipped"]["dockle"]
    assert "container_image" in result["skipped"]["dive"]
    assert "dockle" not in spawned_binaries(calls)
    assert "dive" not in spawned_binaries(calls)
    assert result.get("recommendations", []) == []


def test_image_opt_in_runs_dockle_and_dive(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    image = tmp_path / "img.tar"
    image.write_bytes(b"fake-tar")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo), container_image=str(image)))
    assert result["status"] == "ok"
    assert "dockle" not in result.get("skipped", {})
    assert "dive" not in result.get("skipped", {})
    assert "dockle" in spawned_binaries(calls)
    assert "dive" in spawned_binaries(calls)
    # NEVER auto-build: no `dive build`, no push/pull subcommands spawned.
    for argv, _ in calls:
        arglist = [str(a) for a in argv]
        assert "build" not in arglist
        assert "push" not in arglist
        assert "pull" not in arglist
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("dockle-") for r in rule_ids)
    # Dive lands in recommendations[], never in findings.
    assert not any(r.startswith("dive-") for r in rule_ids)
    rec_rules = [r["rule_id"] for r in result["recommendations"]]
    assert "dive-efficiency" in rec_rules
    assert "dive-wasted-space" in rec_rules


def test_image_missing_binaries_skip_with_reason(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    patch_binaries(monkeypatch, dockle=False, dive=False)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo), container_image="myapp:latest"))
    assert "dockle" in result["skipped"]
    assert "dive" in result["skipped"]
    assert "not installed" in result["skipped"]["dockle"].lower()
    assert result.get("recommendations", []) == []


# --- diff + repo routing ---------------------------------------------------


def test_diff_py_only_skips_container_lanes(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(PY_DIFF))
    assert result["status"] == "ok"
    assert {"hadolint", "kics", "dockle", "dive"} <= set(result.get("skipped", {}))
    assert "hadolint" not in spawned_binaries(calls)
    assert "kics" not in spawned_binaries(calls)
    assert not any(
        str(f.get("rule_id", "")).startswith(("hadolint-", "kics-", "dockle-"))
        for f in result["findings"]
    )


def test_diff_js_only_skips_container_lanes(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(JS_DIFF))
    assert result["status"] == "ok"
    assert {"hadolint", "kics", "dockle", "dive"} <= set(result.get("skipped", {}))


def test_diff_dockerfile_runs_hadolint_but_compose_image_skip(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(DOCKERFILE_DIFF))
    assert result["status"] == "ok"
    assert "hadolint" not in result.get("skipped", {})
    assert spawn_count(calls, "hadolint") == 1
    # Compose + image lanes skip in diffs even for container diffs (diffs
    # lack whole-file/project context; images are never built from diffs).
    for lane in ("kics", "dockle", "dive"):
        assert lane in result.get("skipped", {})
    assert "kics" not in spawned_binaries(calls)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("hadolint-") for r in rule_ids)


COMPOSE_DIFF = """\
diff --git a/docker-compose.yml b/docker-compose.yml
index 1111111..2222222 100644
--- a/docker-compose.yml
+++ b/docker-compose.yml
@@ -0,0 +1,2 @@
+services:
+  web:
"""


def test_diff_compose_never_routes_to_hadolint(monkeypatch) -> None:
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(COMPOSE_DIFF))
    assert result["status"] == "ok"
    assert "hadolint" not in spawned_binaries(calls)
    assert "hadolint" in result.get("skipped", {})


def test_diff_dockerfile_missing_hadolint_skips_with_reason(monkeypatch) -> None:
    patch_binaries(monkeypatch, hadolint=False)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_diff(DOCKERFILE_DIFF))
    assert "hadolint" in result["skipped"]
    assert "not installed" in result["skipped"]["hadolint"].lower()
    assert "hadolint" not in spawned_binaries(calls)


def test_repo_py_only_skips_container_lanes(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert {"hadolint", "kics", "dockle", "dive"} <= set(result.get("skipped", {}))
    assert {"hadolint", "kics", "dockle", "dive"} & spawned_binaries(calls) == set()


def test_repo_container_only_runs_hadolint_and_kics(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (repo / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "hadolint" not in result.get("skipped", {})
    assert "kics" not in result.get("skipped", {})
    assert spawn_count(calls, "hadolint") == 1
    assert "kics" in spawned_binaries(calls)
    # Image lanes still opt-in even on container repos.
    assert "dockle" in result.get("skipped", {})
    assert "dive" in result.get("skipped", {})
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert any(r.startswith("hadolint-") for r in rule_ids)
    assert any(r.startswith("kics-") for r in rule_ids)


def test_repo_compose_only_skips_hadolint_runs_kics(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "hadolint" in result.get("skipped", {})
    assert "kics" not in result.get("skipped", {})
    assert "hadolint" not in spawned_binaries(calls)


# --- recommendations contract ----------------------------------------------


def test_recommendations_key_present_and_separate(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    image = tmp_path / "img.tar"
    image.write_bytes(b"fake-tar")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo), container_image=str(image)))
    assert isinstance(result["recommendations"], list)
    assert all(set(r) == {"source", "rule_id", "message", "image"} for r in result["recommendations"])
    finding_ids = {f["rule_id"] for f in result["findings"]}
    rec_ids = {r["rule_id"] for r in result["recommendations"]}
    assert finding_ids.isdisjoint(rec_ids)


def test_recommendations_survive_cache_round_trip(monkeypatch, tmp_path: Path) -> None:
    from bravoguard.cache import FindingCache

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    image = tmp_path / "img.tar"
    image.write_bytes(b"fake-tar")
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(), calls)
    cache = FindingCache(":memory:")
    first = asyncio.run(orchestrator.scan_repo(str(repo), container_image=str(image), cache=cache))
    assert not first.get("cached")
    assert first["recommendations"] != []
    calls.clear()
    second = asyncio.run(
        orchestrator.scan_repo(str(repo), container_image=str(image), cache=cache)
    )
    assert second["cached"] is True
    assert second["recommendations"] == first["recommendations"]
    assert "dive" not in spawned_binaries(calls)


# --- installer -------------------------------------------------------------


def test_installer_covers_container_binaries() -> None:
    import json as _json

    from scripts import install, install_external

    manifest = _json.loads(
        (Path(__file__).parent.parent / "tools-manifest.json").read_text(encoding="utf-8")
    )
    pinned = {b["name"]: b["version"] for b in manifest.get("binaries", [])}
    assert pinned["hadolint"] == "v2.15.1"
    assert pinned["kics"] == "v2.2.0"
    assert pinned["dockle"] == "v0.4.15"
    assert pinned["dive"] == "v0.13.1"
    # hadolint + kics run automatically on container signals -> core;
    # dockle + dive are image-opt-in -> optional (strict-only).
    assert "hadolint" in install.CORE_BINARIES
    assert "kics" in install.CORE_BINARIES
    assert "dockle" in install.OPTIONAL_BINARIES
    assert "dive" in install.OPTIONAL_BINARIES
    assert "hadolint" in install_external.CORE_BINARIES
    assert "kics" in install_external.CORE_BINARIES
    assert "dockle" in install_external.OPTIONAL_BINARIES
    assert "dive" in install_external.OPTIONAL_BINARIES
    # Release-binary legs (verified live asset names for hadolint/dockle/dive;
    # kics v2.2.0 ships no release assets, so its leg is go-install first).
    assert install.release_asset("hadolint", "linux", "v2.15.1") == "hadolint-linux-x86_64"
    assert install.release_asset("dockle", "linux", "v0.4.15").endswith(".tar.gz")
    assert install.release_asset("dive", "windows", "v0.13.1").endswith(".zip")


def test_server_scan_repo_accepts_container_image() -> None:
    import inspect

    from bravoguard import server

    params = inspect.signature(server.scan_repo).parameters
    assert "container_image" in params
    assert params["container_image"].default is None
