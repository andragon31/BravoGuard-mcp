"""T4 SBOM-store + Grype second-opinion tests: store reuse, normalize, CVE dedup, skips.

All subprocesses are mocked; no real syft/grype binary or network is invoked.
Fixtures under ``tests/fixtures/sbom/`` carry recorded-shape payloads: a
CycloneDX SBOM (syft ``-o cyclonedx-json`` shape) and a grype ``-o json``
matches envelope (grype 0.118.0 shape, one entry carrying epss/kev).
"""

import asyncio
import json
import shutil
from pathlib import Path

from bravoguard import orchestrator
from bravoguard.cache import CACHE_ENV_VAR, resolve_sbom_path
from bravoguard.languages import LANE_GATES
from bravoguard.normalizer import (
    FINDING_KEYS,
    dedup_cve_findings,
    make_finding,
    normalize_findings,
    normalize_grype,
    normalize_trivy,
)

SYFT_FIXTURE = Path(__file__).parent / "fixtures" / "sbom" / "syft_cyclonedx.json"
GRYPE_FIXTURE = Path(__file__).parent / "fixtures" / "sbom" / "grype_matches.json"

# Trivy payload overlapping the grype django match on (CVE-2019-14234,
# requirements.txt); trivy carries the fix, grype carries none, so the
# secondary dedup must keep the trivy finding.
TRIVY_OVERLAP = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2019-14234",
                    "PkgName": "django",
                    "InstalledVersion": "2.2",
                    "FixedVersion": "2.2.4",
                    "Severity": "CRITICAL",
                    "Title": "Django: SQL injection possibility in key lookups",
                    "CweIDs": ["CWE-89"],
                }
            ],
        }
    ]
}

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import os
+print(os.environ.get("TOKEN"))
"""


class FakeProcess:
    """Minimal stand-in for asyncio.subprocess.Process."""

    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self, input_data=None):
        return (self._stdout, b"")

    def kill(self) -> None:
        pass

    async def wait(self) -> int:
        return self.returncode


def install_fake(monkeypatch, responses: dict, calls: list) -> None:
    """Patch create_subprocess_exec so each binary returns canned stdout."""

    async def fake_create(*argv: str, **kwargs: object) -> FakeProcess:
        calls.append((list(argv), dict(kwargs)))
        assert "shell" not in kwargs, "scanners must never run with shell=True"
        first = Path(str(argv[0])).name
        names = {Path(str(a)).name for a in argv}
        if first == "uv" and "checkov" in names:
            label = "checkov"
        elif "oxlint" in names:
            label = "oxlint"
        else:
            label = first
        if label not in responses:
            raise FileNotFoundError(label)
        stdout, returncode = responses[label]
        return FakeProcess(stdout, returncode)

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
    }
    responses.update(overrides)
    return responses


def point_cache_at(monkeypatch, tmp_path: Path) -> Path:
    """Redirect the SBOM store (resolve_cache_path-adjacent) into tmp."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv(CACHE_ENV_VAR, str(cache_dir / "cache.db"))
    return cache_dir


def patch_binaries(monkeypatch, *, syft=True, grype=True) -> None:
    """Control shutil.which for the syft/grype presence matrix."""
    real_which = shutil.which

    def fake_which(name: str):
        if name == "syft" and not syft:
            return None
        if name == "grype" and not grype:
            return None
        if name in ("syft", "grype"):
            return f"/usr/bin/{name}"
        return real_which(name)

    monkeypatch.setattr(shutil, "which", fake_which)


def spawned_binaries(calls: list) -> set[str]:
    return {Path(str(argv[0])).name for argv, _ in calls}


def spawn_count(calls: list, binary: str) -> int:
    return sum(1 for argv, _ in calls if Path(str(argv[0])).name == binary)


def syft_stdout() -> bytes:
    return SYFT_FIXTURE.read_bytes()


def grype_stdout() -> bytes:
    return GRYPE_FIXTURE.read_bytes()


def grype_payload() -> dict:
    return json.loads(GRYPE_FIXTURE.read_text(encoding="utf-8"))


# --- argv shape ------------------------------------------------------------


def test_syft_argv_is_cyclonedx_json_over_target() -> None:
    argv = orchestrator.syft_argv("/repo")
    assert argv[0] == "syft"
    assert "/repo" in argv
    assert "-o" in argv
    assert "cyclonedx-json" in argv


def test_grype_argv_matches_stored_sbom_as_json() -> None:
    argv = orchestrator.grype_argv("/store/sbom.cyclonedx.json")
    assert argv[0] == "grype"
    assert "sbom:/store/sbom.cyclonedx.json" in argv
    assert "-o" in argv
    assert "json" in argv


# --- SBOM store ------------------------------------------------------------


def test_sbom_store_path_is_cache_adjacent(tmp_path: Path) -> None:
    store = resolve_sbom_path("abc123", explicit=tmp_path / "cache" / "cache.db")
    assert store.parent.name == "sbom"
    assert store.parent.parent == tmp_path / "cache"
    assert store.name == "abc123.cyclonedx.json"


def test_sbom_store_write_then_fingerprint_hit_reuses(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(syft=(syft_stdout(), 0)), calls)
    first = asyncio.run(orchestrator._run_syft(str(repo), 30))
    second = asyncio.run(orchestrator._run_syft(str(repo), 30))
    assert spawn_count(calls, "syft") == 1
    assert first[1]["sbom_path"] == second[1]["sbom_path"]
    stored = json.loads(Path(first[1]["sbom_path"]).read_text(encoding="utf-8"))
    assert stored["bomFormat"] == "CycloneDX"
    assert {c["name"] for c in stored["components"]} == {"lodash", "django"}


def test_sbom_fingerprint_change_regenerates(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    calls: list = []
    install_fake(monkeypatch, quiet_responses(syft=(syft_stdout(), 0)), calls)
    first = asyncio.run(orchestrator._run_syft(str(repo), 30))
    (repo / "new.py").write_text("y = 2\n", encoding="utf-8")
    second = asyncio.run(orchestrator._run_syft(str(repo), 30))
    assert spawn_count(calls, "syft") == 2
    assert first[1]["sbom_path"] != second[1]["sbom_path"]
    assert Path(first[1]["sbom_path"]).is_file()
    assert Path(second[1]["sbom_path"]).is_file()


def test_syft_lane_emits_no_findings() -> None:
    assert orchestrator.normalize_syft({"sbom_path": "x"}) == []
    assert orchestrator.normalize_syft({}) == []


# --- grype normalize -------------------------------------------------------


def test_normalize_grype_mapping() -> None:
    findings = normalize_grype(grype_payload())
    assert len(findings) == 2
    for finding in findings:
        assert set(finding) == set(FINDING_KEYS)
    lodash, django = findings
    assert lodash["rule_id"] == "grype-CVE-2024-1234"
    assert lodash["path"] == "package-lock.json"
    assert django["rule_id"] == "grype-CVE-2019-14234"
    assert django["path"] == "requirements.txt"


def test_normalize_grype_caps_critical_at_high() -> None:
    (lodash, _) = normalize_grype(grype_payload())
    assert lodash["severity"] == "HIGH"


def test_normalize_grype_fix_hint_names_fixed_version() -> None:
    (lodash, django) = normalize_grype(grype_payload())
    assert "4.17.21" in lodash["fix_hint"]
    assert "lodash" in lodash["fix_hint"]
    assert django["fix_hint"] == ""


def test_normalize_grype_passes_epss_kev_through() -> None:
    (lodash, django) = normalize_grype(grype_payload())
    assert lodash["epss"] == 0.82
    assert lodash["kev"] is True
    assert django["epss"] is None
    assert django["kev"] is False


def test_normalize_grype_tolerates_empty_payload() -> None:
    assert normalize_grype({}) == []
    assert normalize_grype({"matches": []}) == []


# --- CVE secondary dedup ---------------------------------------------------


def test_cve_dedup_prefers_richer_fix_info() -> None:
    rich = make_finding(
        "trivy-CVE-2024-1", "CWE-89", "app.lock", 0, "HIGH", "m", "Upgrade x 1 to 2."
    )
    poor = make_finding("grype-CVE-2024-1", "", "app.lock", 0, "HIGH", "m2", "")
    assert dedup_cve_findings([rich, poor]) == [rich]
    assert dedup_cve_findings([poor, rich]) == [rich]


def test_cve_dedup_first_wins_on_fix_tie() -> None:
    first = make_finding("trivy-CVE-2024-2", "", "a.lock", 0, "HIGH", "m", "")
    second = make_finding("grype-CVE-2024-2", "", "a.lock", 0, "HIGH", "m2", "")
    assert dedup_cve_findings([first, second]) == [first]


def test_cve_dedup_keeps_distinct_cves_and_paths() -> None:
    trivy_misconfig = make_finding("trivy-DS-0001", "", "Dockerfile", 1, "MEDIUM", "m", "")
    grype_other = make_finding("grype-GHSA-abcd-1234", "", "Dockerfile", 0, "HIGH", "m2", "")
    same_cve_other_path = make_finding(
        "grype-CVE-2024-1", "", "other.lock", 0, "HIGH", "m3", ""
    )
    findings = [trivy_misconfig, grype_other, same_cve_other_path]
    assert dedup_cve_findings(findings) == findings


def test_normalize_findings_merges_same_cve_same_path() -> None:
    (trivy_finding,) = normalize_trivy(TRIVY_OVERLAP)
    ( _, django_grype) = normalize_grype(grype_payload())
    merged = normalize_findings([trivy_finding, django_grype])
    cve_hits = [f for f in merged if "CVE-2019-14234" in f["rule_id"]]
    assert len(cve_hits) == 1
    assert cve_hits[0]["rule_id"] == trivy_finding["rule_id"]
    assert "2.2.4" in cve_hits[0]["fix_hint"]


def test_primary_dedup_still_applies_to_grype_repeats() -> None:
    findings = normalize_grype(grype_payload())
    assert len(normalize_findings([findings[0], findings[0]])) == 1


# --- lane registration -----------------------------------------------------


def test_lane_gates_register_syft_and_grype() -> None:
    assert "syft" in LANE_GATES
    assert "grype" in LANE_GATES


def test_empty_detection_skips_syft_and_grype(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "notes.txt").write_text("hello\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(syft=(syft_stdout(), 0), grype=(grype_stdout(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert "syft" in result.get("skipped", {})
    assert "grype" in result.get("skipped", {})
    assert "syft" not in spawned_binaries(calls)
    assert "grype" not in spawned_binaries(calls)


# --- wiring ----------------------------------------------------------------


def test_both_present_runs_grype_after_syft_store(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(syft=(syft_stdout(), 0), grype=(grype_stdout(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert "syft" not in result.get("skipped", {})
    assert "grype" not in result.get("skipped", {})
    assert spawn_count(calls, "syft") == 1
    assert spawn_count(calls, "grype") == 1
    grype_argv = next(argv for argv, _ in calls if Path(str(argv[0])).name == "grype")
    assert any(str(part).startswith("sbom:") for part in grype_argv)
    rule_ids = [f["rule_id"] for f in result["findings"]]
    assert "grype-CVE-2024-1234" in rule_ids


def test_trivy_grype_overlap_dedups_end_to_end(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(
            trivy=(json.dumps(TRIVY_OVERLAP).encode(), 0),
            syft=(syft_stdout(), 0),
            grype=(grype_stdout(), 0),
        ),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    cve_hits = [f for f in result["findings"] if "CVE-2019-14234" in f["rule_id"]]
    assert len(cve_hits) == 1
    assert cve_hits[0]["rule_id"] == "trivy-CVE-2019-14234"
    assert "2.2.4" in cve_hits[0]["fix_hint"]


def test_syft_missing_skips_both_with_reason(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch, syft=False)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(syft=(syft_stdout(), 0), grype=(grype_stdout(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "syft" in result["skipped"]["syft"].lower()
    assert "grype" in result.get("skipped", {})
    assert "syft" not in spawned_binaries(calls)
    assert "grype" not in spawned_binaries(calls)
    assert "syft" not in result.get("errors", {})
    assert "grype" not in result.get("errors", {})


def test_grype_missing_skips_both_with_reason(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch, grype=False)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(syft=(syft_stdout(), 0), grype=(grype_stdout(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert "grype" in result["skipped"]["grype"].lower()
    assert "syft" in result.get("skipped", {})
    assert "syft" not in spawned_binaries(calls)
    assert "grype" not in spawned_binaries(calls)


def test_scan_diff_never_spawns_syft_or_grype(monkeypatch) -> None:
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(syft=(syft_stdout(), 0), grype=(grype_stdout(), 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_diff(SEED_DIFF))
    assert "syft" not in spawned_binaries(calls)
    assert "grype" not in spawned_binaries(calls)
    assert "syft" not in result.get("skipped", {})
    assert "grype" not in result.get("skipped", {})
    assert "syft" not in result.get("errors", {})
    assert "grype" not in result.get("errors", {})
    assert not any(
        str(f.get("rule_id", "")).startswith(("syft-", "grype-"))
        for f in result["findings"]
    )


def test_grype_bad_json_degrades_to_failed(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch)
    calls: list = []
    install_fake(
        monkeypatch,
        quiet_responses(syft=(syft_stdout(), 0), grype=(b"not json", 0)),
        calls,
    )
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert result["errors"]["grype"] == "failed"
    assert "grype" not in result.get("skipped", {})


def test_syft_spawn_race_skips_grype_with_reason(
    monkeypatch, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    point_cache_at(monkeypatch, tmp_path)
    patch_binaries(monkeypatch)
    calls: list = []
    responses = quiet_responses(grype=(grype_stdout(), 0))
    install_fake(monkeypatch, responses, calls)
    result = asyncio.run(orchestrator.scan_repo(str(repo)))
    assert result["status"] == "ok"
    assert result["errors"]["syft"] == "not-installed"
    assert "SBOM" in result["skipped"]["grype"]
    assert "grype" not in spawned_binaries(calls)


def test_manifest_pins_syft_and_grype() -> None:
    manifest = json.loads(
        (Path(__file__).parent.parent / "tools-manifest.json").read_text(encoding="utf-8")
    )
    pins = {b["name"]: b.get("version") for b in manifest.get("binaries", [])}
    assert pins.get("syft") == "1.51.1"
    assert pins.get("grype") == "0.118.0"
