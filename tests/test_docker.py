"""Docker proof contract tests: file contents only, no daemon required."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ROOT / "docker"


def read(name: str) -> str:
    return (DOCKER / name).read_text(encoding="utf-8")


def test_dockerfile_base_and_sync() -> None:
    text = read("Dockerfile.linux-test")
    assert "python:3.11-slim-bookworm" in text
    assert "uv sync --frozen" in text


def test_dockerfile_installs_guarddog_without_skip() -> None:
    text = read("Dockerfile.linux-test")
    assert "guarddog" in text
    assert "skip" not in text.lower()
    assert "osv-scanner" in text


def test_proof_script_covers_all_gates() -> None:
    text = read("proof-linux.sh")
    for gate in ("pytest", "ruff", "scripts/install.py --check",
                 "bravoguard doctor", "scan_diff", "osv_lookup", "/tmp/proof.log"):
        assert gate in text, f"missing gate: {gate}"


def test_proof_script_seeded_diff_expects_finding() -> None:
    text = read("proof-linux.sh")
    assert "pickle.loads" in text and ">=1" in text


def test_host_runners_gate_daemon_and_build() -> None:
    for name in ("run-linux-proof.ps1", "run-linux-proof.sh"):
        text = read(name)
        assert "docker info" in text
        assert "exit 2" in text
        assert "docker build -f docker/Dockerfile.linux-test" in text
        assert "bravoguard-linux-test" in text
