"""Verify all BRAVOGuard tools are installed. Fail fast with actionable output.

Usage:
  uv run scripts/install_external.py        # check only, exit non-zero if missing
  uv run scripts/install_external.py --strict  # also require optional 2nd-opinion tools

Python CLIs (semgrep, bandit, pip-audit, guarddog, ruff) install isolated
(pipx / uv tool) on purpose — semgrep 1.176 pins mcp==1.29 which conflicts
with our mcp>=2.0.0 in one venv. Go/JS binaries are pinned in tools-manifest.json
and must be on PATH (winget/scoop/choco on Windows, brew/apt elsewhere,
or npm i -g / go install per manifest source).
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools-manifest.json"

PYTHON_TOOLS = ["semgrep", "bandit", "pip-audit", "guarddog", "ruff"]
CORE_BINARIES = ["osv-scanner", "syft", "trivy", "checkov", "betterleaks", "trufflehog", "oxlint"]
OPTIONAL_BINARIES = ["opengrep", "grype", "biome", "eslint", "knip", "madge", "jscpd"]


def check_python_tools() -> list[str]:
    # PATH-only on purpose (isolated installs, no same-venv conflict).
    return [f"python:{tool} (pipx install / uv tool install {tool})" for tool in PYTHON_TOOLS if shutil.which(tool) is None]


def check_binaries(names: list[str]) -> list[str]:
    missing: list[str] = []
    for n in names:
        if n == "betterleaks":
            # Secrets edge: gitleaks v8 fallback satisfies betterleaks
            # (mirrors orchestrator.resolve_secrets_binary).
            if shutil.which("betterleaks") is not None or shutil.which("gitleaks") is not None:
                continue
            missing.append("bin:betterleaks (see tools-manifest.json; gitleaks v8 fallback accepted)")
        elif shutil.which(n) is None:
            missing.append(f"bin:{n} (see tools-manifest.json)")
    return missing


def main() -> int:
    strict = "--strict" in sys.argv
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    pinned = {b["name"]: b.get("version", "?") for b in manifest["binaries"]}

    missing = check_python_tools() + check_binaries(CORE_BINARIES)
    if strict:
        missing += check_binaries(OPTIONAL_BINARIES)

    if missing:
        print("BRAVOGuard install incomplete. Missing:")
        for m in missing:
            print(f"  - {m}")
        print("\nFix: pipx/uv-tool for Python CLIs + binaries per tools-manifest.json (scanners stay isolated, never in the project venv).")
        print("Pinned versions:", ", ".join(f"{k}={v}" for k, v in pinned.items()))
        return 1
    print(f"BRAVOGuard install OK ({len(pinned)} tools pinned, verified).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
