"""Cross-platform installer for BRAVOGuard external scanners (Windows + Linux).

Usage:
  uv run scripts/install.py --check                  # verify only, no changes
  uv run scripts/install.py --install                # dry-run: list actions
  uv run scripts/install.py --install --yes          # execute user-local installs
  uv run scripts/install.py --install --yes --strict # also optional tools

Rules: user-local only (uv tool / pipx / winget / brew / npm -g / go install),
never in the project venv; --yes is required for any mutation; guarddog is
skipped on Windows (known nono-py build failure) unless --force-guarddog.
Every action prints the tool plus its manifest-pinned version. Never silent.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools-manifest.json"
INSTALL_TIMEOUT = 300

PYTHON_TOOLS = ["semgrep", "bandit", "guarddog", "pip-audit", "ruff"]
CORE_BINARIES = ["osv-scanner", "syft", "trivy", "checkov", "betterleaks", "trufflehog", "oxlint"]
OPTIONAL_BINARIES = ["opengrep", "grype", "biome", "eslint", "knip", "madge", "jscpd"]

NPM_PKGS = {
    "oxlint": "oxlint",
    "biome": "@biomejs/biome",
    "eslint": "eslint",
    "knip": "knip",
    "madge": "madge",
    "jscpd": "jscpd",
}
WINGET_IDS = {
    "syft": "Anchore.Syft",
    "trivy": "Aqua.Trivy",
    "grype": "Anchore.Grype",
    "trufflehog": "TruffleSecurity.TruffleHog",
    "osv-scanner": "Google.OSVScanner",
    "checkov": "Bridgecrew.Checkov",
}
GO_MODULES = {
    "opengrep": "github.com/opengrep/opengrep",
    "osv-scanner": "github.com/google/osv-scanner/cmd/osv-scanner",
    "syft": "github.com/anchore/syft",
    "trivy": "github.com/aquasecurity/trivy/cmd/trivy",
    "grype": "github.com/anchore/grype",
    "betterleaks": "github.com/gitleaks/betterleaks",
    "trufflehog": "github.com/trufflesecurity/trufflehog",
}
BREW_NAMES = {
    "opengrep": "opengrep",
    "osv-scanner": "osv-scanner",
    "syft": "syft",
    "trivy": "trivy",
    "grype": "grype",
    "trufflehog": "trufflehog",
}


@dataclass
class Action:
    tool: str
    version: str
    candidates: list[list[str]] = field(default_factory=list)
    manual: str = ""
    skipped: bool = False
    skip_reason: str = ""


def detect_platform(current: str | None = None) -> str:
    name = current if current is not None else sys.platform
    if name.startswith("win"):
        return "windows"
    if name.startswith("darwin"):
        return "macos"
    return "linux"


def load_manifest() -> dict[str, dict]:
    raw = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {b["name"]: b for b in raw["binaries"]}


def should_skip_guarddog(plat: str, force_guarddog: bool) -> bool:
    return plat == "windows" and not force_guarddog


def python_candidates(tool: str) -> list[list[str]]:
    return [["uv", "tool", "install", tool], ["pipx", "install", tool]]


def npm_spec(pkg: str, version: str) -> str:
    if version == "latest":
        return pkg
    if version.endswith("+"):
        return f"{pkg}@{version[:-1]}"
    return f"{pkg}@{version}"


def go_tag(version: str) -> str:
    if version in ("latest", "V2") or version.endswith(("+", ".x")):
        return "latest"
    return version if version.startswith("v") else f"v{version}"


def binary_candidates(name: str, entry: dict, plat: str) -> tuple[list[list[str]], str]:
    version = entry.get("version", "?")
    if name in NPM_PKGS:
        return [[["npm", "i", "-g", npm_spec(NPM_PKGS[name], version)]], ""]
    if name == "osv-scanner":
        if plat == "windows":
            cmds = [["winget", "install", "--id", WINGET_IDS[name], "-e"]]
        else:
            cmds = [["brew", "install", BREW_NAMES[name]]]
        cmds.append(["go", "install", f"{GO_MODULES[name]}@v2"])
        return [cmds, ""]
    if name == "checkov":
        cmds = []
        if plat == "windows":
            cmds.append(["winget", "install", "--id", WINGET_IDS[name], "-e"])
        else:
            cmds.append(["brew", "install", "checkov"])
        cmds += [["pipx", "install", "checkov"], ["uv", "tool", "install", "checkov"]]
        return [cmds, ""]
    cmds = []
    if plat == "windows":
        if name in WINGET_IDS:
            cmds.append(["winget", "install", "--id", WINGET_IDS[name], "-e"])
        if name in ("syft", "trivy", "grype", "trufflehog"):
            cmds.append(["choco", "install", name, "-y"])
            cmds.append(["scoop", "install", name])
    elif name in BREW_NAMES:
        cmds.append(["brew", "install", BREW_NAMES[name]])
    if name in GO_MODULES:
        cmds.append(["go", "install", f"{GO_MODULES[name]}@{go_tag(version)}"])
    manual = ""
    source = entry.get("source", "")
    if source.startswith("github:"):
        manual = f"manual: download {version} from https://github.com/{source[7:]}/releases"
    return [cmds, manual]


def build_plan(plat: str, strict: bool, force_guarddog: bool) -> list[Action]:
    pinned = load_manifest()
    actions: list[Action] = []
    for tool in PYTHON_TOOLS:
        if tool == "guarddog" and should_skip_guarddog(plat, force_guarddog):
            actions.append(Action(tool, "latest", skipped=True,
                                 skip_reason="known nono-py build failure on Windows; use Linux or --force-guarddog"))
            continue
        actions.append(Action(tool, "latest", python_candidates(tool)))
    names = list(CORE_BINARIES) + (list(OPTIONAL_BINARIES) if strict else [])
    for name in names:
        entry = pinned[name]
        candidates, manual = binary_candidates(name, entry, plat)
        actions.append(Action(name, entry.get("version", "?"), candidates, manual))
    return actions


def verifier():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import install_external

    return install_external


def run_check(strict: bool, plat: str, force_guarddog: bool) -> int:
    ext = verifier()
    missing = ext.check_python_tools() + ext.check_binaries(CORE_BINARIES)
    if strict:
        missing += ext.check_binaries(OPTIONAL_BINARIES)
    if should_skip_guarddog(plat, force_guarddog):
        guarded = [m for m in missing if "guarddog" in m]
        missing = [m for m in missing if "guarddog" not in m]
        for g in guarded:
            print(f"WARN (known skip): {g} — nono-py fails to build on Windows; Linux path unaffected.")
    pinned = load_manifest()
    print("Pinned:", ", ".join(f"{k}={v.get('version', '?')}" for k, v in pinned.items()))
    if missing:
        print("BRAVOGuard install incomplete. Missing:")
        for m in missing:
            print(f"  - {m}")
        return 1
    print("BRAVOGuard install OK (installer --check, platform-aware).")
    return 0


def print_plan(actions: list[Action], plat: str) -> None:
    print(f"Plan for {plat} (dry-run, no changes made):")
    for a in actions:
        if a.skipped:
            print(f"  SKIP {a.tool}: {a.skip_reason}")
            continue
        print(f"  {a.tool}=={a.version}:")
        for cmd in a.candidates:
            print(f"    - {' '.join(cmd)}")
        if a.manual:
            print(f"    - {a.manual}")


def execute_plan(actions: list[Action]) -> int:
    failures = 0
    for a in actions:
        if a.skipped:
            print(f"SKIP {a.tool}: {a.skip_reason}")
            continue
        picked = next((c for c in a.candidates if shutil.which(c[0])), a.candidates[0])
        print(f"RUN {a.tool}=={a.version}: {' '.join(picked)}")
        try:
            subprocess.run(picked, check=True, timeout=INSTALL_TIMEOUT)
            print(f"OK {a.tool}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
            print(f"FAIL {a.tool}: {e}")
            if a.manual:
                print(f"  fallback: {a.manual}")
            failures += 1
    return 1 if failures else 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="BRAVOGuard cross-platform installer (user-local only).")
    p.add_argument("--check", action="store_true", help="verify only, no changes")
    p.add_argument("--install", action="store_true", help="plan installs (dry-run unless --yes)")
    p.add_argument("--strict", action="store_true", help="include optional 2nd-opinion tools")
    p.add_argument("--yes", action="store_true", help="required to execute any install")
    p.add_argument("--force-guarddog", action="store_true", help="attempt guarddog even on Windows")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    plat = detect_platform()
    if args.check:
        return run_check(args.strict, plat, args.force_guarddog)
    actions = build_plan(plat, args.strict, args.force_guarddog)
    if not args.yes:
        print_plan(actions, plat)
        print("Dry-run only. Re-run with --yes to execute (user-local installs, never project venv).")
        return 0
    return execute_plan(actions)


if __name__ == "__main__":
    raise SystemExit(main())
