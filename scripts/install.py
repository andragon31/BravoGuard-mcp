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
Go-unfriendly tools (trivy/trufflehog) prefer official release binaries
(stdlib download into ~/.local/bin) with go as fallback; syft/grype use
fixed /cmd go paths with release fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
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
    "osv-scanner": "github.com/google/osv-scanner/v2/cmd/osv-scanner",
    "syft": "github.com/anchore/syft/cmd/syft",
    "trivy": "github.com/aquasecurity/trivy/cmd/trivy",
    "grype": "github.com/anchore/grype/cmd/grype",
    "betterleaks": "github.com/gitleaks/betterleaks",
    "trufflehog": "github.com/trufflesecurity/trufflehog",
}
GITLEAKS_V8_MODULE = "github.com/zricethezav/gitleaks/v8"
BREW_NAMES = {
    "opengrep": "opengrep",
    "osv-scanner": "osv-scanner",
    "syft": "syft",
    "trivy": "trivy",
    "grype": "grype",
    "trufflehog": "trufflehog",
}

RELEASE_MARKER = "release"

RELEASE_REPOS = {
    "trivy": "aquasecurity/trivy",
    "trufflehog": "trufflesecurity/trufflehog",
    "syft": "anchore/syft",
    "grype": "anchore/grype",
}

# {ver} is the plain version without a leading v; the download tag keeps the
# v (releases/download/v0.74.0/...). Verified live against the GitHub release
# metadata for the pinned versions: trivy/Windows is lowercase
# `windows-64bit`, and trufflehog ships .tar.gz on every platform.
RELEASE_ASSETS = {
    "trivy": {
        "linux": "trivy_{ver}_Linux-64bit.tar.gz",
        "windows": "trivy_{ver}_windows-64bit.zip",
        "macos": "trivy_{ver}_macOS-64bit.tar.gz",
    },
    "trufflehog": {
        "linux": "trufflehog_{ver}_linux_amd64.tar.gz",
        "windows": "trufflehog_{ver}_windows_amd64.tar.gz",
        "macos": "trufflehog_{ver}_darwin_amd64.tar.gz",
    },
    "syft": {
        "linux": "syft_{ver}_linux_amd64.tar.gz",
        "windows": "syft_{ver}_windows_amd64.zip",
        "macos": "syft_{ver}_darwin_amd64.tar.gz",
    },
    "grype": {
        "linux": "grype_{ver}_linux_amd64.tar.gz",
        "windows": "grype_{ver}_windows_amd64.zip",
        "macos": "grype_{ver}_darwin_amd64.tar.gz",
    },
}


def strip_v(version: str) -> str:
    return version.removeprefix("v")


def release_tag(version: str) -> str:
    return version if version.startswith("v") else f"v{version}"


def release_asset(tool: str, plat: str, version: str) -> str:
    return RELEASE_ASSETS[tool][plat].format(ver=strip_v(version))


def release_url(repo: str, version: str, asset: str) -> str:
    return f"https://github.com/{repo}/releases/download/{release_tag(version)}/{asset}"


def user_bin_dir() -> Path:
    return Path.home() / ".local" / "bin"


def resolve_trufflehog_version(pinned: str) -> str | None:
    """Resolve a `v3.95.x` pin to the newest exact tag, else None when offline."""
    if not pinned.endswith(".x"):
        return pinned
    stem = pinned[:-2]
    req = urllib.request.Request(
        "https://api.github.com/repos/trufflesecurity/trufflehog/releases",
        headers={"Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=INSTALL_TIMEOUT) as resp:  # nosec: B310
            payload = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError, TypeError, KeyError):
        return None
    if not isinstance(payload, list):
        return None
    for rel in payload:
        tag = rel.get("tag_name", "")
        if tag.startswith(stem):
            return tag
    return None


def _pick_binary_member(names: list[str], tool: str) -> str | None:
    want = tool.lower()
    for name in names:
        if Path(name).name.lower() in (want, f"{want}.exe"):
            return name
    for name in names:
        if Path(name).name.lower().startswith(want):
            return name
    return None


def _write_binary_dest(data: bytes, dest_dir: Path, member: str) -> None:
    name = Path(member).name
    if os.name == "nt" and not name.lower().endswith(".exe"):
        name += ".exe"
    dest = dest_dir / name
    dest.write_bytes(data)
    if os.name != "nt":
        dest.chmod(0o755)


def extract_release_binary(archive: Path, dest_dir: Path, tool: str) -> bool:
    """Unpack the single tool binary from a release archive.

    The chosen member is read into memory and written out directly, so
    hostile member paths (tar-slip) can never escape dest_dir.
    """
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        if archive.name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/") and Path(n).name]
                member = _pick_binary_member(names, tool)
                if member is None:
                    return False
                _write_binary_dest(zf.read(member), dest_dir, member)
        elif archive.name.endswith(".tar.gz"):
            with tarfile.open(archive, "r:gz") as tf:
                members = [m.name for m in tf.getmembers() if m.isfile() and Path(m.name).name]
                member = _pick_binary_member(members, tool)
                if member is None:
                    return False
                stream = tf.extractfile(member)
                if stream is None:
                    return False
                _write_binary_dest(stream.read(), dest_dir, member)
        else:
            return False
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        return False
    return True


def _fetch_asset(url: str, tmp: Path) -> bool:
    req = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=INSTALL_TIMEOUT) as resp, tmp.open("wb") as fh:  # nosec: B310
            shutil.copyfileobj(resp, fh)
    except (OSError, ValueError):
        return False
    return True


def download_release_binary(repo: str, version: str, asset_matrix: dict[str, str], dest_dir: Path | str) -> bool:
    """Download one official release asset for this platform, unpack its binary.

    Stdlib only (urllib/tarfile/zipfile). Never raises: False tells the
    caller to try the next candidate.
    """
    if version.endswith(".x"):
        return False
    asset = asset_matrix.get(detect_platform())
    if asset is None:
        return False
    asset = asset.format(ver=strip_v(version))
    url = release_url(repo, version, asset)
    if not url.startswith("https://github.com/"):
        return False
    dest = Path(dest_dir)
    tmp = dest / asset
    try:
        dest.mkdir(parents=True, exist_ok=True)
        if not _fetch_asset(url, tmp):
            return False
        return extract_release_binary(tmp, dest, repo.rpartition("/")[2])
    except OSError:
        return False
    finally:
        tmp.unlink(missing_ok=True)


def install_release(tool: str, version: str) -> bool:
    """Execute one release-binary candidate. False keeps try-next going."""
    repo = RELEASE_REPOS.get(tool)
    matrix = RELEASE_ASSETS.get(tool)
    if repo is None or matrix is None:
        return False
    if version.endswith(".x"):
        if tool != "trufflehog":
            return False
        resolved = resolve_trufflehog_version(version)
        if resolved is None:
            return False
        version = resolved
    return download_release_binary(repo, version, matrix, user_bin_dir())


def release_candidate(tool: str, version: str, plat: str) -> list[str]:
    return [RELEASE_MARKER, tool, version, plat]


def describe_candidate(candidate: list[str]) -> str:
    if candidate and candidate[0] == RELEASE_MARKER:
        tool, version, plat = candidate[1], candidate[2], candidate[3]
        repo = RELEASE_REPOS.get(tool, "?")
        if version.endswith(".x"):
            return f"release: {tool} {version} (exact patch resolved at install) from https://github.com/{repo}/releases"
        asset = release_asset(tool, plat, version)
        return f"release: {tool} {version} from https://github.com/{repo}/releases/download/{release_tag(version)}/{asset}"
    return " ".join(candidate)


def run_candidate(candidate: list[str]) -> None:
    if candidate and candidate[0] == RELEASE_MARKER:
        if not install_release(candidate[1], candidate[2]):
            raise RuntimeError(f"release install failed: {' '.join(candidate)}")
        return
    subprocess.run(candidate, check=True, timeout=INSTALL_TIMEOUT)


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


def wrap_win_cmd(cmd: list[str], plat: str) -> list[str]:
    if plat == "windows" and cmd and cmd[0] in ("scoop", "npm"):
        return ["cmd", "/c", *cmd]
    return cmd


def candidate_binary(candidate: list[str]) -> str:
    if len(candidate) >= 3 and candidate[0] == "cmd" and candidate[1] == "/c":
        return candidate[2]
    return candidate[0]


def binary_candidates(name: str, entry: dict, plat: str) -> tuple[list[list[str]], str]:
    version = entry.get("version", "?")
    if name in NPM_PKGS:
        return [[wrap_win_cmd(["npm", "i", "-g", npm_spec(NPM_PKGS[name], version)], plat)], ""]
    if name == "osv-scanner":
        if plat == "windows":
            cmds = [["winget", "install", "--id", WINGET_IDS[name], "-e"]]
        else:
            cmds = [["brew", "install", BREW_NAMES[name]]]
        # NOTE: `go install <module>@v2` is an invalid version query
        # (go: no matching versions for query "v2"). The v2 layout requires
        # the /v2 module path with @latest; falls back with NOTE when the
        # local toolchain is too old.
        cmds.append(["go", "install", f"{GO_MODULES[name]}@latest"])
        return [cmds, ""]
    if name == "checkov":
        cmds = []
        if plat == "windows":
            cmds.append(["winget", "install", "--id", WINGET_IDS[name], "-e"])
        else:
            cmds.append(["brew", "install", "checkov"])
        cmds += [["pipx", "install", "checkov"], ["uv", "tool", "install", "checkov"]]
        return [cmds, ""]
    if name == "betterleaks":
        cmds = []
        if plat == "windows":
            if name in WINGET_IDS:
                cmds.append(["winget", "install", "--id", WINGET_IDS[name], "-e"])
        elif name in BREW_NAMES:
            cmds.append(["brew", "install", BREW_NAMES[name]])
        # NOTE: github.com/gitleaks/betterleaks@latest does not exist
        # (repository not found). Keep it first, then fall back to gitleaks
        # v8 (go1.26 satisfies its go1.24 requirement); execute_plan tries
        # candidates in order until one succeeds.
        cmds.append(["go", "install", f"{GO_MODULES[name]}@{go_tag(version)}"])
        cmds.append(["go", "install", f"{GITLEAKS_V8_MODULE}@latest"])
        manual = ""
        source = entry.get("source", "")
        if source.startswith("github:"):
            manual = f"manual: download {version} from https://github.com/{source[7:]}/releases"
        return [cmds, manual]
    cmds = []
    if plat == "windows":
        if name in WINGET_IDS:
            cmds.append(["winget", "install", "--id", WINGET_IDS[name], "-e"])
        if name in ("syft", "trivy", "grype", "trufflehog"):
            cmds.append(["choco", "install", name, "-y"])
            cmds.append(wrap_win_cmd(["scoop", "install", name], plat))
    elif name in BREW_NAMES:
        cmds.append(["brew", "install", BREW_NAMES[name]])
    if name in GO_MODULES:
        cmds.append(["go", "install", f"{GO_MODULES[name]}@{go_tag(version)}"])
    if name in RELEASE_ASSETS:
        release = release_candidate(name, version, plat)
        if name in ("trivy", "trufflehog"):
            # go builds are known-broken (trivy toolchain pins, trufflehog
            # replace directives): try the pinned release binary first.
            cmds.insert(0, release)
        else:
            # syft/grype go builds are proven: the release binary is only a
            # fallback for runners without a working Go toolchain.
            cmds.append(release)
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
            print(f"    - {describe_candidate(cmd)}")
        if a.manual:
            print(f"    - {a.manual}")


def execute_plan(actions: list[Action]) -> int:
    failures = 0
    for a in actions:
        if a.skipped:
            print(f"SKIP {a.tool}: {a.skip_reason}")
            continue
        if not a.candidates:
            print(f"FAIL {a.tool}: no install candidates")
            if a.manual:
                print(f"  fallback: {a.manual}")
            failures += 1
            continue
        available = [c for c in a.candidates if (c and c[0] == RELEASE_MARKER) or shutil.which(candidate_binary(c))]
        if not available:
            print(f"FAIL {a.tool}: no candidate manager found")
            if a.manual:
                print(f"  fallback: {a.manual}")
            failures += 1
            continue
        print(f"RUN {a.tool}=={a.version}: {' '.join(available[0])}")
        last_error: Exception | None = None
        succeeded = False
        for index, candidate in enumerate(available):
            if index > 0:
                print(f"RETRY {a.tool}=={a.version} (attempt {index + 1}): {' '.join(candidate)}")
            try:
                run_candidate(candidate)
                print(f"OK {a.tool}")
                succeeded = True
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, RuntimeError) as e:
                last_error = e
                if index + 1 < len(available):
                    print(f"RETRY {a.tool}=={a.version}: {' '.join(candidate)} failed ({e}); trying next")
                continue
        if not succeeded:
            print(f"FAIL {a.tool}: {last_error}")
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
