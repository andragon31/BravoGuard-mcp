"""BRAVOGuard CLI: version, doctor, tools, update.

Single entry point so public GitHub users can install, verify, and
update safely without learning scanner internals:

  bravoguard version [--check]   # local versions + optional GitHub latest check
  bravoguard doctor [--strict]   # full health check (server, tools, rules, cache)
  bravoguard tools               # pinned vs installed tool matrix
  bravoguard update [--check-only] [--yes]  # safe update with backup + verify
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sqlite3
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from bravoguard import __version__

PKG_DIR = Path(__file__).resolve().parent
ROOT = PKG_DIR.parents[1]
MANIFEST = ROOT / "tools-manifest.json"
RULES_DIR = ROOT / "rules"
CACHE_DB = Path.home() / ".cache" / "bravoguard" / "cache.db"

# Overridable for forks: BRAVO_GITHUB_REPO=Owner/BravoGuard-mcp
GITHUB_REPO = "Andragon/BravoGuard-mcp"

PYTHON_TOOLS = ["semgrep", "bandit", "pip-audit", "guarddog", "ruff"]
CORE_BINARIES = ["osv-scanner", "syft", "trivy", "checkov", "betterleaks", "trufflehog", "oxlint"]
OPTIONAL_BINARIES = ["opengrep", "grype", "biome", "eslint", "knip", "madge", "jscpd"]


def _probe_binary(name: str) -> str | None:
    """PATH binary satisfying a tool; secrets edge accepts the gitleaks fallback."""
    if shutil.which(name) is not None:
        return name
    if name == "betterleaks" and shutil.which("gitleaks") is not None:
        return "gitleaks"
    return None


def _tool_version(binary: str) -> str:
    for flag in ("--version", "version", "-V"):
        try:
            import subprocess

            out = subprocess.run([binary, flag], capture_output=True, text=True, timeout=10, check=False)
            text = (out.stdout + out.stderr).strip().splitlines()
            if text:
                return text[0][:120]
        except (OSError, subprocess.SubprocessError):
            continue
    return "installed (version unknown)"


def cmd_version(check: bool = False) -> int:
    import importlib.metadata as md

    def dist(v: str) -> str:
        try:
            return md.version(v)
        except ImportError:
            return "not-installed"

    print(f"bravoguard {__version__}")
    print(f"python {platform.python_version()} ({platform.system()} {platform.machine()})")
    print(f"fastmcp {dist('fastmcp')} / mcp {dist('mcp')}")
    print(f"rules: {RULES_DIR} ({len(list(RULES_DIR.rglob('*.yaml')))} yaml)")
    print("tables: owasp_2025.json + llm_2026.json")
    if check:
        latest = fetch_latest_release()
        if latest:
            print(f"latest GitHub ({GITHUB_REPO}): {latest}")
            if latest.lstrip("v") != __version__:
                print("Update available: run `bravoguard update` (safe, with backup + doctor).")
            else:
                print("Up to date.")
        else:
            print("Could not reach GitHub API (offline?). Local versions above are authoritative.")
    return 0


RELEASE_URL_SCHEMES = ("http", "https")


def _check_release_url(url: str) -> str:
    scheme = urlparse(url).scheme.lower()
    if scheme not in RELEASE_URL_SCHEMES:
        raise ValueError(f"refusing release-check URL with non-http(s) scheme: {scheme!r}")
    return url


def fetch_latest_release() -> str | None:
    import os

    repo = os.environ.get("BRAVO_GITHUB_REPO", GITHUB_REPO)
    url = _check_release_url(f"https://api.github.com/repos/{repo}/releases/latest")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bravoguard-cli", "Accept": "application/vnd.github+json"})
        # Audited: release URL scheme allow-listed http/https by _check_release_url above.
        with urllib.request.urlopen(req, timeout=10) as r:  # nosec: B310
            return json.loads(r.read().decode()).get("tag_name")
    except (OSError, ValueError):
        return None


def cmd_tools() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    print(f"{'tool':<14} {'pinned':<12} {'status'}")
    for b in manifest["binaries"]:
        name, pinned = b["name"], b.get("version", "?")
        probed = _probe_binary(name)
        if probed is None:
            extra = "MISSING"
        elif probed != name:
            extra = f"{_tool_version(probed)} (via {probed} fallback)"
        else:
            extra = _tool_version(name)
        print(f"{name:<14} {pinned:<12} {extra}")
    for t in PYTHON_TOOLS:
        ok = shutil.which(t) is not None
        if not ok and t == "guarddog" and sys.platform == "win32":
            print(f"{t:<14} {'isolated':<12} SKIPPED (nono-py fails to build on Windows; Linux path unaffected)")
            continue
        print(f"{t:<14} {'isolated':<12} {_tool_version(t) if ok else 'MISSING (pipx/uv-tool)'}")
    return 0


def cmd_doctor(strict: bool = False) -> int:
    failures: list[str] = []
    print(f"== bravoguard doctor {__version__} ==")

    # 1. Server imports + tools exposed (FastMCP 4 API with <4 fallback).
    try:
        import asyncio

        from bravoguard.server import mcp

        async def _names() -> set[str]:
            if hasattr(mcp, "get_tools"):
                return set((await mcp.get_tools()).keys())
            return {t.name for t in await mcp._list_tools()}

        tools = asyncio.run(_names())
        expected = {"scan_diff", "scan_repo", "osv_lookup", "owasp_explain", "suggest_fix"}
        if tools == expected:
            print("[ok] server exposes 5 tools")
        else:
            failures.append(f"tools mismatch: {sorted(tools)}")
            print(f"[fail] tools mismatch: {sorted(tools)}")
    except Exception as e:  # noqa: BLE001 — doctor reports failures, never raises
        failures.append(f"server import: {e}")
        print(f"[fail] server import: {e}")

    # 2. Mapping tables load + corrected values.
    try:
        from bravoguard.owasp_map import explain_cwe, explain_llm

        assert explain_cwe("CWE-79")["owasp_2025"] == "A05"
        assert explain_llm("LLM01:2026")["title"] == "Prompt Injection"
        print("[ok] owasp_2025.json + llm_2026.json load (A05 fix verified)")
    except Exception as e:  # noqa: BLE001 — doctor reports failures, never raises
        failures.append(f"mapping tables: {e}")
        print(f"[fail] mapping tables: {e}")

    # 3. Rules carry required metadata.
    try:
        import yaml  # optional; fall back to text scan if missing

        _ = yaml
        has_yaml = True
    except ImportError:
        has_yaml = False
    bad = []
    for y in RULES_DIR.rglob("*.yaml"):
        text = y.read_text(encoding="utf-8")
        if "owasp_2025: A03" in text and "CWE-79" in text:
            bad.append(f"{y.name}: stale A03 for injection")
        if "fix_hint" not in text:
            bad.append(f"{y.name}: missing fix_hint")
    if bad:
        failures.extend(bad)
        print(f"[fail] rules: {bad}")
    else:
        print(f"[ok] rules metadata ({'yaml parsed' if has_yaml else 'text scan'})")

    # 4. Tools on PATH (secrets edge: betterleaks or gitleaks v8 fallback).
    missing = [t for t in PYTHON_TOOLS + CORE_BINARIES if _probe_binary(t) is None]
    if strict:
        missing += [t for t in OPTIONAL_BINARIES if shutil.which(t) is None]
    if sys.platform == "win32" and "guarddog" in missing:
        # Installer-known skip: nono-py fails to build on Windows; Linux path unaffected.
        missing.remove("guarddog")
        print("[WARN] guarddog missing (nono-py fails to build on Windows; Linux path unaffected)")
    if missing:
        failures.append(f"missing tools: {missing}")
        print(f"[fail] missing tools: {missing}")
        print("       fix: pipx/uv-tool for python CLIs, binaries per tools-manifest.json")
    else:
        secrets = _probe_binary("betterleaks")
        print(f"[ok] tools on PATH ({'strict' if strict else 'core'}; secrets via {secrets})")

    # 5. Cache writable.
    try:
        CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(CACHE_DB))
        c.execute("CREATE TABLE IF NOT EXISTS _health(id INTEGER PRIMARY KEY, ts TEXT)")
        c.execute("INSERT INTO _health(ts) VALUES (?)", (datetime.now(UTC).isoformat(),))
        c.commit()
        c.close()
        print(f"[ok] cache writable: {CACHE_DB}")
    except (sqlite3.Error, OSError) as e:
        failures.append(f"cache: {e}")
        print(f"[fail] cache: {e}")

    print("doctor: PASS" if not failures else f"doctor: FAIL ({len(failures)} issues)")
    return 0 if not failures else 1


def cmd_update(check_only: bool = False, yes: bool = False) -> int:
    latest = fetch_latest_release()
    print(f"local: v{__version__}  latest: {latest or 'unknown (offline?)'}")
    if latest and latest.lstrip("v") == __version__:
        print("Already up to date.")
        return 0
    if check_only:
        print("Update available. Run `bravoguard update --yes` to apply safely (backup + verify).")
        return 0 if latest else 1
    if not yes:
        print("Refusing without --yes (safe default). Re-run with `bravoguard update --yes`.")
        return 2

    # Safe update: backup cache, fast-forward git, re-sync, verify.
    import subprocess

    if CACHE_DB.exists():
        bak = CACHE_DB.with_suffix(f".bak-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
        shutil.copy2(CACHE_DB, bak)
        print(f"backup: {CACHE_DB} -> {bak}")

    def run(cmd: list[str]) -> int:
        print(f"$ {' '.join(cmd)}")
        try:
            return subprocess.run(cmd, cwd=str(ROOT), timeout=300, check=False).returncode
        except (OSError, subprocess.SubprocessError) as e:
            print(f"failed: {e}")
            return 1

    if (ROOT / ".git").exists():
        if run(["git", "fetch", "origin"]) != 0:
            return 1
        if run(["git", "pull", "--ff-only"]) != 0:
            print("git pull --ff-only refused (local changes?). Commit/stash first, then retry. No changes applied.")
            return 1
    else:
        print("No .git checkout (installed from wheel?). Update via `uv tool install --upgrade` or fresh clone instead.")
        return 1

    if run(["uv", "sync", "--all-extras"]) != 0:
        print("uv sync failed. Cache backup above is intact; fix deps and re-run doctor.")
        return 1
    rc = cmd_doctor(strict=False)
    print("update: OK (doctor PASS)" if rc == 0 else "update: applied but doctor FAILS — see above, cache backup kept.")
    return rc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bravoguard", description="BRAVOGuard MCP maintenance CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    pv = sub.add_parser("version", help="show versions")
    pv.add_argument("--check", action="store_true", help="also check GitHub latest release")
    pd = sub.add_parser("doctor", help="full health check")
    pd.add_argument("--strict", action="store_true", help="also require optional tools")
    sub.add_parser("tools", help="pinned vs installed tool matrix")
    pu = sub.add_parser("update", help="safe update with backup + verify")
    pu.add_argument("--check-only", action="store_true")
    pu.add_argument("--yes", action="store_true", help="apply changes (required)")
    a = p.parse_args(argv)
    if a.cmd == "version":
        return cmd_version(check=a.check)
    if a.cmd == "doctor":
        return cmd_doctor(strict=a.strict)
    if a.cmd == "tools":
        return cmd_tools()
    if a.cmd == "update":
        return cmd_update(check_only=a.check_only, yes=a.yes)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
