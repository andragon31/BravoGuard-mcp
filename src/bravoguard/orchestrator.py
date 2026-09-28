"""Subprocess orchestration for BRAVOGuard scanners (Phase 1, T2).

Runs scanner CLIs as subprocesses with enforced timeouts and no shell:

- SAST: ``semgrep --config rules/ --json`` with ``opengrep`` fallback (same args).
- Python: ``bandit -f json`` over the scan target.
- Secrets: ``betterleaks detect`` (diff via stdin, repo via path).

Security properties:

- ``asyncio.create_subprocess_exec`` with an argv list; never ``shell=True``.
- Every scanner call is bounded by ``asyncio.wait_for`` (DIFF 60s, DEFAULT 120s).
- ``scan_repo`` targets are validated by :func:`resolve_scan_path`.
- Scanner output is never logged or embedded in errors (it may hold secrets).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Awaitable, Callable

from bravoguard.cache import FindingCache, make_osv_key, make_scan_key, scanner_fingerprint

from bravoguard.normalizer import (
    FINDING_KEYS,
    normalize_bandit,
    normalize_betterleaks,
    normalize_findings,
    normalize_semgrep,
)

DIFF_TIMEOUT_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 120

SEMGREP_ENGINE = "semgrep"
OPENGREP_FALLBACK = "opengrep"

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "DIFF_TIMEOUT_SECONDS",
    "FINDING_KEYS",
    "OPENGREP_FALLBACK",
    "SEMGREP_ENGINE",
    "normalize_bandit",
    "normalize_betterleaks",
    "normalize_findings",
    "normalize_semgrep",
]


class OrchestratorError(Exception):
    """Scanner invocation failed (binary name only; never scanner output)."""


class ScanPathError(ValueError):
    """Raised when a scan_repo path fails validation."""


class ScannerMissingError(OrchestratorError):
    """Raised when a scanner binary is not installed."""

    def __init__(self, binary: str) -> None:
        super().__init__(f"scanner not installed: {binary}")
        self.binary = binary


class ScannerTimeoutError(OrchestratorError):
    """Raised when a scanner exceeds its timeout budget."""

    def __init__(self, binary: str) -> None:
        super().__init__(f"scanner timed out: {binary}")
        self.binary = binary


def semgrep_argv(target: str) -> list[str]:
    """Primary SAST engine: semgrep with the portable rules/ config as JSON."""
    return [SEMGREP_ENGINE, "--config", str(RULES_DIR), "--json", "--quiet", target]


def opengrep_argv(target: str) -> list[str]:
    """Drop-in fallback: identical args run on the opengrep engine."""
    return [OPENGREP_FALLBACK, "--config", str(RULES_DIR), "--json", "--quiet", target]


def bandit_argv(target: str) -> list[str]:
    """Python SAST as a recursive JSON report."""
    return ["bandit", "-f", "json", "-q", "-r", target]


def betterleaks_stdin_argv() -> list[str]:
    """Secrets edge scan reading a diff from stdin (Gitleaks v8-style flags)."""
    return ["betterleaks", "detect", "--no-git", "--source", "-"]


def betterleaks_path_argv(target: str) -> list[str]:
    """Secrets scan of a repo checkout path."""
    return ["betterleaks", "detect", "--no-git", "--source", target]


async def run_scanner_json(
    argv: list[str], *, input_data: bytes | None, timeout: float
) -> dict[str, Any] | list[Any]:
    """Run one scanner and parse its stdout as JSON.

    Never uses a shell; the whole call is bounded by ``timeout``. Non-zero
    exits are normal when findings exist, so stdout is parsed regardless of
    return code. Scanner output is never logged or put into exceptions.
    """
    if not argv:
        raise OrchestratorError("empty scanner argv")
    binary = argv[0]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise ScannerMissingError(binary) from None
    except OSError:
        raise OrchestratorError(f"scanner failed to start: {binary}") from None
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(input_data), timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        with contextlib.suppress(ProcessLookupError, OSError, TimeoutError):
            await asyncio.wait_for(proc.wait(), 2)
        raise ScannerTimeoutError(binary) from None
    if not stdout.strip():
        if proc.returncode not in (0, 1, None):
            raise OrchestratorError(f"scanner failed: {binary}")
        return {}
    try:
        return json.loads(stdout.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeError):
        raise OrchestratorError(f"scanner returned invalid JSON: {binary}") from None


def resolve_scan_path(raw_path: str, allowed_root: Path | None = None) -> Path:
    """Validate a scan_repo target and return its resolved path.

    Absolute paths are accepted when they exist (and, when ``allowed_root``
    is given, only inside it). Relative paths resolve against
    ``allowed_root`` (default: repo root) and must stay inside it, so ``..``
    traversal is rejected.
    """
    cleaned = (raw_path or "").strip()
    if not cleaned:
        raise ScanPathError("empty scan path")
    if "\x00" in cleaned:
        raise ScanPathError("invalid scan path")
    candidate = Path(cleaned)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        if allowed_root is not None and not _inside_root(resolved, allowed_root.resolve()):
            raise ScanPathError("scan path escapes allowed root")
    else:
        root = (allowed_root if allowed_root is not None else REPO_ROOT).resolve()
        resolved = (root / candidate).resolve()
        if not _inside_root(resolved, root):
            raise ScanPathError("scan path escapes allowed root")
    if not resolved.exists():
        raise FileNotFoundError(str(resolved))
    return resolved


def _inside_root(resolved: Path, root: Path) -> bool:
    return resolved == root or resolved.is_relative_to(root)


def _diff_target(line: str) -> str | None:
    """Return the materialized filename for a +++ header line, else None."""
    if not line.startswith("+++ "):
        return None
    target = line[4:].split("\t", 1)[0].strip()
    if target in ("", "/dev/null", "dev/null"):
        return None
    if " " in target:  # added line starting with "++ ", not a header
        return None
    if target.startswith("b/"):
        target = target[2:]
    name = Path(target).name
    if not name:
        return None
    return name if Path(name).suffix else f"{name}.py"


def _unique_filename(name: str, used: set[str]) -> str:
    if name not in used:
        used.add(name)
        return name
    stem, suffix = Path(name).stem, Path(name).suffix
    counter = 2
    while f"{stem}_{counter}{suffix}" in used:
        counter += 1
    final = f"{stem}_{counter}{suffix}"
    used.add(final)
    return final


def materialize_diff_files(diff: str, workdir: Path) -> list[Path]:
    """Write added diff lines per +++ header into workdir; return files.

    Header-less added lines fall back to ``snippet.py`` so bare pastes still
    scan. Suffixes come from the diff headers (default ``.py``) so the SAST
    engines pick the right language rules.
    """
    buffers: dict[str, list[str]] = {}
    order: list[str] = []
    current: str | None = None
    pending: list[str] = []
    for line in diff.splitlines():
        header = _diff_target(line)
        if header is not None:
            current = header
            if current not in buffers:
                buffers[current] = []
                order.append(current)
            continue
        if line.startswith("+") and not line.startswith("+++"):
            if current is None:
                pending.append(line[1:])
            else:
                buffers[current].append(line[1:])
    if pending:
        if "snippet.py" not in buffers:
            buffers["snippet.py"] = []
            order.append("snippet.py")
        buffers["snippet.py"].extend(pending)
    written = []
    used: set[str] = set()
    for name in order:
        target = workdir / _unique_filename(name, used)
        target.write_text("\n".join(buffers[name]) + "\n", encoding="utf-8")
        written.append(target)
    return written


async def _scan_sast(target: str, timeout: float) -> tuple[str, Any]:
    """Run semgrep, falling back to opengrep with identical args."""
    try:
        payload = await run_scanner_json(semgrep_argv(target), input_data=None, timeout=timeout)
        return SEMGREP_ENGINE, payload
    except ScannerMissingError:
        payload = await run_scanner_json(opengrep_argv(target), input_data=None, timeout=timeout)
        return OPENGREP_FALLBACK, payload


async def _run_bandit(target: str, timeout: float) -> tuple[str, Any]:
    payload = await run_scanner_json(bandit_argv(target), input_data=None, timeout=timeout)
    return "bandit", payload


async def _run_betterleaks_stdin(diff_bytes: bytes, timeout: float) -> tuple[str, Any]:
    payload = await run_scanner_json(
        betterleaks_stdin_argv(), input_data=diff_bytes, timeout=timeout
    )
    return "betterleaks", payload


async def _run_betterleaks_path(target: str, timeout: float) -> tuple[str, Any]:
    payload = await run_scanner_json(
        betterleaks_path_argv(target), input_data=None, timeout=timeout
    )
    return "betterleaks", payload


_NORMALIZERS = {
    "sast": normalize_semgrep,
    "bandit": normalize_bandit,
    "betterleaks": normalize_betterleaks,
}


def _error_reason(exc: BaseException) -> str:
    if isinstance(exc, ScannerTimeoutError):
        return "timeout"
    if isinstance(exc, ScannerMissingError):
        return "not-installed"
    return "failed"


def _dir_fingerprint(target: Path) -> str:
    """Best-effort content digest of a repo dir (relpath + size + mtime)."""
    digest = hashlib.sha256()
    try:
        files = sorted(
            p for p in target.rglob("*") if p.is_file() and ".git" not in p.parts
        )
    except OSError:
        return target.name
    for path in files[:5000]:
        try:
            stat = path.stat()
            rel = path.relative_to(target).as_posix()
            digest.update(f"{rel}|{stat.st_size}|{stat.st_mtime_ns}\n".encode("utf-8"))
        except OSError:
            continue
    return digest.hexdigest()


def _lookup_scan_cache(cache: FindingCache | None, key: str) -> dict[str, Any] | None:
    if cache is None:
        return None
    try:
        cached = cache.get(key)
    except Exception:
        return None
    if cached is None:
        return None
    return {"status": "ok", "findings": cached, "cached": True}


def _store_scan_cache(
    cache: FindingCache | None, key: str, findings: Any, cache_ttl: float | None
) -> None:
    if cache is None or not isinstance(findings, list):
        return
    with contextlib.suppress(Exception):
        cache.put(key, findings, ttl_seconds=cache_ttl)


async def _collect(jobs: list[tuple[str, Any]]) -> dict[str, Any]:
    labels = [label for label, _ in jobs]
    results = await asyncio.gather(*[coro for _, coro in jobs], return_exceptions=True)
    findings: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for label, result in zip(labels, results):
        if isinstance(result, BaseException):
            errors[label] = _error_reason(result)
            continue
        _, payload = result
        findings.extend(_NORMALIZERS[label](payload))
    response: dict[str, Any] = {"status": "ok", "findings": normalize_findings(findings)}
    if errors:
        response["errors"] = errors
    return response


async def scan_diff(
    diff: str,
    timeout: float = DIFF_TIMEOUT_SECONDS,
    *,
    cache: FindingCache | None = None,
    cache_ttl: float | None = None,
) -> dict[str, Any]:
    """Scan added lines of a unified diff with SAST + bandit + secrets.

    Per-scanner ``asyncio.wait_for`` budgets apply (default DIFF 60s); a
    failing scanner is recorded under ``errors`` without failing the scan.
    Cache-first when ``cache`` is given: hits skip the fan-out and return
    ``cached: True``; misses write normalized findings through. Empty diffs
    are never cached.
    """
    if not diff or not diff.strip():
        return {"status": "empty-diff", "findings": []}
    key = ""
    if cache is not None:
        key = make_scan_key(diff, scanner_versions=scanner_fingerprint())
        hit = _lookup_scan_cache(cache, key)
        if hit is not None:
            return hit
    budget = timeout if timeout and timeout > 0 else DIFF_TIMEOUT_SECONDS
    with tempfile.TemporaryDirectory(prefix="bravoguard-diff-") as tmp:
        workdir = Path(tmp)
        materialize_diff_files(diff, workdir)
        jobs = [
            ("sast", _scan_sast(str(workdir), budget)),
            ("bandit", _run_bandit(str(workdir), budget)),
            ("betterleaks", _run_betterleaks_stdin(diff.encode("utf-8"), budget)),
        ]
        result = await _collect(jobs)
    _store_scan_cache(cache, key, result.get("findings"), cache_ttl)
    return result


async def scan_repo(
    path: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    allowed_root: Path | None = None,
    cache: FindingCache | None = None,
    cache_ttl: float | None = None,
) -> dict[str, Any]:
    """Deep-scan a repo checkout: validate the path, fan out, collect.

    Cache-first when ``cache`` is given, keyed on the directory content
    digest (relpath + size + mtime) so edits invalidate. Guard statuses
    (empty/invalid path) are never cached.
    """
    if not path or not path.strip():
        return {"status": "empty-path", "findings": []}
    budget = timeout if timeout and timeout > 0 else DEFAULT_TIMEOUT_SECONDS
    try:
        target = resolve_scan_path(path, allowed_root)
    except ScanPathError:
        return {"status": "invalid-path", "findings": [], "reason": "outside-allowed-root"}
    except FileNotFoundError:
        return {"status": "invalid-path", "findings": [], "reason": "not-found"}
    key = ""
    if cache is not None:
        key = make_scan_key(
            f"repo:{target}|{_dir_fingerprint(target)}",
            scanner_versions=scanner_fingerprint(),
        )
        hit = _lookup_scan_cache(cache, key)
        if hit is not None:
            return hit
    jobs = [
        ("sast", _scan_sast(str(target), budget)),
        ("bandit", _run_bandit(str(target), budget)),
        ("betterleaks", _run_betterleaks_path(str(target), budget)),
    ]
    result = await _collect(jobs)
    _store_scan_cache(cache, key, result.get("findings"), cache_ttl)
    return result


async def osv_lookup(
    package: str,
    version: str,
    *,
    cache: FindingCache | None = None,
    db_updated_at: str = "",
    db_built: str = "",
    cache_ttl: float | None = None,
    fetcher: Callable[[str, str], Awaitable[list[dict[str, Any]]]] | None = None,
) -> dict[str, Any]:
    """Cache-first OSV hook; the real osv-scanner/pip-audit call lands in T4.

    On a cache hit returns ``{"status": "ok", "vulns": [...], "cached": True}``
    without invoking ``fetcher``. Without a fetcher (T4 not done) a miss
    returns the explicit ``not-implemented`` stub. Empty packages are never
    cached.
    """
    if not (package or "").strip():
        return {"status": "empty-package", "vulns": []}
    key = ""
    if cache is not None:
        key = make_osv_key(
            package.strip(),
            (version or "").strip(),
            scanner_versions=scanner_fingerprint(),
            db_updated_at=db_updated_at,
            db_built=db_built,
        )
        try:
            cached = cache.get(key)
        except Exception:
            cached = None
        if cached is not None:
            return {"status": "ok", "vulns": cached, "cached": True}
    if fetcher is None:
        return {"status": "not-implemented", "task": f"osv_lookup:{package}@{version}"}
    vulns = await fetcher(package, version)
    if cache is not None and isinstance(vulns, list):
        with contextlib.suppress(Exception):
            cache.put(key, vulns, ttl_seconds=cache_ttl)
    return {"status": "ok", "vulns": vulns}
