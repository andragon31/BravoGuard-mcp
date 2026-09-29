"""Subprocess orchestration for BRAVOGuard scanners (Phase 1, T2).

Runs scanner CLIs as subprocesses with enforced timeouts and no shell:

- SAST: ``semgrep --config rules/ --json`` with ``opengrep`` fallback (same args).
- Python: ``bandit -f json`` over the scan target.
- Secrets: ``betterleaks detect`` (diff via stdin, repo via path) with a
  ``gitleaks`` v8 fallback when betterleaks is missing. The fallback adds
  ``--report-path`` capture (this gitleaks build prints only logs to
  stdout); the tmpfile is read once, deleted, and never logged.
- Frontend: ``oxlint <target> --format json`` (M1).
- Container/IaC: ``trivy fs --format json --scanners vuln,misconfig``
  (M1; the ``secret`` scanner is excluded on purpose — betterleaks owns
  secrets, so enabling it would duplicate findings and double-handle live
  secrets).
- IaC: ``uv tool run --from checkov checkov -d <target> -o json`` (M1; the
  bare ``checkov`` shim is broken on Windows, ``uv tool run`` is proven).

``scan_diff`` stays SAST + bandit + secrets: the diff materializer emits
Python snippets, while oxlint needs JS/TS files, trivy needs manifests /
lockfiles / IaC, and checkov needs IaC files — repo-scale lanes with no
diff signal, so wiring them there adds subprocess cost for zero findings.

Security properties:

- ``asyncio.create_subprocess_exec`` with an argv list; never ``shell=True``.
- Every scanner call is bounded by ``asyncio.wait_for`` (DIFF 60s, DEFAULT 120s).
- ``scan_repo`` targets are validated by :func:`resolve_scan_path`.
- Scanner output is never logged or embedded in errors (it may hold secrets).

Exclude enforcement (``exclude`` param, default :data:`DEFAULT_EXCLUDES`):

- Pattern syntax (single matcher :func:`_is_excluded`): fnmatch against the
  rel-posix path, against ``"/" + rel-posix`` (so a leading ``*/`` also
  matches top-level paths — ``*/.venv/*`` matches ``.venv/x.py``), and
  against the basename. A trailing ``/`` means dir prefix (``frames/``
  matches ``frames/clip.mp4``).
- SAST (semgrep/opengrep): native repeatable ``--exclude=PATTERN`` flags
  (verified against semgrep 1.178 ``scan --help``; opengrep keeps identical
  args). Patterns pass through raw; engine-side glob dialect is gitignore
  style, so exotic shapes are best-effort there.
- Bandit: native ``-x`` comma list (verified in bandit 1.9.4 ``--help``:
  ``-x EXCLUDED_PATHS``, glob patterns supported). Bandit matches against
  absolute paths and ignores trailing-slash dir prefixes, so patterns are
  translated: ``frames/`` -> ``*/frames/*``, bare ``skip.py`` ->
  ``*/skip.py``; wildcards pass through raw.
- Secrets (betterleaks/gitleaks): neither engine has a native path-exclude
  flag (verified in ``gitleaks detect --help``; betterleaks was absent so it
  is treated as gitleaks-compatible per tools-manifest.json). ``scan_diff``
  pre-filters diff chunks by b-side path before stdin; ``scan_repo`` stages
  a filtered mirror (rel layout preserved, findings paths remapped back) and
  skips the lane entirely when the mirror is empty.
- oxlint: native repeatable ``--ignore-pattern=PAT`` flags (verified in
  oxlint 1.65.0 ``--help``; proven live: ``--ignore-pattern bad.js`` drops
  the file to zero diagnostics). Patterns pass through raw; the
  engine-side glob dialect is best-effort, same as semgrep.
- trivy: native ``--skip-dirs`` / ``--skip-files`` (verified in
  ``trivy filesystem --help``). Trailing-slash dir prefixes become
  ``--skip-dirs`` values (slash stripped); everything else becomes
  ``--skip-files``, with bare filenames (no ``/`` or ``*``) prefixed as
  ``**/name`` so they match at any depth. Best-effort: trivy documents
  "directories or glob patterns" without pinning basename semantics.
- checkov: native repeatable ``--skip-path`` (verified in
  ``checkov --help``: "Path (file or directory) to skip, using regular
  expression logic ... Can be specified multiple times"). Exclude globs
  are translated with :func:`fnmatch.translate`, because a raw ``*.wav``
  is an invalid regex; with ``re.search`` semantics the translated
  patterns match dir prefixes and basename globs best-effort.
- An empty post-filter result returns ``ok`` with empty findings; timeouts
  are unchanged; cache keys already include the normalized excludes.

Platform notes (M1, parent-verified env):

- oxlint ships as an ``oxlint.ps1`` shim on Windows, which
  ``create_subprocess_exec`` cannot spawn directly — on win32 the lane runs
  ``cmd /c oxlint ...`` (same pattern as the installer R1 fix). POSIX uses
  the bare ``oxlint`` binary. Flags are identical on both.
- trivy is a real ``.exe`` on Windows: direct argv on both platforms.
- checkov runs ONLY as ``uv tool run --from checkov checkov`` (its
  installed ``.cmd`` shim throws on import even after a clean reinstall).
  The ``uv`` startup overhead is seconds, inside the 120s budget; when
  ``uv`` itself is missing the lane degrades to ``not-installed``.
- trivy downloads its vulnerability DB (~118 MB) plus the checks bundle
  on first run into the trivy cache dir, then reuses them. First-ever
  scans are slow (tens of seconds observed); the lane honors its timeout
  budget and surfaces overruns honestly as ``timeout`` — DB-download
  slowness is data, not failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import hashlib
import json
import shlex
import shutil
import sys
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from bravoguard.cache import FindingCache, make_osv_key, make_scan_key, scanner_fingerprint
from bravoguard.normalizer import (
    FINDING_KEYS,
    normalize_bandit,
    normalize_betterleaks,
    normalize_checkov,
    normalize_findings,
    normalize_oxlint,
    normalize_semgrep,
    normalize_trivy,
)

DIFF_TIMEOUT_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 120

SEMGREP_ENGINE = "semgrep"
OPENGREP_FALLBACK = "opengrep"
BETTERLEAKS_ENGINE = "betterleaks"
GITLEAKS_FALLBACK = "gitleaks"
OXLINT_ENGINE = "oxlint"
TRIVY_ENGINE = "trivy"
CHECKOV_ENGINE = "checkov"

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"

# Default scan exclusions: media/binary dirs and extensions skipped by the
# fingerprint and the diff materializer (real-project scans exclude them so
# media churn never invalidates the cache). `.git` is always excluded.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".venv/",
    "frames/",
    "projects/",
    "*.wav",
    "*.zip",
    "*.mp4",
    "*.mp3",
    "*.avi",
    "*.mov",
    "*.mkv",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.bmp",
    "*.ico",
    "*.pdf",
    "*.bin",
    "*.exe",
    "*.dll",
    "*.so",
)

__all__ = [
    "BETTERLEAKS_ENGINE",
    "CHECKOV_ENGINE",
    "DEFAULT_EXCLUDES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DIFF_TIMEOUT_SECONDS",
    "FINDING_KEYS",
    "GITLEAKS_FALLBACK",
    "OPENGREP_FALLBACK",
    "OXLINT_ENGINE",
    "SEMGREP_ENGINE",
    "TRIVY_ENGINE",
    "materialize_base",
    "normalize_bandit",
    "normalize_betterleaks",
    "normalize_checkov",
    "normalize_findings",
    "normalize_oxlint",
    "normalize_semgrep",
    "normalize_trivy",
    "resolve_secrets_binary",
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


def semgrep_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Primary SAST engine: semgrep with the portable rules/ config as JSON.

    ``exclude`` patterns become repeatable ``--exclude=PATTERN`` flags
    (``None`` adds no flags; callers pass normalized excludes explicitly).
    """
    argv = [SEMGREP_ENGINE, "--config", str(RULES_DIR), "--json", "--quiet"]
    argv.extend(f"--exclude={pattern}" for pattern in dict.fromkeys(exclude or ()))
    argv.append(target)
    return argv


def opengrep_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Drop-in fallback: identical args run on the opengrep engine."""
    argv = [OPENGREP_FALLBACK, "--config", str(RULES_DIR), "--json", "--quiet"]
    argv.extend(f"--exclude={pattern}" for pattern in dict.fromkeys(exclude or ()))
    argv.append(target)
    return argv


def _bandit_exclude_value(patterns: tuple[str, ...]) -> str | None:
    """Translate excludes to bandit's ``-x`` dialect (absolute-path matching).

    Trailing-slash dir prefixes (ignored by bandit) become ``*/dir/*`` and
    bare filenames (never matching absolute paths) become ``*/name``;
    wildcard patterns pass through raw. Deduped, comma-joined, ``None`` when
    empty.
    """
    translated: list[str] = []
    for pattern in patterns:
        if pattern.endswith("/"):
            candidate = f"*/{pattern.strip('/')}/*"
        elif "/" not in pattern and not pattern.startswith("*"):
            candidate = f"*/{pattern}"
        else:
            candidate = pattern
        if candidate not in translated:
            translated.append(candidate)
    return ",".join(translated) if translated else None


def bandit_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Python SAST as a recursive JSON report.

    ``exclude`` becomes a native ``-x`` comma list (``None`` adds no flags;
    callers pass normalized excludes explicitly).
    """
    argv = ["bandit", "-f", "json", "-q", "-r", target]
    value = _bandit_exclude_value(tuple(exclude or ()))
    if value is not None:
        argv += ["-x", value]
    return argv


def resolve_secrets_binary() -> str | None:
    """Secrets-edge engine: betterleaks first, gitleaks fallback, else None.

    Gitleaks v8 accepts the same ``detect`` flags, so either binary serves the
    lane; ``None`` means neither is on PATH.
    """
    if shutil.which(BETTERLEAKS_ENGINE) is not None:
        return BETTERLEAKS_ENGINE
    if shutil.which(GITLEAKS_FALLBACK) is not None:
        return GITLEAKS_FALLBACK
    return None


def betterleaks_stdin_argv(binary: str = BETTERLEAKS_ENGINE) -> list[str]:
    """Secrets edge scan reading a diff from stdin.

    Gitleaks v8-style flags (``detect --no-git --source``), identical for
    both engines; betterleaks is pinned as gitleaks-compatible in
    tools-manifest.json (fallback gitleaks v8.28). Missing binaries raise
    ScannerMissingError, never crash.
    """
    return [binary, "detect", "--no-git", "--source", "-"]


def betterleaks_path_argv(target: str, binary: str = BETTERLEAKS_ENGINE) -> list[str]:
    """Secrets scan of a repo checkout path (same pin, see above)."""
    return [binary, "detect", "--no-git", "--source", target]


def oxlint_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Frontend lint as JSON (``-f/--format`` verified in oxlint 1.65.0 ``--help``).

    ``exclude`` patterns become repeatable ``--ignore-pattern=PAT`` flags
    (``None`` adds no flags). On win32 the lane must run through
    ``cmd /c`` because oxlint ships as a ``.ps1`` shim that
    ``create_subprocess_exec`` cannot spawn directly; POSIX uses the bare
    binary. Flags are identical on both platforms.
    """
    argv = [OXLINT_ENGINE, "--format", "json"]
    argv.extend(f"--ignore-pattern={pattern}" for pattern in dict.fromkeys(exclude or ()))
    argv.append(target)
    if sys.platform == "win32":
        return ["cmd", "/c", *argv]
    return argv


def _trivy_skip_args(patterns: tuple[str, ...]) -> list[str]:
    """Translate excludes to trivy ``--skip-dirs`` / ``--skip-files`` flags.

    Trailing-slash dir prefixes (``frames/``) become ``--skip-dirs frames``;
    everything else becomes ``--skip-files``, with bare filenames (no ``/``
    or ``*``) prefixed as ``**/name`` so they match at any depth. Deduped,
    repeatable flags (one value per flag); empty input adds no flags.
    """
    flags: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        if pattern.endswith("/"):
            flag, value = "--skip-dirs", pattern.strip("/")
        elif "/" not in pattern and "*" not in pattern:
            flag, value = "--skip-files", f"**/{pattern}"
        else:
            flag, value = "--skip-files", pattern
        if value and (flag, value) not in seen:
            seen.add((flag, value))
            flags += [flag, value]
    return flags


def trivy_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Container/IaC scan as JSON over a filesystem target.

    ``--scanners vuln,misconfig`` (verified in ``trivy filesystem --help``;
    allowed values ``vuln,misconfig,secret,license``). The ``secret``
    scanner is deliberately excluded — betterleaks owns secrets. Direct
    argv on both platforms (trivy is a real ``.exe`` on Windows).
    """
    argv = [TRIVY_ENGINE, "fs", "--format", "json", "--scanners", "vuln,misconfig"]
    argv.extend(_trivy_skip_args(tuple(exclude or ())))
    argv.append(target)
    return argv


def _checkov_skip_values(patterns: tuple[str, ...]) -> list[str]:
    """Translate excludes to checkov ``--skip-path`` regex values.

    checkov matches ``--skip-path`` with regex logic, so raw globs like
    ``*.wav`` would be invalid regexes — each pattern goes through
    :func:`fnmatch.translate`. Deduped; empty input yields no values.
    """
    return [regex for regex in dict.fromkeys(fnmatch.translate(p) for p in patterns)]


def checkov_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """IaC scan as JSON via the isolated checkov install.

    ``uv tool run --from checkov checkov`` is the only working invocation
    here (the bare ``.cmd`` shim throws on import); ``-d`` / ``-o json`` /
    ``--quiet`` / ``--compact`` verified in ``checkov --help``. ``exclude``
    becomes repeatable ``--skip-path`` regex flags (``None`` adds none).
    """
    argv = [
        "uv",
        "tool",
        "run",
        "--from",
        "checkov",
        "checkov",
        "-d",
        target,
        "-o",
        "json",
        "--quiet",
        "--compact",
    ]
    for regex in _checkov_skip_values(tuple(exclude or ())):
        argv += ["--skip-path", regex]
    return argv


async def run_scanner_json(
    argv: list[str],
    *,
    input_data: bytes | None,
    timeout: float,
    parse: Callable[[str], Any] | None = None,
) -> dict[str, Any] | list[Any]:
    """Run one scanner and parse its stdout as JSON.

    Never uses a shell; the whole call is bounded by ``timeout``. Non-zero
    exits are normal when findings exist, so stdout is parsed regardless of
    return code. Scanner output is never logged or put into exceptions.
    ``parse`` overrides the JSON decode for lanes with noisy stdout (oxlint
    only); it must raise ``json.JSONDecodeError`` on garbage.
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
        text = stdout.decode("utf-8", errors="replace")
        if parse is not None:
            return parse(text)
        return json.loads(text)
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
    target = target.removeprefix("b/")
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


def materialize_base() -> Path:
    """Repo-local base dir for diff materialization, with system-temp fallback.

    ``<cwd>/.bravoguard/tmp/`` keeps semgrep off the system temp tree, where
    scans hang on Windows (>120s on %TEMP% vs ~0.3s repo-local,
    parent-verified). Falls back to :func:`tempfile.gettempdir` when the
    repo-local dir cannot be created or fails a write probe. Same rule on
    every platform; no platform branches.
    """
    try:
        candidate = Path.cwd() / ".bravoguard" / "tmp"
        candidate.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".probe-", dir=str(candidate), delete=True):
            pass
        return candidate
    except OSError:
        return Path(tempfile.gettempdir())


def materialize_diff_files(
    diff: str, workdir: Path, exclude: list[str] | tuple[str, ...] | None = None
) -> list[Path]:
    """Write added diff lines per +++ header into workdir; return files.

    Header-less added lines fall back to ``snippet.py`` so bare pastes still
    scan. Suffixes come from the diff headers (default ``.py``) so the SAST
    engines pick the right language rules. Files matching ``exclude``
    (default :data:`DEFAULT_EXCLUDES`) are skipped, checking both the
    materialized basename and the full ``diff --git`` b-side path (so
    ``*/.venv/*`` drops ``.venv/evil.py`` even though it materializes as
    ``evil.py``).
    """
    excludes = _normalize_excludes(exclude)
    buffers: dict[str, list[str]] = {}
    b_paths: dict[str, str | None] = {}
    order: list[str] = []
    current: str | None = None
    current_b: str | None = None
    pending: list[str] = []
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current_b = _git_b_path(line)
            continue
        header = _diff_target(line)
        if header is not None:
            current = header
            if current not in buffers:
                buffers[current] = []
                order.append(current)
                b_paths[current] = current_b
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
            b_paths["snippet.py"] = None
        buffers["snippet.py"].extend(pending)
    written = []
    used: set[str] = set()
    for name in order:
        if _is_excluded(name, excludes):
            continue
        b_path = b_paths.get(name)
        if b_path is not None and _is_excluded(b_path, excludes):
            continue
        target = workdir / _unique_filename(name, used)
        target.write_text("\n".join(buffers[name]) + "\n", encoding="utf-8")
        written.append(target)
    return written


async def _scan_sast(
    target: str, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """Run semgrep, falling back to opengrep with identical args."""
    try:
        payload = await run_scanner_json(
            semgrep_argv(target, exclude), input_data=None, timeout=timeout
        )
        return SEMGREP_ENGINE, payload
    except ScannerMissingError:
        payload = await run_scanner_json(
            opengrep_argv(target, exclude), input_data=None, timeout=timeout
        )
        return OPENGREP_FALLBACK, payload


async def _run_bandit(
    target: str, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    payload = await run_scanner_json(
        bandit_argv(target, exclude), input_data=None, timeout=timeout
    )
    return "bandit", payload


def _parse_oxlint_stdout(text: str) -> Any:
    """Parse oxlint stdout, skipping a leading non-JSON preamble line.

    With zero lintable files oxlint exits 1 printing ``No files found...``
    to stdout ahead of the valid envelope; first parse wins, the retry from
    the first ``{`` lets that envelope through. Garbage re-raises, keeping
    the lane ``failed``.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        return json.loads(text[start:] if start >= 0 else text)


async def _run_oxlint(
    target: str, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """Frontend lane: missing oxlint (or cmd) degrades to not-installed.

    Rule: a parseable envelope wins over rc (empty diagnostics -> ok/empty,
    findings normalize as before); unparsable stdout stays ``failed``. Same
    output-driven tolerance may later apply to trivy/checkov (out of scope).
    """
    payload = await run_scanner_json(
        oxlint_argv(target, exclude),
        input_data=None,
        timeout=timeout,
        parse=_parse_oxlint_stdout,
    )
    return "oxlint", payload


async def _run_trivy(
    target: str, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """Container/IaC lane: first-ever runs download the vuln DB (slow);
    overruns surface as timeout via run_scanner_json."""
    payload = await run_scanner_json(
        trivy_argv(target, exclude), input_data=None, timeout=timeout
    )
    return "trivy", payload


async def _run_checkov(
    target: str, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """IaC lane via ``uv tool run``; missing uv degrades to not-installed."""
    payload = await run_scanner_json(
        checkov_argv(target, exclude), input_data=None, timeout=timeout
    )
    return "checkov", payload


def _ignore_scanner_stdout(_text: str) -> dict[str, Any]:
    """Tolerant stdout parse for the gitleaks fallback: stdout carries log
    lines (never findings), so it is discarded — the report file wins."""
    return {}


def _read_secrets_report(report: str, binary: str) -> Any:
    """Read one gitleaks ``--report-path`` file (contents never logged).

    A missing file means the engine ran but produced nothing; unparsable
    JSON mirrors :func:`run_scanner_json` — both stay ``failed``.
    """
    try:
        text = Path(report).read_text(encoding="utf-8")
    except OSError:
        raise OrchestratorError(f"scanner failed: {binary}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        raise OrchestratorError(f"scanner returned invalid JSON: {binary}") from None


async def _run_gitleaks_with_report(
    argv: list[str], *, input_data: bytes | None, timeout: float
) -> Any:
    """Gitleaks fallback leg with ``--report-path`` tmpfile capture.

    The tmpfile is read once then deleted; its contents never reach logs
    or errors (Secret/Match redaction in the normalizer is unchanged).
    """
    binary = argv[0] if argv else GITLEAKS_FALLBACK
    with tempfile.NamedTemporaryFile(
        prefix="bravoguard-secrets-", suffix=".json", delete=False
    ) as tmp:
        report = tmp.name
    with contextlib.suppress(OSError):
        Path(report).unlink()
    try:
        await run_scanner_json(
            [*argv, "--report-path", report],
            input_data=input_data,
            timeout=timeout,
            parse=_ignore_scanner_stdout,
        )
        return _read_secrets_report(report, binary)
    finally:
        with contextlib.suppress(OSError):
            Path(report).unlink()


async def _run_secrets_with_fallback(
    primary: list[str], fallback: list[str], *, input_data: bytes | None, timeout: float
) -> tuple[str, Any]:
    """Try ``primary`` (betterleaks), then the resolved gitleaks ``fallback``.

    Same try-next-candidate shape as semgrep/opengrep. The ``betterleaks``
    result label is kept so normalization is unchanged; a combined missing
    error surfaces only when neither binary runs. The gitleaks leg reads
    findings from a ``--report-path`` tmpfile (stdout is logs only).
    """
    try:
        payload = await run_scanner_json(primary, input_data=input_data, timeout=timeout)
        return "betterleaks", payload
    except ScannerMissingError:
        if resolve_secrets_binary() != GITLEAKS_FALLBACK:
            raise ScannerMissingError(f"{BETTERLEAKS_ENGINE}/{GITLEAKS_FALLBACK}") from None
    try:
        payload = await _run_gitleaks_with_report(fallback, input_data=input_data, timeout=timeout)
    except ScannerMissingError:
        raise ScannerMissingError(f"{BETTERLEAKS_ENGINE}/{GITLEAKS_FALLBACK}") from None
    return "betterleaks", payload


async def _run_betterleaks_stdin(diff_bytes: bytes, timeout: float) -> tuple[str, Any]:
    return await _run_secrets_with_fallback(
        betterleaks_stdin_argv(),
        betterleaks_stdin_argv(GITLEAKS_FALLBACK),
        input_data=diff_bytes,
        timeout=timeout,
    )


async def _run_betterleaks_path(target: str, timeout: float) -> tuple[str, Any]:
    return await _run_secrets_with_fallback(
        betterleaks_path_argv(target),
        betterleaks_path_argv(target, GITLEAKS_FALLBACK),
        input_data=None,
        timeout=timeout,
    )


_NORMALIZERS = {
    "sast": normalize_semgrep,
    "bandit": normalize_bandit,
    "betterleaks": normalize_betterleaks,
    "oxlint": normalize_oxlint,
    "trivy": normalize_trivy,
    "checkov": normalize_checkov,
}


def _error_reason(exc: BaseException) -> str:
    if isinstance(exc, ScannerTimeoutError):
        return "timeout"
    if isinstance(exc, ScannerMissingError):
        return "not-installed"
    return "failed"


def _normalize_excludes(exclude: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    if exclude is None:
        return DEFAULT_EXCLUDES
    return tuple(e for e in exclude if e)


def _is_excluded(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/"):
            prefix = pattern.rstrip("/")
            if rel_posix == prefix or rel_posix.startswith(pattern):
                return True
        elif (
            fnmatch.fnmatch(rel_posix, pattern)
            or fnmatch.fnmatch("/" + rel_posix, pattern)
            or fnmatch.fnmatch(Path(rel_posix).name, pattern)
        ):
            return True
    return False


def _git_b_path(line: str) -> str | None:
    """Return the b-side path of a ``diff --git a/x b/y`` line, else None."""
    try:
        sides = shlex.split(line[len("diff --git ") :])
    except ValueError:
        sides = line.split()
    for side in reversed(sides):
        cleaned = side.strip().strip("\"'")
        if cleaned.startswith("b/"):
            return cleaned[2:]
    return None


def _chunk_b_path(chunk: list[str]) -> str | None:
    """Return the b-side path of a ``diff --git`` chunk, else None (keep)."""
    b_path = _git_b_path(chunk[0])
    if b_path is not None:
        return b_path
    for line in chunk[1:]:
        if line.startswith("+++ ") and "/dev/null" not in line:
            target = line[4:].split("\t", 1)[0].strip().strip("\"'")
            return target.removeprefix("b/")
    return None


def _filter_diff(diff: str, excludes: tuple[str, ...]) -> str:
    """Drop per-file chunks whose b-side path matches ``excludes``.

    Preamble lines and chunks with no parseable path are kept, so unusual
    diffs degrade to the old unfiltered behavior instead of losing content.
    """
    preamble: list[str] = []
    chunks: list[list[str]] = []
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            chunks.append([line])
        elif not chunks:
            preamble.append(line)
        else:
            chunks[-1].append(line)
    kept = list(preamble)
    for chunk in chunks:
        path = _chunk_b_path(chunk)
        if path is not None and _is_excluded(path, excludes):
            continue
        kept.extend(chunk)
    text = "\n".join(kept)
    if diff.endswith("\n") and text and not text.endswith("\n"):
        text += "\n"
    return text


async def _empty_secrets_result() -> tuple[str, Any]:
    """Secrets-lane stand-in when pre-filtering removed every input file."""
    return "betterleaks", []


def _stage_filtered_tree(target: Path, excludes: tuple[str, ...], staging: Path) -> int:
    """Mirror non-excluded files of ``target`` into ``staging`` (rel layout).

    The secrets engines take a directory with no native exclude flag, so
    they scan this mirror instead of the raw checkout; findings paths are
    remapped by :func:`_remap_staged_path`. ``.git`` is always skipped.
    Returns the staged file count (0 means the lane is skipped).
    """
    candidates: list[tuple[str, Path]] = []
    if target.is_file():
        candidates.append((target.name, target))
    else:
        try:
            files = sorted(
                p for p in target.rglob("*") if p.is_file() and ".git" not in p.parts
            )
        except OSError:
            return 0
        for path in files:
            try:
                rel = path.relative_to(target).as_posix()
            except (OSError, ValueError):
                continue
            candidates.append((rel, path))
    staged = 0
    for rel, path in candidates:
        if _is_excluded(rel, excludes):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        dest = staging / rel
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        except OSError:
            continue
        staged += 1
    return staged


def _remap_staged_path(path: str, staging: Path, target: Path) -> str:
    """Map a findings path inside the secrets staging mirror back to ``target``."""
    for prefix in (str(staging), str(staging).replace("\\", "/")):
        if path == prefix:
            return str(target)
        if path.startswith((prefix + "/", prefix + "\\")):
            return str(target / path[len(prefix) + 1 :])
    return path


def _dir_fingerprint(
    target: Path, exclude: list[str] | tuple[str, ...] | None = None
) -> str:
    """Best-effort content digest of a repo dir (relpath + size + mtime)."""
    excludes = _normalize_excludes(exclude)
    digest = hashlib.sha256()
    try:
        files = sorted(
            p
            for p in target.rglob("*")
            if p.is_file() and ".git" not in p.parts
        )
    except OSError:
        return target.name
    for path in files[:5000]:
        try:
            rel = path.relative_to(target).as_posix()
            if _is_excluded(rel, excludes):
                continue
            stat = path.stat()
            digest.update(f"{rel}|{stat.st_size}|{stat.st_mtime_ns}\n".encode())
        except OSError:
            continue
    return digest.hexdigest()


def _lookup_scan_cache(cache: FindingCache | None, key: str) -> dict[str, Any] | None:
    if cache is None:
        return None
    try:
        cached = cache.get(key)
    except Exception:  # noqa: BLE001 — cache is best-effort; a bad entry must never fail a scan
        return None
    if cached is None:
        return None
    if isinstance(cached, dict):  # envelope: findings + errors
        response: dict[str, Any] = {
            "status": "ok",
            "findings": cached.get("findings", []),
            "cached": True,
        }
        if cached.get("errors"):
            response["errors"] = cached["errors"]
        return response
    return {"status": "ok", "findings": cached, "cached": True}  # legacy list payload


def _is_fully_degraded(result: dict[str, Any], total_scanners: int) -> bool:
    """True when every scanner is missing and nothing was found (skip cache)."""
    errors = result.get("errors")
    return (
        not result.get("findings")
        and isinstance(errors, dict)
        and total_scanners > 0
        and len(errors) == total_scanners
        and all(reason == "not-installed" for reason in errors.values())
    )


def _store_scan_cache(
    cache: FindingCache | None,
    key: str,
    findings: Any,
    cache_ttl: float | None,
    errors: dict[str, str] | None = None,
) -> None:
    if cache is None or not isinstance(findings, list):
        return
    with contextlib.suppress(Exception):
        cache.put(key, {"findings": findings, "errors": errors or {}}, ttl_seconds=cache_ttl)


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
    exclude: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Scan added lines of a unified diff with SAST + bandit + secrets.

    Per-scanner ``asyncio.wait_for`` budgets apply (default DIFF 60s); a
    failing scanner is recorded under ``errors`` without failing the scan.
    Cache-first when ``cache`` is given: hits skip the fan-out and return
    ``cached: True`` (with stored ``errors`` when present); misses write
    normalized findings through. Empty diffs are never cached, and neither
    are fully-degraded results (all scanners not-installed). Files matching
    ``exclude`` (default :data:`DEFAULT_EXCLUDES`) are never materialized,
    and the secrets lane reads the exclude-filtered diff (skipped entirely
    when nothing survives the filter). The diff is materialized under
    :func:`materialize_base` (repo-local ``.bravoguard/tmp/`` when writable,
    system temp otherwise); the tree is always removed afterwards, even on
    scanner error or timeout, so finding content never lingers.
    """
    if not diff or not diff.strip():
        return {"status": "empty-diff", "findings": []}
    key = ""
    excludes = _normalize_excludes(exclude)
    if cache is not None:
        key = make_scan_key(
            f"{diff}\x00exclude:{','.join(sorted(excludes))}",
            scanner_versions=scanner_fingerprint(),
        )
        hit = _lookup_scan_cache(cache, key)
        if hit is not None:
            return hit
    budget = timeout if timeout and timeout > 0 else DIFF_TIMEOUT_SECONDS
    workdir = Path(tempfile.mkdtemp(prefix="bravoguard-diff-", dir=str(materialize_base())))
    try:
        materialize_diff_files(diff, workdir, excludes)
        filtered = _filter_diff(diff, excludes)
        secrets_job = (
            _run_betterleaks_stdin(filtered.encode("utf-8"), budget)
            if filtered.strip()
            else _empty_secrets_result()
        )
        jobs = [
            ("sast", _scan_sast(str(workdir), budget, excludes)),
            ("bandit", _run_bandit(str(workdir), budget, excludes)),
            ("betterleaks", secrets_job),
        ]
        result = await _collect(jobs)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if not _is_fully_degraded(result, len(jobs)):
        _store_scan_cache(cache, key, result.get("findings"), cache_ttl, result.get("errors"))
    return result


async def scan_repo(
    path: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    allowed_root: Path | None = None,
    cache: FindingCache | None = None,
    cache_ttl: float | None = None,
    exclude: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Deep-scan a repo checkout: validate the path, fan out, collect.

    Cache-first when ``cache`` is given, keyed on the directory content
    digest (relpath + size + mtime, minus ``exclude``) so edits invalidate
    while media churn does not. Guard statuses (empty/invalid path) and
    fully-degraded results (all scanners not-installed) are never cached.
    Every engine enforces ``exclude`` (default :data:`DEFAULT_EXCLUDES`):
    semgrep/opengrep via native ``--exclude``, bandit via native ``-x``,
    the secrets lane via a filtered staging mirror (findings paths
    remapped back; the lane is skipped when the mirror is empty),
    oxlint via native ``--ignore-pattern``, trivy via native
    ``--skip-dirs``/``--skip-files``, and checkov via native
    ``--skip-path`` regexes. Lanes with no applicable files (no JS for
    oxlint, no manifests/IaC for trivy/checkov) return ``ok`` with empty
    findings, not errors.
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
    excludes = _normalize_excludes(exclude)
    if cache is not None:
        key = make_scan_key(
            f"repo:{target}|{_dir_fingerprint(target, excludes)}"
            f"\x00exclude:{','.join(sorted(excludes))}",
            scanner_versions=scanner_fingerprint(),
        )
        hit = _lookup_scan_cache(cache, key)
        if hit is not None:
            return hit
    with tempfile.TemporaryDirectory(prefix="bravoguard-secrets-") as stage_tmp:
        staging = Path(stage_tmp)
        staged = _stage_filtered_tree(target, excludes, staging)
        secrets_job = (
            _run_betterleaks_path(str(staging), budget)
            if staged
            else _empty_secrets_result()
        )
        jobs = [
            ("sast", _scan_sast(str(target), budget, excludes)),
            ("bandit", _run_bandit(str(target), budget, excludes)),
            ("betterleaks", secrets_job),
            ("oxlint", _run_oxlint(str(target), budget, excludes)),
            ("trivy", _run_trivy(str(target), budget, excludes)),
            ("checkov", _run_checkov(str(target), budget, excludes)),
        ]
        result = await _collect(jobs)
        if staged:
            for finding in result.get("findings", []):
                if isinstance(finding, dict) and finding.get("path"):
                    finding["path"] = _remap_staged_path(
                        str(finding["path"]), staging, target
                    )
    if not _is_fully_degraded(result, len(jobs)):
        _store_scan_cache(cache, key, result.get("findings"), cache_ttl, result.get("errors"))
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
    """Cache-first OSV hook; pass ``fetcher=bravoguard.osv.fetch_osv`` for T4 real scanners.

    On a cache hit returns ``{"status": "ok", "vulns": [...], "cached": True}``
    without invoking ``fetcher``. Without a fetcher a miss returns the
    explicit ``not-implemented`` stub. Empty packages are never cached.
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
        except Exception:  # noqa: BLE001 — cache is best-effort; a bad entry must never fail a lookup
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
