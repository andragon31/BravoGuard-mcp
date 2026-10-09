"""Subprocess orchestration for BRAVOGuard scanners (Phase 1, T2).

Runs scanner CLIs as subprocesses with enforced timeouts and no shell:

- SAST: ``semgrep`` with per-language rule dirs (python: ``--config rules/python``
  + ``--config rules/supply-chain``; javascript: ``--config rules/frontend``) as JSON,
  with ``opengrep`` fallback (same args). Groups with no files are never invoked.
- Python: ``bandit -f json`` over the scan target.
- Secrets: ``betterleaks detect`` over a materialized dir (``scan_diff``
  scans its workdir, ``scan_repo`` a filtered mirror) with a ``gitleaks``
  v8 fallback when betterleaks is missing. The fallback adds
  ``--report-path`` capture (this gitleaks build prints only logs to
  stdout); the tmpfile is read once, deleted, and never logged.
- Secrets verify (opt-in, ``scan_repo`` only): ``trufflehog filesystem --json
  --results=verified`` over the raw target; ``scan_diff`` stays offline/fast.
- Frontend: ``oxlint --config .oxlintrc.json <target> --format json`` (M1 + T2
  suspicious category via repo-root config; explicit ``--config`` because default
  discovery is CWD-relative and misses arbitrary targets).
- Container/IaC/license: ``trivy fs --format json --scanners vuln,misconfig,license``
  (M1 + T2 license; the ``secret`` scanner stays excluded on purpose — betterleaks owns
  secrets, so enabling it would duplicate findings and double-handle live
  secrets).
- SBOM store (T4): ``syft <target> -o cyclonedx-json`` written once under
  the cache dir (``sbom/<dir-fingerprint>.cyclonedx.json``) and reused
  while the fingerprint is unchanged (generate-once/rescan-many).
- Supply vulns second opinion (T4): ``grype sbom:<store> -o json`` over the
  stored SBOM (local-DB matching, no network calls, so no opt-in flag —
  unlike the trufflehog verify lane).
- Supply heuristics (T5): ``guarddog pypi scan`` over requirements manifests
  plus ``guarddog npm scan`` over package.json manifests as JSON (manifest-
  gated per side; win32 skipped per the cli.py nono-py precedent; complements
  the own typosquat lane on the heuristics axis). ``scan_diff`` stays
  untouched (diffs lack dependency context).
- Python depth (T6): ``ruff check --output-format json`` without S rules
  (bandit owns security) plus ``vulture --min-confidence 60`` dead-code
  text lines, both over explicit python files (suffix-gated, diff + repo);
  ``deptry --json-output`` over the project root (manifest-gated on
  requirements manifests / pyproject with dependencies; repo only — diffs
  lack dependency context, same rationale as supply/guarddog).
- JS depth (T7): ``oxlint`` over materialized .js/.ts files in ``scan_diff``
  (same per-language groups T1 built; suffix-gated; missing-binary pre-check;
  repo path unchanged) plus ``eslint --config eslint.config.mjs --format json``
  over explicit js files (suffix-gated, diff + repo; core security rules only —
  plugin/Hooks/Next/a11y cut, documented in the config); ``knip --reporter json
  --directory`` over the project root (manifest-gated on package.json; repo only);
  ``lockfile-lint --path/--type/--allowed-hosts/--validate-https`` per lockfile
  (manifest-gated on lockfiles; repo only; pnpm detected but unsupported);
  ``npm audit --json --prefix`` over the project root (manifest-gated on
  package.json; repo only; no new binary — npm ships with node).
- IaC: ``uv tool run --from checkov checkov -d <target> -o json`` (M1; the
  bare ``checkov`` shim is broken on Windows, ``uv tool run`` is proven).

``scan_diff`` stays SAST + bandit + secrets: the diff materializer emits
Python snippets, while oxlint needs JS/TS files, trivy needs manifests /
lockfiles / IaC, and checkov needs IaC files — repo-scale lanes with no
diff signal, so wiring them there adds subprocess cost for zero findings.
Syft/grype stay out for the same reason (an SBOM needs a tree; diffs lack
context — same rationale as supply).

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
  style, so exotic shapes are best-effort there. ``scan_repo`` additionally
  passes explicit pre-filtered file lists (``SAST_FILE_EXTENSIONS``,
  ``_is_excluded``-filtered, chunked at ``SAST_FILES_PER_SCAN`` sharing the
  lane budget) so semgrep-core never enumerates hostile trees; ``scan_diff``
  already passes explicit materialized files.
- Bandit: native ``-x`` comma list (verified in bandit 1.9.4 ``--help``:
  ``-x EXCLUDED_PATHS``, glob patterns supported). Bandit matches against
  absolute paths and ignores trailing-slash dir prefixes, so patterns are
  translated: ``frames/`` -> ``*/frames/*``, bare ``skip.py`` ->
  ``*/skip.py``; wildcards pass through raw.
- Secrets (betterleaks/gitleaks): neither engine has a native path-exclude
  flag (verified in ``gitleaks detect --help``; betterleaks was absent so it
  is treated as gitleaks-compatible per tools-manifest.json). ``scan_diff``
  relies on materialization-time filtering (excluded files are never
  written, so the workdir is already clean); ``scan_repo`` stages
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
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from bravoguard.cache import (
    FindingCache,
    make_osv_key,
    make_scan_key,
    resolve_sbom_path,
    scanner_fingerprint,
)
from bravoguard.languages import JS_SUFFIXES, PYTHON_SUFFIXES, detect_languages, lanes_for
from bravoguard.normalizer import (
    FINDING_KEYS,
    normalize_bandit,
    normalize_betterleaks,
    normalize_checkov,
    normalize_deptry,
    normalize_eslint,
    normalize_findings,
    normalize_grype,
    normalize_guarddog,
    normalize_knip,
    normalize_lockfile_lint,
    normalize_npm_audit,
    normalize_oxlint,
    normalize_ruff,
    normalize_semgrep,
    normalize_supply,
    normalize_syft,
    normalize_trivy,
    normalize_trufflehog,
    normalize_vulture,
    parse_vulture_output,
)
from bravoguard.supply import scan_supply

DIFF_TIMEOUT_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 120

SEMGREP_ENGINE = "semgrep"
OPENGREP_FALLBACK = "opengrep"
BETTERLEAKS_ENGINE = "betterleaks"
GITLEAKS_FALLBACK = "gitleaks"
OXLINT_ENGINE = "oxlint"
TRIVY_ENGINE = "trivy"
CHECKOV_ENGINE = "checkov"
TRUFFLEHOG_ENGINE = "trufflehog"
RUFF_ENGINE = "ruff"
VULTURE_ENGINE = "vulture"
DEPTRY_ENGINE = "deptry"
SYFT_ENGINE = "syft"
GRYPE_ENGINE = "grype"
GUARDDOG_ENGINE = "guarddog"
ESLINT_ENGINE = "eslint"
KNIP_ENGINE = "knip"
LOCKFILE_LINT_ENGINE = "lockfile-lint"
NPM_ENGINE = "npm"

# T4 skip reasons for the SBOM + second-opinion lanes (surfaced as skipped+reason).
SYFT_MISSING_REASON = "syft not installed: SBOM store skipped"
GRYPE_MISSING_REASON = "grype not installed: SBOM matcher skipped"
GRYPE_NO_SBOM_REASON = "syft SBOM unavailable: no SBOM to match"
SYFT_IDLE_REASON = "grype not installed: SBOM store unused without matcher"

# Opt-in reason for the trufflehog verify lane (surfaced as skipped+reason).
TRUFFLEHOG_OPT_IN_REASON = "trufflehog verify is opt-in: pass verify_secrets=True"

# Ruff lint select (T6): style/correctness/import/naming/modernization only.
# S (flake8-bandit) is excluded on purpose — bandit owns the security signal
# (S is flake8-bandit per ``ruff linter``; verified overlap), so selecting it
# would double-report bandit findings under a second rule id. Ruff prefix
# selection is linter-aware (verified live on ruff 0.16.5: ``--select F``
# enables Pyflakes only, not FAST/FBT/FIX — same for B/BLE, A/ASYNC, I/ICN,
# E/EM/ERA), so these prefixes cannot smuggle S rules in. None of these
# linters needs extra config (no preview flag, no banned-API lists).
RUFF_SELECT_PREFIXES: tuple[str, ...] = ("E", "F", "W", "I", "N", "UP", "B", "A", "C4", "SIM")
RUFF_LINE_LENGTH = 100

# Vulture confidence floor (T6): 60 == vulture's own default (verified live:
# bare ``vulture mod.py`` and ``--min-confidence 60`` emit identical
# output), so the explicit flag documents the threshold without changing
# engine behavior.
VULTURE_MIN_CONFIDENCE = 60

# T6 skip reasons for the Python depth lanes (surfaced as skipped+reason).
RUFF_MISSING_REASON = "ruff not installed: python lint lane skipped"
VULTURE_MISSING_REASON = "vulture not installed: dead-code lane skipped"
DEPTRY_MISSING_REASON = "deptry not installed: dependency-hygiene lane skipped"
DEPTRY_NO_MANIFEST_REASON = (
    "deptry manifest-gated: no requirements manifests or pyproject dependencies"
)
DEPTRY_DIFF_REASON = (
    "deptry needs a project root with manifests: scan_diff lacks dependency context"
)

# T5 skip reasons for the guarddog heuristics lane (surfaced as skipped+reason).
GUARDDOG_WIN32_REASON = (
    "guarddog skipped on Windows: nono-py fails to build "
    "(cli.py precedent; Linux path unaffected)"
)
GUARDDOG_MISSING_REASON = "guarddog not installed: heuristics lane skipped"

# T7 skip reasons for the JS depth lanes (surfaced as skipped+reason).
OXLINT_MISSING_REASON = "oxlint not installed: frontend lint lane skipped"
ESLINT_MISSING_REASON = "eslint not installed: specialist lint lane skipped"
KNIP_MISSING_REASON = "knip not installed: dead-code lane skipped"
KNIP_NO_MANIFEST_REASON = "knip manifest-gated: no package.json with dependencies"
LOCKFILE_LINT_MISSING_REASON = "lockfile-lint not installed: lockfile-policy lane skipped"
LOCKFILE_LINT_NO_LOCKFILE_REASON = (
    "lockfile-lint manifest-gated: no package-lock.json/yarn.lock/pnpm-lock.yaml"
)
LOCKFILE_LINT_PNPM_REASON = (
    "lockfile-lint skipped for pnpm-lock.yaml: only npm/yarn lockfiles supported"
)
NPM_AUDIT_MISSING_REASON = "npm not installed: audit lane skipped"
NPM_AUDIT_NO_MANIFEST_REASON = "npm audit manifest-gated: no package.json"
JS_MANIFEST_DIFF_REASON = (
    "needs a project root with manifests: scan_diff lacks dependency context"
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"
OXLINT_CONFIG = REPO_ROOT / ".oxlintrc.json"
ESLINT_CONFIG = REPO_ROOT / "eslint.config.mjs"

# SAST candidate extensions (scan_repo file-list lane): rules/python targets
# python (.py/.pyi), rules/frontend targets javascript+typescript
# (.js/.jsx/.ts/.tsx/.mjs/.cjs). Semgrep detects language from the suffix,
# so only these suffixes are enumerated.
SAST_FILE_EXTENSIONS: tuple[str, ...] = (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
# Windows command-line limits bound explicit file-list argv; chunks share the
# SAST lane budget evenly (per-chunk = budget / chunk count).
SAST_FILES_PER_SCAN = 100
# Upper bound on files examined by the guarddog manifest discovery walk
# (same order as the fingerprint cap; manifest files are few in practice).
GUARDDOG_MAX_WALK_FILES = 5000

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
    "GRYPE_ENGINE",
    "GUARDDOG_ENGINE",
    "OPENGREP_FALLBACK",
    "OXLINT_ENGINE",
    "SEMGREP_ENGINE",
    "SYFT_ENGINE",
    "TRIVY_ENGINE",
    "TRUFFLEHOG_ENGINE",
    "materialize_base",
    "normalize_bandit",
    "normalize_betterleaks",
    "normalize_checkov",
    "normalize_deptry",
    "normalize_findings",
    "normalize_grype",
    "normalize_guarddog",
    "normalize_oxlint",
    "normalize_ruff",
    "normalize_supply",
    "normalize_syft",
    "normalize_trivy",
    "normalize_trufflehog",
    "normalize_vulture",
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


class _SastPartialTimeout(ScannerTimeoutError):
    """Chunk timeout carrying findings-so-far (scan_repo SAST file-list lane).

    A chunk timeout aborts the remaining chunks; the merged payload collected
    before the timeout rides along so ``_collect`` keeps those findings while
    still recording an honest ``timeout`` error (friendlier than dropping
    completed-chunk findings).
    """

    def __init__(self, binary: str, payload: Any, engine: str) -> None:
        super().__init__(binary)
        self.partial_payload = payload
        self.engine = engine


def semgrep_argv(
    target: str | Path | list[str | Path] | tuple[str | Path, ...],
    exclude: list[str] | tuple[str, ...] | None = None,
    config_dirs: list[str | Path] | tuple[str | Path, ...] | None = None,
) -> list[str]:
    """Primary SAST engine: semgrep with portable rule dirs as JSON.

    ``exclude`` patterns become repeatable ``--exclude=PATTERN`` flags
    (``None`` adds no flags; callers pass normalized excludes explicitly).
    ``config_dirs`` is one or more ``--config`` dirs (``--config`` is
    repeatable; default is the joint ``rules/`` pack). T2 split: python
    groups pass ``rules/python`` + ``rules/supply-chain``, javascript
    groups pass ``rules/frontend`` (see :func:`_sast_rule_dirs`).
    ``target`` is one dir/file or an explicit file list (scan_diff passes
    materialized files so gitignored trees are not skipped).
    """
    configs = tuple(config_dirs) if config_dirs is not None else (RULES_DIR,)
    argv = [SEMGREP_ENGINE]
    for config in configs:
        argv += ["--config", str(config)]
    argv += ["--json", "--quiet"]
    argv.extend(f"--exclude={pattern}" for pattern in dict.fromkeys(exclude or ()))
    if isinstance(target, (list, tuple)):
        argv.extend(str(item) for item in target)
    else:
        argv.append(str(target))
    return argv


def opengrep_argv(
    target: str | Path | list[str | Path] | tuple[str | Path, ...],
    exclude: list[str] | tuple[str, ...] | None = None,
    config_dirs: list[str | Path] | tuple[str | Path, ...] | None = None,
) -> list[str]:
    """Drop-in fallback: identical args run on the opengrep engine."""
    configs = tuple(config_dirs) if config_dirs is not None else (RULES_DIR,)
    argv = [OPENGREP_FALLBACK]
    for config in configs:
        argv += ["--config", str(config)]
    argv += ["--json", "--quiet"]
    argv.extend(f"--exclude={pattern}" for pattern in dict.fromkeys(exclude or ()))
    if isinstance(target, (list, tuple)):
        argv.extend(str(item) for item in target)
    else:
        argv.append(str(target))
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


def betterleaks_path_argv(target: str, binary: str = BETTERLEAKS_ENGINE) -> list[str]:
    """Secrets scan of a repo checkout path (same pin, see above)."""
    return [binary, "detect", "--no-git", "--source", target]


def oxlint_argv(target: str, exclude: list[str] | tuple[str, ...] | None = None) -> list[str]:
    """Frontend lint as JSON (``-f/--format`` verified in oxlint 1.65.0 ``--help``).

    ``exclude`` patterns become repeatable ``--ignore-pattern=PAT`` flags
    (``None`` adds no flags). ``--config`` points at the repo-root
    ``.oxlintrc.json`` explicitly: the default discovery (``./.oxlintrc.json``
    per ``oxlint --help``) is CWD-relative, so scans of arbitrary targets
    would silently miss the suspicious category without it (verified live
    with oxlint 1.65.0: CWD config does not apply to targets elsewhere,
    explicit ``-c`` raises the rule count 95 -> 122 and surfaces
    ``eslint(no-new)``). On win32 the lane must run through
    ``cmd /c`` because oxlint ships as a ``.ps1`` shim that
    ``create_subprocess_exec`` cannot spawn directly; POSIX uses the bare
    binary. Flags are identical on both platforms.
    """
    argv = [OXLINT_ENGINE, "--config", str(OXLINT_CONFIG), "--format", "json"]
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
    """Container/IaC/license scan as JSON over a filesystem target.

    ``--scanners vuln,misconfig,license`` (verified in ``trivy filesystem --help``;
    allowed values ``vuln,misconfig,secret,license``). The ``secret``
    scanner stays excluded — betterleaks owns secrets, so enabling it
    would duplicate findings and double-handle live secrets. Direct
    argv on both platforms (trivy is a real ``.exe`` on Windows).
    """
    argv = [TRIVY_ENGINE, "fs", "--format", "json", "--scanners", "vuln,misconfig,license"]
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


def _kill_tree(proc: Any) -> None:
    """Best-effort whole-tree kill for a timed-out scanner process."""
    pid = getattr(proc, "pid", None)
    if pid is None:
        return
    if os.name == "nt":
        with contextlib.suppress(Exception):
            subprocess.run(
                ["taskkill.exe", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    else:
        with contextlib.suppress(Exception):
            os.killpg(pid, signal.SIGKILL)


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
            start_new_session=True,
        )
    except FileNotFoundError:
        raise ScannerMissingError(binary) from None
    except OSError:
        raise OrchestratorError(f"scanner failed to start: {binary}") from None
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(input_data), timeout)
    except TimeoutError:
        _kill_tree(proc)
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


def _sast_targets_by_language(files: list[Path]) -> dict[str, list[Path]]:
    """Partition SAST files by suffix group for lane routing.

    T2 split (implemented): per-language groups carry dedicated rule dirs
    via :func:`_sast_rule_dirs` — ``"python"`` scans with ``rules/python``
    + ``rules/supply-chain``, ``"javascript"`` with ``rules/frontend``;
    ``"other"`` files keep riding the joint ``rules/`` call. Groups with
    no files are never invoked (see :func:`_scan_sast_by_language`).
    """
    grouped: dict[str, list[Path]] = {"python": [], "javascript": [], "other": []}
    for path in files:
        suffix = path.suffix.lower()
        if suffix in PYTHON_SUFFIXES:
            grouped["python"].append(path)
        elif suffix in JS_SUFFIXES:
            grouped["javascript"].append(path)
        else:
            grouped["other"].append(path)
    return grouped


async def _scan_sast(
    target: str | Path | list[str | Path] | tuple[str | Path, ...],
    timeout: float,
    exclude: tuple[str, ...] = (),
    config_dirs: list[str | Path] | tuple[str | Path, ...] | None = None,
) -> tuple[str, Any]:
    """Run semgrep, falling back to opengrep with identical args."""
    if isinstance(target, (list, tuple)) and not target:
        return SEMGREP_ENGINE, {"results": []}
    try:
        payload = await run_scanner_json(
            semgrep_argv(target, exclude, config_dirs), input_data=None, timeout=timeout
        )
        return SEMGREP_ENGINE, payload
    except ScannerMissingError:
        payload = await run_scanner_json(
            opengrep_argv(target, exclude, config_dirs), input_data=None, timeout=timeout
        )
        return OPENGREP_FALLBACK, payload


def _sast_rule_dirs(group: str) -> tuple[Path, ...]:
    """Rule dirs for one :func:`_sast_targets_by_language` group (single branch point).

    ``"python"`` scans with ``rules/python`` + ``rules/supply-chain``
    (``--config`` is repeatable), ``"javascript"`` with ``rules/frontend``,
    anything else (``"other"``) with the joint ``rules/`` pack. Both
    ``scan_diff`` and ``scan_repo`` route through here via
    :func:`_scan_sast_by_language`, so group-to-config branching exists once.
    """
    if group == "python":
        return (RULES_DIR / "python", RULES_DIR / "supply-chain")
    if group == "javascript":
        return (RULES_DIR / "frontend",)
    return (RULES_DIR,)


async def _scan_sast_by_language(
    files: list[str | Path] | tuple[str | Path, ...],
    timeout: float,
    exclude: tuple[str, ...] = (),
) -> tuple[str, Any]:
    """Scan SAST files with per-language rule dirs, chunked and merged.

    Partition via :func:`_sast_targets_by_language`; each non-empty group
    scans with its :func:`_sast_rule_dirs` configs (a group with no files
    is never invoked). Large groups chunk at :data:`SAST_FILES_PER_SCAN`
    sharing the lane budget evenly across all chunks; payloads merge via
    :func:`_merge_sast_payloads`. A chunk timeout raises
    :class:`_SastPartialTimeout` carrying findings-so-far, same as the
    pre-split repo lane. Shared by ``scan_diff`` and ``scan_repo`` so the
    split branching lives in exactly one place.
    """
    grouped = _sast_targets_by_language([Path(item) for item in files])
    jobs: list[tuple[str, list[Path]]] = []
    for group in ("python", "javascript", "other"):
        group_files = grouped[group]
        if not group_files:
            continue
        for i in range(0, len(group_files), SAST_FILES_PER_SCAN):
            jobs.append((group, group_files[i : i + SAST_FILES_PER_SCAN]))
    if not jobs:
        return SEMGREP_ENGINE, {"results": []}
    per_chunk = timeout / len(jobs)
    payloads: list[Any] = []
    engine = SEMGREP_ENGINE
    for group, chunk in jobs:
        try:
            engine, payload = await _scan_sast(
                chunk, per_chunk, exclude, _sast_rule_dirs(group)
            )
        except ScannerTimeoutError as exc:
            raise _SastPartialTimeout(
                exc.binary, _merge_sast_payloads(payloads), engine
            ) from None
        payloads.append(payload)
    return engine, _merge_sast_payloads(payloads)


def _enumerate_sast_files(target: Path, excludes: tuple[str, ...]) -> list[Path]:
    """List SAST candidate files under ``target`` (scan_repo lane only).

    Only :data:`SAST_FILE_EXTENSIONS` suffixes are collected; :func:`_is_excluded`
    stays the single matcher (its rel-posix + basename forms cover both). Entries
    failing ``is_file() and not is_symlink()`` are skipped — that drops sockets,
    fifos, and symlinks (never followed, so symlink loops cannot hang
    enumeration; no symlinks proven in the hostile trees, and the check is one
    cheap stat). ``.git`` is never descended. A single-file ``target`` with a
    matching suffix is accepted as-is (already resolved by ``resolve_scan_path``).
    """
    if target.is_file():
        if target.suffix.lower() in SAST_FILE_EXTENSIONS and not _is_excluded(
            target.name, excludes
        ):
            return [target]
        return []
    try:
        entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
    except OSError:
        return []
    candidates = []
    for path in entries:
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix.lower() not in SAST_FILE_EXTENSIONS:
            continue
        try:
            rel = path.relative_to(target).as_posix()
        except (OSError, ValueError):
            continue
        if _is_excluded(rel, excludes):
            continue
        candidates.append(path)
    return candidates


def _merge_sast_payloads(payloads: list[Any]) -> dict[str, Any]:
    """Concatenate chunk ``results``/``errors`` into one semgrep-shaped payload."""
    results: list[Any] = []
    errors: list[Any] = []
    for payload in payloads:
        if isinstance(payload, dict):
            items = payload.get("results", [])
            if isinstance(items, list):
                results.extend(items)
            errs = payload.get("errors", [])
            if isinstance(errs, list):
                errors.extend(errs)
        elif isinstance(payload, list):
            results.extend(payload)
    merged: dict[str, Any] = {"results": results}
    if errors:
        merged["errors"] = errors
    return merged


async def _scan_sast_repo_files(
    target: Path, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """scan_repo SAST lane over explicit pre-filtered file lists, chunked.

    semgrep-core fails enumerating hostile trees (exit -1 "Failed to obtain
    target files"); explicit files bypass enumeration, same class as the L3
    scan_diff fix. ``--exclude`` flags stay on every argv (defense in depth)
    and the opengrep fallback is per-chunk identical. Empty candidate list
    returns ok/empty without spawning. Per-language rule dirs apply via
    :func:`_scan_sast_by_language` (shared with ``scan_diff``). Cache keys
    are unchanged: the key already digests target content (relpath+size+mtime)
    plus normalized excludes, and the candidate SET is a pure function of
    those two, so file lists and chunking need no key change.
    """
    files = _enumerate_sast_files(target, exclude)
    if not files:
        return SEMGREP_ENGINE, {"results": []}
    return await _scan_sast_by_language(files, timeout, exclude)


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


def syft_argv(target: str) -> list[str]:
    """SBOM inventory of a directory target as CycloneDX JSON on stdout.

    Documented-source flags: syft 1.51.1 is absent in this env, so re-verify
    read-only via ``syft --help`` when present before changing them —
    ``syft <dir> -o cyclonedx-json`` per anchore/syft docs. Stdout is
    captured and written to the store by :func:`_run_syft` (no ``-o file=``
    form, so the spawn stays inside :func:`run_scanner_json`).
    """
    return [SYFT_ENGINE, target, "-o", "cyclonedx-json"]


def grype_argv(sbom_path: str) -> list[str]:
    """Second-opinion match of a stored SBOM as JSON on stdout.

    Documented-source flags: grype 0.118.0 is absent in this env, so
    re-verify read-only via ``grype --help`` when present before changing
    them — ``grype sbom:<path> -o json`` per anchore/grype docs. Matching
    is local-DB (no network verification calls, unlike trufflehog), so the
    lane needs no opt-in flag.
    """
    return [GRYPE_ENGINE, f"sbom:{sbom_path}", "-o", "json"]


def sbom_store_path(target: str | Path) -> Path:
    """Store file for a scan target: ``<cache-dir>/sbom/<fingerprint>.cyclonedx.json``.

    Keyed on :func:`_dir_fingerprint` with default excludes (the SBOM is a
    content inventory; per-scan excludes shape findings, not the store).
    :func:`_run_syft` and the ``scan_repo`` grype phase both route through
    here, so the write path and the match path can never diverge.
    """
    return resolve_sbom_path(_dir_fingerprint(Path(target)))


async def _run_syft(target: str, timeout: float) -> tuple[str, Any]:
    """SBOM store lane: generate-once/rescan-many keyed on the dir fingerprint.

    Fingerprint hit (store file exists) reuses it with no spawn; miss runs
    syft once and writes its CycloneDX stdout to the store. The lane emits
    no findings itself (:func:`normalize_syft` is ``[]``) — the SBOM feeds
    :func:`_run_grype`. Missing binary / timeout / bad JSON propagate to
    the caller (``scan_repo`` pre-checks both binaries and reports
    skipped+reason instead; a spawn race still degrades honestly via
    ``_collect`` errors). ``scan_diff`` never calls this (SBOM needs a
    tree; diffs lack context).
    """
    store = sbom_store_path(target)
    if store.is_file():
        return "syft", {"sbom_path": str(store)}
    payload = await run_scanner_json(
        syft_argv(target), input_data=None, timeout=timeout
    )
    with contextlib.suppress(OSError):
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps(payload), encoding="utf-8")
    return "syft", {"sbom_path": str(store)}


async def _run_grype(sbom_path: str, timeout: float) -> tuple[str, Any]:
    """Second-opinion matcher over a stored SBOM (local DB, no network)."""
    payload = await run_scanner_json(
        grype_argv(sbom_path), input_data=None, timeout=timeout
    )
    return "grype", payload


def guarddog_pypi_argv(manifest: str) -> list[str]:
    """Heuristics scan of one requirements manifest as JSON.

    Documented-source flags: guarddog is absent in this env, so the
    ``guarddog pypi scan <requirements> --output-format json`` shape follows
    the DataDog GuardDog docs — re-verify read-only via
    ``guarddog pypi scan --help`` when the binary is present before changing
    them (live re-verification owed). The pypi side scans requirements
    manifests only: pyproject-only projects contribute no scan target yet
    (same owed verification), never a guessed argv.
    """
    return [GUARDDOG_ENGINE, "pypi", "scan", manifest, "--output-format", "json"]


def guarddog_npm_argv(manifest: str) -> list[str]:
    """Heuristics scan of one package.json manifest as JSON.

    Documented-source flags (same provenance + owed re-verification as
    :func:`guarddog_pypi_argv`): ``guarddog npm scan <package.json>
    --output-format json`` per the DataDog GuardDog docs.
    """
    return [GUARDDOG_ENGINE, "npm", "scan", manifest, "--output-format", "json"]


def _guarddog_manifests(target: Path) -> list[tuple[str, Path]]:
    """Scan targets for the guarddog lane: ``(ecosystem, manifest)`` pairs.

    The pypi side runs only with requirements manifests, the npm side only
    with package.json (manifest-gated per side; a side with no manifests
    contributes nothing and spawns nothing). Bounded walk, no symlinks,
    never inside ``.git``; sorted for deterministic argv order. A single
    requirements/package.json file target scans as its own side.
    """
    if target.is_file():
        names = [(target.name, target)]
    else:
        try:
            entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
        except OSError:
            return []
        names = [
            (p.name, p)
            for p in entries[:GUARDDOG_MAX_WALK_FILES]
            if p.is_file() and not p.is_symlink()
        ]
    manifests: list[tuple[str, Path]] = []
    for name, path in names:
        if name.startswith("requirements") and name.endswith(".txt"):
            manifests.append(("pypi", path))
        elif name == "package.json":
            manifests.append(("npm", path))
    return manifests


async def _run_guarddog(target: str, timeout: float) -> tuple[str, Any]:
    """Heuristics lane: one guarddog scan per manifest, sharing the budget.

    Each manifest spawns once (pypi side via :func:`guarddog_pypi_argv`,
    npm side via :func:`guarddog_npm_argv`); scans merge into one envelope
    for :func:`bravoguard.normalizer.normalize_guarddog`. No manifests
    returns ok/empty with no spawn (the scan_repo gate normally skips first;
    this is the defense-in-depth floor). ``scan_diff`` never calls this
    (diffs lack dependency context — same rationale as supply).
    """
    manifests = _guarddog_manifests(Path(target))
    if not manifests:
        return "guarddog", {"results": []}
    per_manifest = timeout / len(manifests)
    scans = []
    for ecosystem, path in manifests:
        argv = (
            guarddog_pypi_argv(str(path))
            if ecosystem == "pypi"
            else guarddog_npm_argv(str(path))
        )
        payload = await run_scanner_json(argv, input_data=None, timeout=per_manifest)
        scans.append({"manifest": str(path), "ecosystem": ecosystem, "scan": payload})
    return "guarddog", {"results": scans}


def ruff_argv(
    files: list[str | Path] | tuple[str | Path, ...],
) -> list[str]:
    """Python lint as JSON over explicit files (no S rules — see ``RUFF_SELECT_PREFIXES``).

    ``--output-format json`` and ``--line-length`` verified in ``ruff check
    --help`` (ruff 0.16.5); ``--no-cache`` never writes ``.ruff_cache`` into
    scanned trees; ``--line-length 100`` is the repo convention
    (``pyproject [tool.ruff]``). Explicit file argv means excludes are
    enforced by enumeration (same as the SAST lane) — no ``--exclude`` flag
    needed. Callers skip empty file lists (no spawn).
    """
    return [
        RUFF_ENGINE,
        "check",
        "--output-format",
        "json",
        "--no-cache",
        "--line-length",
        str(RUFF_LINE_LENGTH),
        "--select",
        ",".join(RUFF_SELECT_PREFIXES),
        *(str(item) for item in files),
    ]


def vulture_argv(
    files: list[str | Path] | tuple[str | Path, ...],
) -> list[str]:
    """Dead-code scan over explicit files as ``path:line: message (NN%)`` text.

    Vulture 2.16 has no JSON output (verified live via ``vulture --help``),
    so :func:`bravoguard.normalizer.parse_vulture_output` parses stdout.
    ``--min-confidence`` verified in the same help; the value is
    :data:`VULTURE_MIN_CONFIDENCE`. Explicit file argv enforces excludes
    by enumeration (same as ruff/SAST). Callers skip empty lists (no spawn).
    """
    return [
        VULTURE_ENGINE,
        *(str(item) for item in files),
        "--min-confidence",
        str(VULTURE_MIN_CONFIDENCE),
    ]


def _deptry_exclude_values(patterns: tuple[str, ...]) -> list[str]:
    """Translate excludes to deptry ``--extend-exclude`` regex values.

    Same :func:`fnmatch.translate` approach as :func:`_checkov_skip_values`
    (deptry matches with ``re.match``). Extend-only on purpose:
    ``--exclude`` OVERWRITES deptry defaults (``venv, .venv, tests, .git``
    per ``deptry --help``), while ``--extend-exclude`` adds on top of them.
    """
    return [regex for regex in dict.fromkeys(fnmatch.translate(p) for p in patterns)]


def deptry_argv(
    target: str, report: str, exclude: list[str] | tuple[str, ...] | None = None
) -> list[str]:
    """Dependency-hygiene scan of a project root, JSON summary to ``report``.

    Flags verified live via ``deptry --help`` (deptry 0.25.1, isolated
    ``uvx`` run): the ROOT positional is the project root, ``--no-ansi``
    keeps stdout plain text, ``--json-output FILE`` writes the issue list
    (stdout carries a text summary only, so the caller reads the report
    file and ignores stdout — same tmpfile shape as the gitleaks leg).
    """
    argv = [DEPTRY_ENGINE, target, "--no-ansi", "--json-output", report]
    for regex in _deptry_exclude_values(tuple(exclude or ())):
        argv += ["--extend-exclude", regex]
    return argv


def _has_pyproject_dependencies(path: Path) -> bool:
    """True when ``pyproject.toml`` declares a ``[project].dependencies`` key."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return False
    project = data.get("project")
    return isinstance(project, dict) and "dependencies" in project


def _deptry_manifests(target: Path) -> list[Path]:
    """Deptry scan manifests: ``requirements*.txt`` + pyproject-with-dependencies.

    Manifest-gated per spec: requirements manifests always count; a
    ``pyproject.toml`` counts only with a ``[project].dependencies`` key (a
    bare name/version declares nothing to check). ``setup.py``/``setup.cfg``
    alone never qualify (spec scope). Bounded walk, no symlinks, never
    inside ``.git``; sorted for deterministic order. A single manifest file
    target counts for its own kind.
    """
    if target.is_file():
        if target.name.startswith("requirements") and target.name.endswith(".txt"):
            return [target]
        if target.name == "pyproject.toml" and _has_pyproject_dependencies(target):
            return [target]
        return []
    try:
        entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
    except OSError:
        return []
    manifests = []
    for path in entries[:GUARDDOG_MAX_WALK_FILES]:
        if not path.is_file() or path.is_symlink():
            continue
        is_requirements = path.name.startswith("requirements") and path.name.endswith(".txt")
        is_deps_pyproject = (
            path.name == "pyproject.toml" and _has_pyproject_dependencies(path)
        )
        if is_requirements or is_deps_pyproject:
            manifests.append(path)
    return manifests


def _python_files(target: Path, excludes: tuple[str, ...]) -> list[Path]:
    """Python sources under ``target`` for the ruff/vulture lanes.

    Reuses :func:`_enumerate_sast_files` (bounded, no symlinks, never
    ``.git``, excludes honored) filtered to :data:`PYTHON_SUFFIXES`, so the
    T6 lanes share the SAST enumeration discipline with zero new walk code.
    """
    return [
        path
        for path in _enumerate_sast_files(target, excludes)
        if path.suffix.lower() in PYTHON_SUFFIXES
    ]


def _js_files(target: Path, excludes: tuple[str, ...]) -> list[Path]:
    """JS/TS sources under ``target`` for the eslint lane (oxlint reuses SAST).

    Same enumeration discipline as :func:`_python_files`, filtered to
    :data:`JS_SUFFIXES`. The oxlint diff lane reuses
    :func:`_sast_targets_by_language` groups instead (T1-built partition).
    """
    return [
        path
        for path in _enumerate_sast_files(target, excludes)
        if path.suffix.lower() in JS_SUFFIXES
    ]


def eslint_argv(
    files: list[str | Path] | tuple[str | Path, ...] | str | Path,
    exclude: list[str] | tuple[str, ...] | None = None,
) -> list[str]:
    """Specialist lint over explicit files (or one dir) as JSON.

    Documented-source flags: eslint is absent in this env, so re-verify
    read-only via ``eslint --help`` when present before changing them —
    ``eslint --config <repo-root eslint.config.mjs> --format json <targets>``
    per the eslint docs (``--format json`` emits the results array; ``--config``
    points at the lane config explicitly because flat-config discovery is
    CWD-relative and misses arbitrary targets — same rationale as oxlint
    ``--config``). A single string target scans a dir (repo mode); a file
    list scans materialized diff files. ``exclude`` becomes repeatable
    ``--ignore-pattern`` flags (same dialect as oxlint; ``None`` adds none).
    """
    if isinstance(files, (str, Path)):
        targets = [str(files)]
    else:
        targets = [str(item) for item in files]
    argv = [
        ESLINT_ENGINE,
        "--config",
        str(ESLINT_CONFIG),
        "--format",
        "json",
    ]
    argv.extend(f"--ignore-pattern={p}" for p in dict.fromkeys(exclude or ()))
    argv.extend(targets)
    return argv


def knip_argv(target: str) -> list[str]:
    """Dead-code scan of a project root as one JSON line on stdout.

    Documented-source flags: knip is absent in this env, so re-verify
    read-only via ``knip --help`` when present before changing them —
    ``knip --reporter json --directory <target>`` per knip.dev reporters page
    (``json`` prints machine-readable ``{"issues": [...]}``) plus
    ``cli-arguments.ts`` (``--reporter`` repeatable, ``--directory``/``-D``
    runs from a different directory so the spawn stays inside
    :func:`run_scanner_json` with no cwd support needed).
    """
    return [KNIP_ENGINE, "--reporter", "json", "--directory", target]


def lockfile_lint_argv(lockfile: str, lock_type: str) -> list[str]:
    """Lockfile-policy scan of one lockfile (text output, exit-coded).

    Documented-source flags (lirantal/lockfile-lint README + ``bin/``
    source; binary absent, live ``--help`` re-verification owed):
    ``lockfile-lint --path <lock> --type <npm|yarn> --allowed-hosts npm
    --validate-https``. ``--validate-https`` enforces https-only (which
    implies the valid-scheme check: only ``https:`` passes); ``--allowed-hosts
    npm`` is the npm-registry alias (matches ``registry.npmjs.org``). The
    ``--allowed-schemes`` alternative is mutually exclusive with
    ``--validate-https`` per the README, so it is documented here, not wired.
    """
    return [
        LOCKFILE_LINT_ENGINE,
        "--path",
        lockfile,
        "--type",
        lock_type,
        "--allowed-hosts",
        "npm",
        "--validate-https",
    ]


def npm_audit_argv(target: str) -> list[str]:
    """Vuln scan of a project root as JSON (no new binary).

    ``npm audit --json --prefix <target>`` per the npm docs (``--json`` emits
    the audit report; ``--prefix`` scopes the spawn to the target without cwd
    support in :func:`run_scanner_json`). ``npm`` ships with node, so the lane
    needs no installer entry — documented choice, same convention as the
    ``uv``-hosted checkov lane needing only its host binary.
    """
    return [NPM_ENGINE, "audit", "--json", "--prefix", target]


def _knip_manifests(target: Path) -> list[Path]:
    """Knip scan manifests: ``package.json`` (no manifest, no run).

    A single ``package.json`` file target counts for itself. Dir walk is
    bounded, skips symlinks, never inside ``.git``; sorted for determinism.
    """
    if target.is_file():
        return [target] if target.name == "package.json" else []
    try:
        entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
    except OSError:
        return []
    return [
        p
        for p in entries[:GUARDDOG_MAX_WALK_FILES]
        if p.is_file() and not p.is_symlink() and p.name == "package.json"
    ]


def _js_lockfiles(target: Path) -> list[tuple[Path, str]]:
    """``(lockfile, type)`` pairs: npm/yarn/pnpm detection (spec: which one).

    ``package-lock.json`` -> ``npm``, ``yarn.lock`` -> ``yarn``,
    ``pnpm-lock.yaml`` -> ``pnpm`` (detected but unsupported by lockfile-lint
    per its README — the runner skips pnpm with
    :data:`LOCKFILE_LINT_PNPM_REASON`). A single lockfile target counts for
    its own kind. Bounded walk, no symlinks, never ``.git``; sorted.
    """
    if target.is_file():
        mapping = {
            "package-lock.json": "npm",
            "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm",
        }
        lock_type = mapping.get(target.name)
        return [(target, lock_type)] if lock_type else []
    try:
        entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
    except OSError:
        return []
    locks: list[tuple[Path, str]] = []
    for path in entries[:GUARDDOG_MAX_WALK_FILES]:
        if not path.is_file() or path.is_symlink():
            continue
        if path.name == "package-lock.json":
            locks.append((path, "npm"))
        elif path.name == "yarn.lock":
            locks.append((path, "yarn"))
        elif path.name == "pnpm-lock.yaml":
            locks.append((path, "pnpm"))
    return locks


def _npm_audit_manifests(target: Path) -> list[Path]:
    """npm audit manifests: ``package.json`` (lockfile used when present).

    Same walk discipline as :func:`_knip_manifests` (separate helper so the
    two lanes keep independent skip reasons and never share a branch).
    """
    return _knip_manifests(target)


async def _run_ruff(
    files: list[str | Path] | tuple[str | Path, ...], timeout: float
) -> tuple[str, Any]:
    """Lint lane over explicit files; empty list returns ok/empty with no spawn."""
    if not files:
        return "ruff", []
    payload = await run_scanner_json(
        ruff_argv(list(files)), input_data=None, timeout=timeout
    )
    return "ruff", payload


async def _run_vulture(
    files: list[str | Path] | tuple[str | Path, ...], timeout: float
) -> tuple[str, Any]:
    """Dead-code lane over explicit files (tolerant text parse, never JSON)."""
    if not files:
        return "vulture", []
    payload = await run_scanner_json(
        vulture_argv(list(files)),
        input_data=None,
        timeout=timeout,
        parse=parse_vulture_output,
    )
    return "vulture", payload


def _read_json_report(report: str, binary: str) -> Any:
    """Read one ``--json-output`` report file (contents never logged).

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


async def _run_deptry(
    target: str, timeout: float, exclude: tuple[str, ...] = ()
) -> tuple[str, Any]:
    """Dependency-hygiene lane via a ``--json-output`` tmpfile (gitleaks pattern).

    Stdout carries a text summary only, so it is discarded and the report
    file wins; the tmpfile is read once then deleted, never logged.
    Callers gate on :func:`_deptry_manifests` first (no manifests, no run).
    """
    with tempfile.NamedTemporaryFile(
        prefix="bravoguard-deptry-", suffix=".json", delete=False
    ) as tmp:
        report = tmp.name
    with contextlib.suppress(OSError):
        Path(report).unlink()
    try:
        await run_scanner_json(
            deptry_argv(target, report, exclude),
            input_data=None,
            timeout=timeout,
            parse=_ignore_scanner_stdout,
        )
        return "deptry", _read_json_report(report, DEPTRY_ENGINE)
    finally:
        with contextlib.suppress(OSError):
            Path(report).unlink()


async def _run_supply(target: Path, exclude: tuple[str, ...] = ()) -> tuple[str, Any]:
    """Supply lane: pure-Python typosquat + bundled-binary checks (H1).

    Never raises and never records an error — unreadable trees yield empty
    findings. Synchronous by design (single bounded walk, no subprocess).
    """
    return "supply", scan_supply(target, exclude)


async def _run_eslint(
    files: list[str | Path] | tuple[str | Path, ...] | str | Path,
    timeout: float,
    exclude: tuple[str, ...] = (),
) -> tuple[str, Any]:
    """Specialist lint lane; empty file list returns ok/empty with no spawn."""
    targets = [files] if isinstance(files, (str, Path)) else list(files)
    if not targets:
        return "eslint", []
    payload = await run_scanner_json(
        eslint_argv(targets, exclude), input_data=None, timeout=timeout
    )
    return "eslint", payload


async def _run_knip(target: str, timeout: float) -> tuple[str, Any]:
    """Dead-code lane over a project root (callers gate on _knip_manifests)."""
    payload = await run_scanner_json(
        knip_argv(target), input_data=None, timeout=timeout
    )
    return "knip", payload


async def _run_lockfile_lint(lockfile: str, lock_type: str, timeout: float) -> tuple[str, Any]:
    """Lockfile-policy lane over one lockfile (stdout+stderr merged).

    The real binary reports validator failures via ``console.error`` (stderr),
    so stdout alone is empty on failure — this runner merges both streams
    into ``{"lockfile", "output"}`` for :func:`normalize_lockfile_lint`.
    Non-zero exits are normal when policy fails, so the payload wins
    regardless of return code (same tolerance as oxlint/vulture).
    """
    argv = lockfile_lint_argv(lockfile, lock_type)
    if not argv:
        raise OrchestratorError("empty scanner argv")
    binary = argv[0]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError:
        raise ScannerMissingError(binary) from None
    except OSError:
        raise OrchestratorError(f"scanner failed to start: {binary}") from None
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(None), timeout)
    except TimeoutError:
        _kill_tree(proc)
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        with contextlib.suppress(ProcessLookupError, OSError, TimeoutError):
            await asyncio.wait_for(proc.wait(), 2)
        raise ScannerTimeoutError(binary) from None
    combined = (
        stdout.decode("utf-8", errors="replace")
        + "\n"
        + stderr.decode("utf-8", errors="replace")
    ).strip()
    return "lockfile-lint", {"lockfile": lockfile, "output": combined}


async def _run_lockfile_lints(target: str, timeout: float) -> tuple[str, Any]:
    """Policy lane over every supported lockfile under ``target``.

    One spawn per lockfile (npm/yarn only; pnpm filtered by the caller),
    sharing the lane budget; outputs merge into ``{"results": [{"lockfile",
    "output"}]}`` for :func:`normalize_lockfile_lint` (same envelope shape
    as the guarddog lane). No supported lockfiles returns ok/empty with no
    spawn (the scan_repo gate normally skips first; defense-in-depth floor).
    """
    locks = [(p, t) for p, t in _js_lockfiles(Path(target)) if t in ("npm", "yarn")]
    if not locks:
        return "lockfile-lint", {"results": []}
    per_lock = timeout / len(locks)
    results = []
    for path, lock_type in locks:
        _, payload = await _run_lockfile_lint(str(path), lock_type, per_lock)
        results.append(payload)
    return "lockfile-lint", {"results": results}


async def _run_npm_audit(target: str, timeout: float) -> tuple[str, Any]:
    """Vuln lane over a project root (callers gate on _npm_audit_manifests)."""
    payload = await run_scanner_json(
        npm_audit_argv(target), input_data=None, timeout=timeout
    )
    return "npm-audit", payload


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


async def _run_betterleaks_path(target: str, timeout: float) -> tuple[str, Any]:
    return await _run_secrets_with_fallback(
        betterleaks_path_argv(target),
        betterleaks_path_argv(target, GITLEAKS_FALLBACK),
        input_data=None,
        timeout=timeout,
    )


def trufflehog_argv(target: str) -> list[str]:
    """Verify-lane argv: verified-only JSON over a filesystem target.

    Flags (``filesystem --json --results=verified``) follow the repo's
    documented source (server docstring, docs/ARCHITECTURE.md,
    examples/opencode-mcp.jsonc); the binary is absent in this env, so
    re-verify read-only via ``trufflehog filesystem --help`` when present
    before changing them. Verification hits live APIs, so the lane only
    runs opt-in (``verify_secrets=True``) with the full lane budget.
    """
    return [TRUFFLEHOG_ENGINE, "filesystem", "--json", "--results=verified", target]


def _parse_trufflehog_stdout(text: str) -> list[dict[str, Any]]:
    """Parse trufflehog ``--json`` JSONL stdout (one object per line).

    Blank lines are skipped; garbage re-raises ``json.JSONDecodeError`` so
    the lane records ``failed`` (same honesty as the other lanes).
    """
    items = []
    for line in text.splitlines():
        if line.strip():
            entry = json.loads(line)
            if isinstance(entry, dict):
                items.append(entry)
    return items


async def _run_trufflehog(target: str, timeout: float) -> tuple[str, Any]:
    """Verify lane: missing binary degrades to not-installed via run_scanner_json."""
    payload = await run_scanner_json(
        trufflehog_argv(target),
        input_data=None,
        timeout=timeout,
        parse=_parse_trufflehog_stdout,
    )
    return "trufflehog", payload


# scan_repo lanes gated by detect_languages (T1). Secrets, trivy, and
# checkov are language-agnostic and always run; future manifest-gated
# lanes (deptry, knip, npm audit, ...) join via LANE_GATES (T2+).
# T4: syft/grype join via LANE_GATES with every-stack gates (any non-empty
# detection runs them; only an empty detection skips) — see languages.py.
# T5: guarddog joins via LANE_GATES manifest-gated on python + javascript
# manifest groups (pypi side needs requirements manifests, npm side needs
# package.json); win32 and missing-binary report skipped+reason, never errors.
# T7: eslint (suffix javascript) + knip / lockfile-lint / npm-audit (manifest
# javascript) join via LANE_GATES; the manifest trio adds a precise second
# check (package.json / lockfile) like deptry. oxlint keeps its repo path
# unchanged (spawn-and-error); the diff path adds a missing pre-check.
# The trufflehog verify lane intentionally bypasses LANE_GATES: secrets are
# language-agnostic (no suffix gate applies) and the lane is opt-in network
# verification, so it is wired separately via verify_secrets (never silent:
# opted-out runs report skipped + TRUFFLEHOG_OPT_IN_REASON).
_REPO_GATED_LANES: tuple[str, ...] = (
    "sast",
    "bandit",
    "oxlint",
    "supply",
    "syft",
    "grype",
    "guarddog",
    "ruff",
    "vulture",
    "deptry",
    "eslint",
    "knip",
    "lockfile-lint",
    "npm-audit",
)


_NORMALIZERS = {
    "sast": normalize_semgrep,
    "bandit": normalize_bandit,
    "betterleaks": normalize_betterleaks,
    "oxlint": normalize_oxlint,
    "trivy": normalize_trivy,
    "checkov": normalize_checkov,
    "supply": normalize_supply,
    "guarddog": normalize_guarddog,
    "ruff": normalize_ruff,
    "vulture": normalize_vulture,
    "deptry": normalize_deptry,
    "eslint": normalize_eslint,
    "knip": normalize_knip,
    "lockfile-lint": normalize_lockfile_lint,
    "npm-audit": normalize_npm_audit,
    "syft": normalize_syft,
    "trufflehog": normalize_trufflehog,
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
    if isinstance(cached, dict):  # envelope: findings + errors + languages + skipped
        response: dict[str, Any] = {
            "status": "ok",
            "findings": cached.get("findings", []),
            "cached": True,
        }
        if cached.get("errors"):
            response["errors"] = cached["errors"]
        if cached.get("languages") is not None:
            response["languages"] = cached["languages"]
        if cached.get("skipped"):
            response["skipped"] = cached["skipped"]
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
    languages: dict[str, Any] | None = None,
    skipped: dict[str, str] | None = None,
) -> None:
    if cache is None or not isinstance(findings, list):
        return
    with contextlib.suppress(Exception):
        cache.put(
            key,
            {
                "findings": findings,
                "errors": errors or {},
                "languages": languages or {},
                "skipped": skipped or {},
            },
            ttl_seconds=cache_ttl,
        )


async def _collect(jobs: list[tuple[str, Any]]) -> dict[str, Any]:
    labels = [label for label, _ in jobs]
    results = await asyncio.gather(*[coro for _, coro in jobs], return_exceptions=True)
    findings: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for label, result in zip(labels, results):
        if isinstance(result, BaseException):
            if isinstance(result, _SastPartialTimeout):
                findings.extend(_NORMALIZERS[label](result.partial_payload))
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
    and the secrets lane scans the materialized workdir in path-mode
    (skipped entirely when no files survive the filter). The diff is materialized under
    :func:`materialize_base` (repo-local ``.bravoguard/tmp/`` when writable,
    system temp otherwise); the tree is always removed afterwards, even on
    scanner error or timeout, so finding content never lingers. The result
    carries ``languages`` (detect_languages over the materialized files);
    when no python files are in the diff, bandit is skipped with reason
    "no python files in diff" (same suffix gate covers the ruff/vulture
    lanes). The ruff + vulture lanes run over the materialized python files
    (missing binaries report skipped+reason, never an error); deptry always
    reports skipped+reason here (a materialized workdir is not a project
    root with manifests). T7: oxlint + eslint run over the materialized
    javascript files (same per-language groups T1 built; suffix-gated;
    missing binaries report skipped+reason, never an error); knip +
    lockfile-lint + npm-audit always report skipped+reason here (they need a
    project root with manifests — same rationale as deptry). Semgrep scans
    per language group via :func:`_scan_sast_by_language` (python:
    ``rules/python`` + ``rules/supply-chain``; javascript: ``rules/frontend``;
    other: joint ``rules/``); empty groups are never invoked.
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
        files = materialize_diff_files(diff, workdir, excludes)
        # T1 routing: the workdir corpus carries diff suffixes (never
        # markers), so this detection is census-only.
        detection = detect_languages(workdir)
        grouped = _sast_targets_by_language(files)
        py_files = grouped["python"]
        js_files = grouped["javascript"]
        skipped: dict[str, str] = {}
        # T6: deptry needs a project root with manifests — a materialized
        # diff workdir is not a project (same rationale as guarddog/supply
        # staying out of scan_diff), so it always reports skipped+reason here.
        skipped["deptry"] = DEPTRY_DIFF_REASON
        # T7: knip + lockfile-lint + npm-audit need a project root with
        # manifests (package.json / lockfiles) — same rationale as deptry.
        skipped["knip"] = f"knip {JS_MANIFEST_DIFF_REASON}"
        skipped["lockfile-lint"] = f"lockfile-lint {JS_MANIFEST_DIFF_REASON}"
        skipped["npm-audit"] = f"npm audit {JS_MANIFEST_DIFF_REASON}"
        if not py_files:
            skipped["bandit"] = "no python files in diff"
            skipped["ruff"] = "no python files in diff"
            skipped["vulture"] = "no python files in diff"
        if not js_files:
            skipped["oxlint"] = "no javascript files in diff"
            skipped["eslint"] = "no javascript files in diff"
        # Single path-mode for both engines: files already exist, so the
        # workdir scan adds zero IO; gitleaks v8 rejects `--source -` (stdin FTL).
        secrets_job = (
            _run_betterleaks_path(str(workdir), budget)
            if files
            else _empty_secrets_result()
        )
        # Semgrep skips gitignored dirs (.bravoguard/tmp); explicit files bypass the skip.
        # Bandit ignores gitignore so it keeps the workdir; repo scans keep dir targets.
        jobs = [
            ("sast", _scan_sast_by_language(files, budget, excludes)),
            ("betterleaks", secrets_job),
        ]
        if py_files:
            jobs.insert(1, ("bandit", _run_bandit(str(workdir), budget, excludes)))
            # T6: missing-binary pre-checks (skipped+reason, never an error).
            if shutil.which(RUFF_ENGINE) is None:
                skipped["ruff"] = RUFF_MISSING_REASON
            else:
                jobs.append(("ruff", _run_ruff(py_files, budget)))
            if shutil.which(VULTURE_ENGINE) is None:
                skipped["vulture"] = VULTURE_MISSING_REASON
            else:
                jobs.append(("vulture", _run_vulture(py_files, budget)))
        if js_files:
            # T7: oxlint runs the existing lane over the materialized workdir
            # (it lints .js/.ts files, ignores .py); eslint runs over the
            # explicit js file list. Both pre-check missing binaries like
            # the repo mode (skipped+reason, never an error). The repo oxlint
            # path is unchanged (spawn-and-error); only the diff path gains
            # the pre-check.
            if shutil.which(OXLINT_ENGINE) is None:
                skipped["oxlint"] = OXLINT_MISSING_REASON
            else:
                jobs.append(("oxlint", _run_oxlint(str(workdir), budget, excludes)))
            if shutil.which(ESLINT_ENGINE) is None:
                skipped["eslint"] = ESLINT_MISSING_REASON
            else:
                jobs.append(("eslint", _run_eslint(js_files, budget)))
        result = await _collect(jobs)
        result["languages"] = detection
        if skipped:
            result["skipped"] = skipped
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if not _is_fully_degraded(result, len(jobs)):
        _store_scan_cache(
            cache,
            key,
            result.get("findings"),
            cache_ttl,
            result.get("errors"),
            languages=detection,
            skipped=skipped or None,
        )
    return result


async def scan_repo(
    path: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    allowed_root: Path | None = None,
    cache: FindingCache | None = None,
    cache_ttl: float | None = None,
    exclude: list[str] | tuple[str, ...] | None = None,
    verify_secrets: bool = False,
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
    ``--skip-path`` regexes. T1 routes the gated lanes (``_REPO_GATED_LANES``)
    by one :func:`bravoguard.languages.detect_languages` call: non-applicable
    lanes are skipped with status ``skipped`` + machine-readable reason
    (never silent, never an error), and the result carries ``languages``.
    The supply lane (pure-Python typosquat +
    bundled-binary checks) runs in-process and never errors; its walk honors
    ``exclude`` except bare binary-extension globs (``*.exe`` etc.), which
    are lifted for that lane only — they exist to keep engines off binaries,
    while listing binaries is the lane's purpose. The trufflehog verify lane
    is opt-in (``verify_secrets=True``): opted-out runs report ``skipped`` +
    reason (never silent); opted-in runs scan the raw target with the full
    lane budget (verification does network calls) and map verified live
    credentials to CRITICAL findings. ``scan_diff`` is untouched by this
    flag and stays offline/fast. The syft SBOM store + grype second-opinion
    lanes run automatically when BOTH binaries are present (grype matching
    is local-DB, so no opt-in flag is needed — deliberate contrast with the
    network-calling trufflehog lane, hence no ``server.scan_repo`` flag);
    when either binary is missing both lanes report ``skipped`` + reason
    (never an error). The guarddog heuristics lane runs when python or npm
    manifests are detected (pypi side per requirements file, npm side per
    package.json); win32 and missing-binary report ``skipped`` + reason
    (never an error, never an attempted spawn). Grype matches the stored
    SBOM in a second phase after
    the fan-out (it needs the syft store path), and its findings merge with
    a final :func:`normalize_findings` pass so the CVE secondary dedup
    sees trivy + grype together. The T6 python depth lanes join the fan-out
    last (ruff + vulture over enumerated python files, deptry over the
    project root): missing binaries and missing deptry manifests report
    ``skipped`` + reason (never an error, never an attempted spawn). The T7
    JS depth lanes join after them (eslint over enumerated js files, knip +
    npm-audit over the project root, lockfile-lint per lockfile): missing
    binaries and missing manifests report ``skipped`` + reason (never an
    error, never an attempted spawn); pnpm-only trees report the documented
    unsupported-type skip.
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
            f"\x00exclude:{','.join(sorted(excludes))}"
            f"\x00verify:{bool(verify_secrets)}",
            scanner_versions=scanner_fingerprint(),
        )
        hit = _lookup_scan_cache(cache, key)
        if hit is not None:
            return hit
    # One detection drives every gated lane; the gated subset is fixed here
    # while future lanes join via LANE_GATES (T2+ extension point).
    detection = detect_languages(target)
    skipped = {
        lane: reason for lane, reason in lanes_for(detection).items() if lane in _REPO_GATED_LANES
    }
    if not verify_secrets:
        skipped["trufflehog"] = TRUFFLEHOG_OPT_IN_REASON
    # T4: the SBOM store is only useful with its matcher and vice versa, so
    # both lanes run only when BOTH binaries are present; either missing
    # skips both with a machine-readable reason (never an error).
    if "syft" not in skipped and "grype" not in skipped:
        if shutil.which(SYFT_ENGINE) is None:
            skipped["syft"] = SYFT_MISSING_REASON
            skipped["grype"] = GRYPE_NO_SBOM_REASON
        elif shutil.which(GRYPE_ENGINE) is None:
            skipped["syft"] = SYFT_IDLE_REASON
            skipped["grype"] = GRYPE_MISSING_REASON
    # T5: guarddog never attempts win32 (nono-py build failure, cli.py
    # precedent — platform first, so Windows never even probes the binary)
    # and degrades to skipped+reason when the binary is missing.
    if "guarddog" not in skipped:
        if sys.platform == "win32":
            skipped["guarddog"] = GUARDDOG_WIN32_REASON
        elif shutil.which(GUARDDOG_ENGINE) is None:
            skipped["guarddog"] = GUARDDOG_MISSING_REASON
    with tempfile.TemporaryDirectory(prefix="bravoguard-secrets-") as stage_tmp:
        staging = Path(stage_tmp)
        staged = _stage_filtered_tree(target, excludes, staging)
        secrets_job = (
            _run_betterleaks_path(str(staging), budget)
            if staged
            else _empty_secrets_result()
        )
        jobs: list[tuple[str, Any]] = []
        if "sast" not in skipped:
            jobs.append(("sast", _scan_sast_repo_files(target, budget, excludes)))
        if "bandit" not in skipped:
            jobs.append(("bandit", _run_bandit(str(target), budget, excludes)))
        jobs.append(("betterleaks", secrets_job))
        if verify_secrets:
            jobs.append(("trufflehog", _run_trufflehog(str(target), budget)))
        if "oxlint" not in skipped:
            jobs.append(("oxlint", _run_oxlint(str(target), budget, excludes)))
        jobs.append(("trivy", _run_trivy(str(target), budget, excludes)))
        jobs.append(("checkov", _run_checkov(str(target), budget, excludes)))
        if "syft" not in skipped:
            jobs.append(("syft", _run_syft(str(target), budget)))
        if "supply" not in skipped:
            jobs.append(("supply", _run_supply(target, excludes)))
        if "guarddog" not in skipped:
            jobs.append(("guarddog", _run_guarddog(str(target), budget)))
        # T6: python depth lanes (suffix-gated ruff/vulture, manifest-gated
        # deptry). Appended last so mixed-lane findings order is unchanged.
        if "ruff" not in skipped:
            if shutil.which(RUFF_ENGINE) is None:
                skipped["ruff"] = RUFF_MISSING_REASON
            else:
                jobs.append(("ruff", _run_ruff(_python_files(target, excludes), budget)))
        if "vulture" not in skipped:
            if shutil.which(VULTURE_ENGINE) is None:
                skipped["vulture"] = VULTURE_MISSING_REASON
            else:
                jobs.append(
                    ("vulture", _run_vulture(_python_files(target, excludes), budget))
                )
        if "deptry" not in skipped:
            if shutil.which(DEPTRY_ENGINE) is None:
                skipped["deptry"] = DEPTRY_MISSING_REASON
            elif not _deptry_manifests(target):
                skipped["deptry"] = DEPTRY_NO_MANIFEST_REASON
            else:
                jobs.append(("deptry", _run_deptry(str(target), budget, excludes)))
        # T7: JS depth lanes (suffix-gated eslint, manifest-gated knip /
        # lockfile-lint / npm-audit). Appended after the T6 lanes so
        # mixed-lane findings order is unchanged. oxlint keeps its repo path
        # unchanged (spawn-and-error, no pre-check — spec: no behavior change).
        if "eslint" not in skipped:
            if shutil.which(ESLINT_ENGINE) is None:
                skipped["eslint"] = ESLINT_MISSING_REASON
            else:
                jobs.append(
                    ("eslint", _run_eslint(_js_files(target, excludes), budget, excludes))
                )
        if "knip" not in skipped:
            if shutil.which(KNIP_ENGINE) is None:
                skipped["knip"] = KNIP_MISSING_REASON
            elif not _knip_manifests(target):
                skipped["knip"] = KNIP_NO_MANIFEST_REASON
            else:
                jobs.append(("knip", _run_knip(str(target), budget)))
        if "lockfile-lint" not in skipped:
            if shutil.which(LOCKFILE_LINT_ENGINE) is None:
                skipped["lockfile-lint"] = LOCKFILE_LINT_MISSING_REASON
            else:
                locks = _js_lockfiles(target)
                supported = [(p, t) for p, t in locks if t in ("npm", "yarn")]
                if not locks:
                    skipped["lockfile-lint"] = LOCKFILE_LINT_NO_LOCKFILE_REASON
                elif not supported:
                    skipped["lockfile-lint"] = LOCKFILE_LINT_PNPM_REASON
                else:
                    jobs.append(("lockfile-lint", _run_lockfile_lints(str(target), budget)))
        if "npm-audit" not in skipped:
            if shutil.which(NPM_ENGINE) is None:
                skipped["npm-audit"] = NPM_AUDIT_MISSING_REASON
            elif not _npm_audit_manifests(target):
                skipped["npm-audit"] = NPM_AUDIT_NO_MANIFEST_REASON
            else:
                jobs.append(("npm-audit", _run_npm_audit(str(target), budget)))
        result = await _collect(jobs)
        # T4 second phase: grype matches the stored SBOM (sequential — it
        # needs the syft store path, so it cannot join the fan-out). Its
        # findings re-enter normalize_findings with the batch so the CVE
        # secondary dedup sees trivy + grype together.
        if "grype" not in skipped:
            store = sbom_store_path(target)
            if store.is_file():
                try:
                    _, grype_payload = await _run_grype(str(store), budget)
                except ScannerMissingError:
                    result.setdefault("errors", {})["grype"] = "not-installed"
                except ScannerTimeoutError:
                    result.setdefault("errors", {})["grype"] = "timeout"
                except OrchestratorError:
                    result.setdefault("errors", {})["grype"] = "failed"
                else:
                    combined = result["findings"] + normalize_grype(grype_payload)
                    result["findings"] = normalize_findings(combined)
            else:
                skipped["grype"] = GRYPE_NO_SBOM_REASON
        if staged:
            for finding in result.get("findings", []):
                if isinstance(finding, dict) and finding.get("path"):
                    finding["path"] = _remap_staged_path(
                        str(finding["path"]), staging, target
                    )
        result["languages"] = detection
        if skipped:
            result["skipped"] = skipped
    if not _is_fully_degraded(result, len(jobs)):
        _store_scan_cache(
            cache,
            key,
            result.get("findings"),
            cache_ttl,
            result.get("errors"),
            languages=detection,
            skipped=skipped or None,
        )
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
