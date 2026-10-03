"""Windows guarddog alternative: typosquat + bundled-binary supply checks (H1).

Pure-Python ``scan_repo`` lane — no subprocess, no new binaries, bounded
time (single walk capped at ``MAX_WALK_FILES``, same order as the
fingerprint). ``scan_diff`` is untouched: diffs lack dependency context (a
few added ``requirements`` lines are not the dep set) and binaries never
appear in diffs, so wiring the lane there adds cost for zero signal.

Typosquat: required deps come from ``requirements*.txt`` (tolerant line
parsing: comments/flags/URLs skipped) plus ``pyproject.toml``
``[project].dependencies``. ``[project].optional-dependencies`` is
required-only by design (extras are opt-in, lower install-time risk).
A dep flags when its normalized form (lowercase, ``-_.`` stripped) is
Damerau distance 1 (single insertion/deletion/substitution, plus one
adjacent transposition — the transposition catches ``reqeusts``/``flaks``
style swaps the plain metric misses) from a curated top-PyPI name without
being equal. The list is certain-only: every entry is a famous top
project; short names (normalized length < 4) are omitted because
distance-1 on 3-letter names collides with real packages (``box`` vs
``tox``).

Bundled binaries: extensions ``.exe/.dll/.so/.dylib/.bin`` walked with the
caller excludes, EXCEPT bare binary-extension globs (``*.exe`` etc.) are
lifted for this lane — those defaults exist to keep scanner engines off
binaries, while listing binaries is this lane's whole purpose. Directory
and filename excludes (``.venv/``, ``frames/``, ``tools/app.exe``) are
still honored, so vendored trees stay silent. LOW severity, review wording:
binaries CAN be legitimate, the finding asks for provenance review.

Findings use mapped CWEs only (CWE-1357 -> A03 typosquat, CWE-506 -> A08
bundled binary, both verified via ``explain_cwe``).
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from pathlib import Path
from typing import Any

from bravoguard.normalizer import make_finding

TYPO_RULE_ID = "bravoguard-supply-typosquat"
TYPO_CWE = "CWE-1357"
BIN_RULE_ID = "bravoguard-supply-bundled-binary"
BIN_CWE = "CWE-506"

BINARY_EXTENSIONS = frozenset({".exe", ".dll", ".so", ".dylib", ".bin"})
# Engine-oriented binary globs lifted for the binex walk (see docstring).
LIFTED_BINARY_GLOBS = frozenset({f"*{ext}" for ext in sorted(BINARY_EXTENSIONS)})
MIN_NAME_LENGTH = 4
MAX_WALK_FILES = 5000

# Certain-only top PyPI projects (every entry a famous real project;
# normalized length >= 4, see docstring). Canonical spelling kept for messages.
TOP_PYPI_PACKAGES = frozenset(
    {
        "django", "flask", "fastapi", "tornado", "aiohttp", "httpx", "requests",
        "urllib3", "starlette", "uvicorn", "gunicorn", "werkzeug", "jinja2",
        "sanic", "falcon", "bottle", "cherrypy", "pyramid", "quart", "webob",
        "numpy", "pandas", "scipy", "matplotlib", "seaborn", "plotly", "bokeh",
        "scikit-learn", "tensorflow", "torch", "keras", "xgboost", "lightgbm",
        "nltk", "spacy", "gensim", "statsmodels", "polars", "pyarrow", "dask",
        "jupyter", "ipython", "notebook", "openai", "anthropic", "transformers",
        "datasets", "tokenizers", "tiktoken", "langchain", "joblib",
        "sqlalchemy", "alembic", "pymongo", "redis", "psycopg2", "asyncpg",
        "pymysql", "elasticsearch", "motor", "aiomysql",
        "boto3", "botocore", "kubernetes", "docker", "ansible", "paramiko",
        "fabric", "invoke", "psutil", "watchdog",
        "pytest", "coverage", "black", "ruff", "flake8", "mypy", "pylint",
        "isort", "sphinx", "mkdocs", "setuptools", "twine", "build",
        "virtualenv", "poetry", "hatch", "wheel", "cython", "pyinstaller",
        "pre-commit", "pytest-cov", "pytest-asyncio", "pytest-mock",
        "hypothesis", "faker", "freezegun", "responses", "requests-mock",
        "click", "rich", "typer", "pydantic", "attrs", "marshmallow", "pyyaml",
        "jsonschema", "python-dateutil", "pytz", "chardet", "idna", "certifi",
        "packaging", "pluggy", "colorama", "tqdm", "loguru", "structlog",
        "tenacity", "retrying", "cachetools", "wrapt", "deprecated", "boltons",
        "more-itertools", "toolz", "arrow", "pendulum",
        "trio", "anyio", "curio", "aiofiles", "uvloop", "websockets",
        "grpcio", "paho-mqtt", "pyzmq",
        "protobuf", "msgpack", "orjson", "ujson", "simplejson",
        "cryptography", "bcrypt", "passlib", "pyjwt", "oauthlib", "authlib",
        "requests-oauthlib", "pycryptodome",
        "beautifulsoup4", "lxml", "scrapy", "selenium", "playwright",
        "html5lib", "feedparser",
        "celery", "kombu", "flower",
        "pillow", "pygame", "opencv-python",
    }
)

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def normalize_dep_name(name: str) -> str:
    """Lowercase with ``-_.`` separators stripped (typosquat comparison form)."""
    return re.sub(r"[-_.]", "", (name or "").strip().lower())


_NORMALIZED_TOP: dict[str, str] = {normalize_dep_name(n): n for n in TOP_PYPI_PACKAGES}


def is_edit_distance_one(first: str, second: str) -> bool:
    """Damerau distance 1: one insertion/deletion/substitution, or one
    adjacent transposition (equal strings excluded)."""
    if first == second:
        return False
    short, long = (first, second) if len(first) <= len(second) else (second, first)
    if len(long) - len(short) > 1:
        return False
    if len(short) != len(long):
        return any(long[:i] + long[i + 1 :] == short for i in range(len(long)))
    diffs = [i for i, (a, b) in enumerate(zip(short, long)) if a != b]
    if len(diffs) == 1:
        return True
    return (
        len(diffs) == 2
        and diffs[1] == diffs[0] + 1
        and short[diffs[0]] == long[diffs[1]]
        and short[diffs[1]] == long[diffs[0]]
    )


def find_typosquat_target(normalized: str) -> str | None:
    """Canonical top name within distance-1, else None (exact matches silent)."""
    if len(normalized) < MIN_NAME_LENGTH or normalized in _NORMALIZED_TOP:
        return None
    for candidate in sorted(_NORMALIZED_TOP):
        if len(candidate) >= MIN_NAME_LENGTH and is_edit_distance_one(normalized, candidate):
            return _NORMALIZED_TOP[candidate]
    return None


def parse_requirement_name(line: str) -> str | None:
    """Extract a dep name from one requirements line; None when skippable."""
    text = line.split("#", 1)[0].strip()
    if not text or text.startswith(("-", ".", "/")) or "://" in text:
        return None
    match = _REQ_NAME_RE.match(text)
    return match.group(1) if match else None


def parse_requirements_file(path: Path) -> list[tuple[str, int]]:
    """(name, line-number) pairs from one requirements file; unreadable -> []."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    seen: set[str] = set()
    pairs: list[tuple[str, int]] = []
    for number, line in enumerate(lines, 1):
        name = parse_requirement_name(line)
        if name is None or normalize_dep_name(name) in seen:
            continue
        seen.add(normalize_dep_name(name))
        pairs.append((name, number))
    return pairs


def parse_pyproject_dependencies(path: Path) -> list[tuple[str, int]]:
    """(name, 0) pairs from ``[project].dependencies``; missing/unreadable -> []."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    project = data.get("project", {})
    deps = project.get("dependencies", []) if isinstance(project, dict) else []
    if not isinstance(deps, list):
        return []
    seen: set[str] = set()
    pairs: list[tuple[str, int]] = []
    for entry in deps:
        name = parse_requirement_name(str(entry)) if isinstance(entry, str) else None
        if name is None or normalize_dep_name(name) in seen:
            continue
        seen.add(normalize_dep_name(name))
        pairs.append((name, 0))
    return pairs


def _is_excluded(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    """Mirror of ``orchestrator._is_excluded`` (kept local: orchestrator imports
    this module, so the matcher cannot be shared without a cycle)."""
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


def _active_patterns(excludes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(p for p in excludes if p not in LIFTED_BINARY_GLOBS)


def _iter_target_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    try:
        entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
    except OSError:
        return []
    return [p for p in entries[:MAX_WALK_FILES] if p.is_file() and not p.is_symlink()]


def scan_typosquat(target: Path, excludes: tuple[str, ...]) -> list[dict[str, Any]]:
    """Flag required deps one edit from a top PyPI name (MEDIUM, CWE-1357)."""
    patterns = _active_patterns(excludes)

    findings: list[dict[str, Any]] = []
    try:
        base = target if target.is_dir() else target.parent
        files = _iter_target_files(target)
    except OSError:
        return []
    for path in files:
        name = path.name
        try:
            rel = path.relative_to(base).as_posix()
        except (OSError, ValueError):
            continue
        if name == "pyproject.toml":
            if _is_excluded(rel, patterns):
                continue
            pairs = [(n, ln, rel) for n, ln in parse_pyproject_dependencies(path)]
        elif name.startswith("requirements") and name.endswith(".txt"):
            if _is_excluded(rel, patterns):
                continue
            pairs = [(n, ln, rel) for n, ln in parse_requirements_file(path)]
        else:
            continue
        for dep, line, rel_path in pairs:
            target_name = find_typosquat_target(normalize_dep_name(dep))
            if target_name is None:
                continue
            findings.append(
                make_finding(
                    TYPO_RULE_ID,
                    TYPO_CWE,
                    rel_path,
                    line,
                    "MEDIUM",
                    f"Possible typosquat: dependency '{dep}' is one edit from "
                    f"top PyPI package '{target_name}'. Verify the exact name "
                    "on PyPI before installing — typosquats run install-time code.",
                    f"Pin the exact package name and version, verify on PyPI: "
                    f"pip index versions {target_name}",
                )
            )
    return findings


def scan_bundled_binaries(target: Path, excludes: tuple[str, ...]) -> list[dict[str, Any]]:
    """Flag committed binaries for provenance review (LOW, CWE-506)."""
    patterns = _active_patterns(excludes)

    findings: list[dict[str, Any]] = []
    try:
        base = target if target.is_dir() else target.parent
        files = _iter_target_files(target)
    except OSError:
        return []
    for path in files:
        if path.suffix.lower() not in BINARY_EXTENSIONS:
            continue
        try:
            rel = path.relative_to(base).as_posix()
        except (OSError, ValueError):
            continue
        if _is_excluded(rel, patterns):
            continue
        findings.append(
            make_finding(
                BIN_RULE_ID,
                BIN_CWE,
                rel,
                0,
                "LOW",
                f"Bundled binary '{rel}' is committed in the repo. Binaries can "
                "be legitimate (vendored tools, test fixtures) — review "
                "provenance before trusting it.",
                "Rebuild from source or verify against the publisher hash: "
                "compare sha256sum output with the release checksum.",
            )
        )
    return findings


def scan_supply(
    target: str | Path, excludes: tuple[str, ...] | list[str] | None = None
) -> list[dict[str, Any]]:
    """Run both supply checks over ``target``; never raises (unreadable -> [])."""
    path = Path(target)
    if not path.exists():
        return []
    patterns = tuple(excludes or ())
    try:
        return scan_typosquat(path, patterns) + scan_bundled_binaries(path, patterns)
    except OSError:
        return []
