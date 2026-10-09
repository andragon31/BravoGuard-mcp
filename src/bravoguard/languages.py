"""Language + container detection and lane gating (T1, Fase 0.1).

Cheap marker check first, then a bounded suffix census over the target tree.
Mirrors :func:`bravoguard.orchestrator._enumerate_sast_files` discipline:
never follow symlinks, never descend ``.git``.

``LANE_GATES`` classifies each existing lane as suffix-gated (bandit owns
Python, oxlint owns JavaScript, semgrep covers both) or manifest-gated
(supply-typosquat needs Python manifests). :func:`lanes_for` is the T2+
extension point: future lanes (ruff, eslint, deptry, knip, hadolint, ...)
register here and are picked up by the orchestrator without new branches.
"""

from __future__ import annotations

from collections.abc import Mapping
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

# Manifest/marker basenames that prove a stack without reading file content.
PYTHON_MARKERS: tuple[str, ...] = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "poetry.lock",
)
# "requirements*.txt" (requirements.txt, requirements-dev.txt, ...) matches
# via _is_python_marker, mirroring supply.py parsing.
JS_MARKERS: tuple[str, ...] = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "tsconfig.json",
)
CONTAINER_MARKERS: tuple[str, ...] = (
    "Dockerfile",
    "Containerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
)
# "Dockerfile.*" (Dockerfile.prod, ...) matches via _is_container_marker.

# Detected-but-unsupported stacks: reported, never faked as supported.
UNSUPPORTED_MARKERS: dict[str, str] = {
    "go.mod": "go",
    "Cargo.toml": "rust",
    "Gemfile": "ruby",
    "composer.json": "php",
    "pom.xml": "java",
}

# Suffix groups for the census and diff routing. JS_SUFFIXES mirrors the
# SAST js/ts extensions in orchestrator.SAST_FILE_EXTENSIONS.
PYTHON_SUFFIXES: tuple[str, ...] = (".py", ".pyi")
JS_SUFFIXES: tuple[str, ...] = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
TS_SUFFIXES: tuple[str, ...] = (".ts", ".tsx")

# Upper bound on files examined per detection (markers + census share it).
MAX_CENSUS_FILES = 5000

# Canonical language order for the ``languages`` list.
LANGUAGE_ORDER: tuple[str, ...] = ("python", "javascript", "containers")

# Per-lane gating: "suffix" lanes need a detected language, "manifest"
# lanes need a manifest group present. T2+ lanes register here.
# T4 choice (documented): syft/grype match the whole target dir regardless
# of language (lockfile-driven vuln matching across ecosystems), so their
# gate lists every detected stack — they run on any non-empty detection
# and skip only when detection found nothing.
LANE_GATES: dict[str, dict[str, Any]] = {
    "sast": {"kind": "suffix", "languages": ("python", "javascript")},
    "bandit": {"kind": "suffix", "languages": ("python",)},
    "oxlint": {"kind": "suffix", "languages": ("javascript",)},
    "supply": {"kind": "manifest", "manifests": ("python",)},
    "syft": {"kind": "suffix", "languages": ("python", "javascript", "containers")},
    "grype": {"kind": "suffix", "languages": ("python", "javascript", "containers")},
    # T5 choice (documented): the guarddog heuristics lane complements the
    # own typosquat lane (different axis), so it gates on either manifest
    # group — python manifests feed the pypi side, package.json the npm side.
    "guarddog": {"kind": "manifest", "manifests": ("python", "javascript")},
    # T6 choice (documented): ruff + vulture are suffix-gated on python
    # (they read .py source, so markers alone never qualify them), while
    # deptry is manifest-gated on python (it reads requirements manifests
    # and pyproject dependencies — no manifests, no run).
    "ruff": {"kind": "suffix", "languages": ("python",)},
    "vulture": {"kind": "suffix", "languages": ("python",)},
    "deptry": {"kind": "manifest", "manifests": ("python",)},
    # T7 choice (documented): eslint is suffix-gated on javascript (it reads
    # .js/.ts source like oxlint, so markers alone never qualify it), while
    # knip / lockfile-lint / npm-audit are manifest-gated on javascript
    # (knip needs package.json; lockfile-lint needs a lockfile;
    # npm audit needs package.json — no manifest, no run). The manifest gate
    # checks the javascript marker group; the orchestrator adds a precise
    # second check per lane (same two-stage pattern as deptry).
    "eslint": {"kind": "suffix", "languages": ("javascript",)},
    "knip": {"kind": "manifest", "manifests": ("javascript",)},
    "lockfile-lint": {"kind": "manifest", "manifests": ("javascript",)},
    "npm-audit": {"kind": "manifest", "manifests": ("javascript",)},
    # T8 choice (documented): hadolint + kics are suffix-gated on containers
    # (they read Dockerfiles / compose files, so markers alone never qualify
    # them — the census counts marker basenames as the containers signal and
    # the orchestrator adds a precise second check via _container_dockerfiles
    # / _kics_targets, same two-stage pattern as deptry). dockle + dive are
    # "image"-gated: the opt-in container_image param (never detection)
    # lifts them, so lanes_for ALWAYS skips them (safer than running an
    # image lane with no image — there is nothing honest to analyze).
    "hadolint": {"kind": "suffix", "languages": ("containers",)},
    "kics": {"kind": "suffix", "languages": ("containers",)},
    "dockle": {"kind": "image", "languages": ("containers",)},
    "dive": {"kind": "image", "languages": ("containers",)},
}

# Machine-readable skip reasons, one per gated lane (T2+ adds its own).
SKIP_REASONS: dict[str, str] = {
    "sast": "no python or javascript files detected",
    "bandit": "no python files or markers detected",
    "oxlint": "no javascript files or markers detected",
    "supply": "no python manifests detected",
    "syft": "no python, javascript, or container signals detected",
    "grype": "no python, javascript, or container signals detected",
    "guarddog": "no python or npm manifests detected",
    "ruff": "no python files or markers detected",
    "vulture": "no python files or markers detected",
    "deptry": "no python manifests detected",
    "eslint": "no javascript files or markers detected",
    "knip": "no javascript manifests detected",
    "lockfile-lint": "no javascript lockfiles detected",
    "npm-audit": "no javascript manifests detected",
    "hadolint": "no container files or markers detected",
    "kics": "no compose or dockerfile targets detected",
    "dockle": "dockle image lane is opt-in: pass container_image=<tar path|image ref>",
    "dive": "dive image lane is opt-in: pass container_image=<tar path|image ref>",
}


def _is_python_marker(name: str) -> bool:
    """True for Python manifest basenames (incl. ``requirements*.txt``)."""
    return name in PYTHON_MARKERS or fnmatch(name, "requirements*.txt")


def _is_container_marker(name: str) -> bool:
    """True for container marker basenames (incl. ``Dockerfile.*``)."""
    return name in CONTAINER_MARKERS or name.startswith("Dockerfile.")


def is_container_filename(name: str) -> bool:
    """Public wrapper over :func:`_is_container_marker` for lane routing.

    The orchestrator diff materializer preserves these basenames (instead
    of the default ``.py`` suffix) so Dockerfile diffs route to hadolint.
    """
    return _is_container_marker(name)


def _candidate_files(target: Path) -> list[Path]:
    """Files to examine: bounded, no symlinks, never inside ``.git``.

    ``rglob`` does not follow directory symlinks and each entry is
    re-checked with ``is_symlink()`` (same cheap stat as
    ``_enumerate_sast_files``); unreadable trees yield ``[]``.
    """
    try:
        entries = sorted(p for p in target.rglob("*") if ".git" not in p.parts)
    except OSError:
        return []
    candidates: list[Path] = []
    for path in entries:
        if len(candidates) >= MAX_CENSUS_FILES:
            break
        if not path.is_file() or path.is_symlink():
            continue
        candidates.append(path)
    return candidates


def detect_languages(target: Path) -> dict[str, Any]:
    """Detect stacks in ``target`` (file or dir) via markers + suffix census.

    Returns ``{"languages": [...], "markers": {...},
    "census": {"python": n, "javascript": n}, "typescript": bool,
    "containers": bool, "unsupported": [...]}``. A single-file target is
    treated as a one-entry corpus (its own basename/suffix only); marker
    lists hold sorted unique basenames; ``unsupported`` holds sorted
    language names from :data:`UNSUPPORTED_MARKERS`.
    """
    target = Path(target)
    if target.is_file():
        names = [target.name]
        suffixes = [target.suffix.lower()]
    elif target.is_dir():
        candidates = _candidate_files(target)
        names = [path.name for path in candidates]
        suffixes = [path.suffix.lower() for path in candidates]
    else:
        names, suffixes = [], []
    python_markers = sorted({name for name in names if _is_python_marker(name)})
    js_markers = sorted({name for name in names if name in JS_MARKERS})
    container_markers = sorted({name for name in names if _is_container_marker(name)})
    unsupported = sorted({UNSUPPORTED_MARKERS[name] for name in names if name in UNSUPPORTED_MARKERS})
    python_count = sum(1 for suffix in suffixes if suffix in PYTHON_SUFFIXES)
    js_count = sum(1 for suffix in suffixes if suffix in JS_SUFFIXES)
    typescript = any(suffix in TS_SUFFIXES for suffix in suffixes) or "tsconfig.json" in js_markers
    containers = bool(container_markers)
    detected = {
        "python": bool(python_markers) or python_count > 0,
        "javascript": bool(js_markers) or js_count > 0,
        "containers": containers,
    }
    return {
        "languages": [name for name in LANGUAGE_ORDER if detected[name]],
        "markers": {"python": python_markers, "javascript": js_markers, "containers": container_markers},
        "census": {"python": python_count, "javascript": js_count},
        "typescript": typescript,
        "containers": containers,
        "unsupported": unsupported,
    }


def lanes_for(detection: Mapping[str, Any]) -> dict[str, str]:
    """Skipped lanes for a :func:`detect_languages` result (``{}`` = run all).

    Interprets :data:`LANE_GATES`: suffix-gated lanes skip when none of
    their languages was detected, manifest-gated lanes skip when none of
    their manifest groups has markers, image-gated lanes (dockle/dive)
    always skip here (the opt-in param lifts them in the orchestrator).
    Missing keys degrade to "skip"
    (safer than running a lane with no signal). T2+ lanes only need a
    ``LANE_GATES`` entry plus a :data:`SKIP_REASONS` line to be routed.
    """
    detected = set(detection.get("languages", []))
    markers = detection.get("markers", {})
    if not isinstance(markers, Mapping):
        markers = {}
    skips: dict[str, str] = {}
    for lane, gate in LANE_GATES.items():
        if gate.get("kind") == "image":
            # Opt-in image lanes: detection never qualifies them (the
            # container_image param lifts the skip in the orchestrator).
            skips[lane] = SKIP_REASONS[lane]
        elif gate.get("kind") == "manifest":
            groups = gate.get("manifests", ())
            if not any(markers.get(group) for group in groups):
                skips[lane] = SKIP_REASONS[lane]
        else:  # suffix-gated (default)
            if not (set(gate.get("languages", ())) & detected):
                skips[lane] = SKIP_REASONS[lane]
    return skips
