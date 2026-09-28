"""SQLite finding cache for BRAVOGuard scans (Phase 1, T3).

Cache-first layer over normalized findings: ``scan_diff``/``scan_repo`` check
the cache before fanning out to scanners and write through after
:func:`bravoguard.normalizer.normalize_findings`. ``osv_lookup`` uses the same
store via :func:`make_osv_key` (real scanner wiring lands in T4).

Key formula: ``sha256(content-hash + scanner versions + DB UpdatedAt/Built
+ image digest + rule versions)``. Scanner versions come from
``tools-manifest.json`` plus orchestrator engine constants; DB dates default
to empty so the schema stays forward-compatible.

Storage: one SQLite table, default path ``.bravoguard/cache.db`` (cwd),
override with ``BRAVO_CACHE_PATH`` (``:memory:`` for tests). TTL is optional
(default: no expiry); pass ``ttl_seconds`` or honor a FastMCP ``cache_ttl``
hint. Empty-input guards are never cached. Payloads are never logged.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

CACHE_ENV_VAR = "BRAVO_CACHE_PATH"
IN_MEMORY_PATH = ":memory:"
DEFAULT_CACHE_DIRNAME = ".bravoguard"
DEFAULT_CACHE_FILENAME = "cache.db"

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS cache_entries ("
    "key TEXT PRIMARY KEY, payload TEXT NOT NULL, "
    "created_at REAL NOT NULL, ttl_seconds REAL)"
)

__all__ = [
    "CACHE_ENV_VAR",
    "DEFAULT_CACHE_FILENAME",
    "FindingCache",
    "IN_MEMORY_PATH",
    "content_hash",
    "get",
    "get_default_cache",
    "make_key",
    "make_osv_key",
    "make_scan_key",
    "put",
    "reset_default_cache",
    "resolve_cache_path",
    "rules_fingerprint",
    "scanner_fingerprint",
]


def content_hash(content: str) -> str:
    """Stable sha256 hex of scan input (diff text, package id, dir digest)."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _manifest_versions(manifest_path: Path | None = None) -> str:
    if manifest_path is None:
        manifest_path = Path(__file__).resolve().parents[2] / "tools-manifest.json"
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        binaries = manifest.get("binaries", [])
        pairs = sorted(f"{b['name']}@{b.get('version', '?')}" for b in binaries if "name" in b)
        return ",".join(pairs)
    except (OSError, ValueError, TypeError, KeyError):
        return ""


def scanner_fingerprint(manifest_path: Path | None = None) -> str:
    """Scanner version string: orchestrator engines + manifest pins."""
    try:
        from bravoguard import orchestrator as _orch

        engines = f"{_orch.SEMGREP_ENGINE}+{_orch.OPENGREP_FALLBACK}"
    except Exception:
        engines = "semgrep+opengrep"
    return f"{engines}|{_manifest_versions(manifest_path)}"


def rules_fingerprint(rules_dir: Path | None = None) -> str:
    """Best-effort rule version string (sorted rule filenames); "" on failure."""
    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parents[2] / "rules"
    try:
        names = sorted(p.name for p in Path(rules_dir).glob("*.yaml") if p.is_file())
        return ",".join(names)
    except OSError:
        return ""


def make_key(
    digest: str,
    scanner_versions: str,
    db_updated_at: str = "",
    db_built: str = "",
    image_digest: str = "",
    rule_versions: str = "",
) -> str:
    """Hash the cache-key parts into one sha256 hex key."""
    parts = [digest, scanner_versions, db_updated_at or "", db_built or "", image_digest or "", rule_versions or ""]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def make_scan_key(
    content: str,
    *,
    scanner_versions: str | None = None,
    db_updated_at: str = "",
    db_built: str = "",
    image_digest: str = "",
    rule_versions: str = "",
) -> str:
    """Key for a scan input (diff text or directory digest)."""
    if scanner_versions is None:
        scanner_versions = scanner_fingerprint()
    return make_key(
        content_hash(content), scanner_versions, db_updated_at, db_built, image_digest, rule_versions
    )


def make_osv_key(
    package: str,
    version: str,
    *,
    scanner_versions: str | None = None,
    db_updated_at: str = "",
    db_built: str = "",
) -> str:
    """Key for an osv_lookup call; hook for the T4 scanner wiring."""
    if scanner_versions is None:
        scanner_versions = scanner_fingerprint()
    content = f"osv:{package.strip()}@{version.strip()}"
    return make_key(content_hash(content), scanner_versions, db_updated_at, db_built)


def resolve_cache_path(explicit: str | Path | None = None) -> str | Path:
    """Resolve the SQLite path: explicit > BRAVO_CACHE_PATH env > .bravoguard/cache.db."""
    if explicit is not None:
        return explicit
    env = os.environ.get(CACHE_ENV_VAR, "").strip()
    if env:
        return env
    return Path.cwd() / DEFAULT_CACHE_DIRNAME / DEFAULT_CACHE_FILENAME


class FindingCache:
    """SQLite store for normalized findings with optional per-entry TTL."""

    def __init__(self, path: str | Path | None = None, ttl_seconds: float | None = None) -> None:
        self._path = resolve_cache_path(path)
        self._default_ttl = ttl_seconds if ttl_seconds and ttl_seconds > 0 else None
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        target = self._path
        if str(target) != IN_MEMORY_PATH:
            target = Path(str(target))
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                target = Path(tempfile.gettempdir()) / "bravoguard-cache.db"
                target.parent.mkdir(parents=True, exist_ok=True)
            self._path = target
        self._conn = sqlite3.connect(str(target), check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        return self._conn

    def get(self, key: str) -> list[dict[str, Any]] | dict[str, Any] | None:
        """Return the cached payload on hit, None on miss/expiry/corruption.

        Scan entries are ``{"findings": [...], "errors": {...}}`` envelopes;
        legacy list-only payloads and OSV vuln lists still read back as-is.
        """
        if not key:
            return None
        try:
            conn = self._connect()
            row = conn.execute(
                "SELECT payload, created_at, ttl_seconds FROM cache_entries WHERE key = ?",
                (key,),
            ).fetchone()
        except (sqlite3.Error, OSError):
            return None
        if row is None:
            return None
        payload, created_at, ttl = row
        if ttl is not None and ttl > 0 and (time.time() - created_at) > ttl:
            with contextlib.suppress(sqlite3.Error, OSError):
                self._connect().execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                self._connect().commit()
            return None
        try:
            value = json.loads(payload)
        except (json.JSONDecodeError, TypeError, ValueError):
            with contextlib.suppress(sqlite3.Error, OSError):
                self._connect().execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                self._connect().commit()
            return None
        return value if isinstance(value, (list, dict)) else None

    def put(
        self,
        key: str,
        findings: list[dict[str, Any]] | dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> None:
        """Write findings (or a findings+errors envelope) through; never raises."""
        if not key or not isinstance(findings, (list, dict)):
            return
        try:
            payload = json.dumps(findings)
        except (TypeError, ValueError):
            return
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        ttl = ttl if ttl and ttl > 0 else None
        try:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO cache_entries(key, payload, created_at, ttl_seconds)"
                " VALUES (?, ?, ?, ?)",
                (key, payload, time.time(), ttl),
            )
            conn.commit()
        except (sqlite3.Error, OSError):
            return

    def close(self) -> None:
        """Close the underlying connection (safe to call twice)."""
        conn, self._conn = self._conn, None
        if conn is not None:
            with contextlib.suppress(sqlite3.Error):
                conn.close()

    def __enter__(self) -> FindingCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


_default_cache: FindingCache | None = None


def get_default_cache() -> FindingCache:
    """Lazy process-wide file cache (created on first tool call, not import)."""
    global _default_cache
    if _default_cache is None:
        _default_cache = FindingCache()
    return _default_cache


def reset_default_cache() -> None:
    """Drop the process-wide instance (tests only)."""
    global _default_cache
    if _default_cache is not None:
        _default_cache.close()
    _default_cache = None


def get(key: str) -> list[dict[str, Any]] | dict[str, Any] | None:
    """Hit the default file cache."""
    return get_default_cache().get(key)


def put(
    key: str,
    findings: list[dict[str, Any]] | dict[str, Any],
    ttl_seconds: float | None = None,
) -> None:
    """Write through to the default file cache."""
    get_default_cache().put(key, findings, ttl_seconds=ttl_seconds)
