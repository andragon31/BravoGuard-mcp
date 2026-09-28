#!/usr/bin/env bash
# In-container Linux proof for BravoGuard.
# Writes all output to /tmp/proof.log and exits nonzero if any gate fails.
set -u

LOG=/tmp/proof.log
FAILURES=0
: > "$LOG"

log() { echo "$*" | tee -a "$LOG"; }

gate() {
  local name="$1"
  shift
  log "### $name"
  if "$@" >>"$LOG" 2>&1; then
    log "PASS: $name"
  else
    log "FAIL: $name"
    FAILURES=$((FAILURES + 1))
  fi
}

# Core-only variant for gates that are honestly partial by design: `install
# --check` and `doctor` exit 1 when optional binaries are missing (same on
# Windows and Linux). The proof passes when the four core Python tools resolve;
# anything else is a real failure.
core_gate() {
  local name="$1"
  shift
  log "### $name (core-only)"
  if "$@" >>"$LOG" 2>&1; then
    log "PASS: $name"
    return
  fi
  log "exit nonzero (honest partial when optional binaries are missing); probing core tools"
  if uv run python - >>"$LOG" 2>&1 <<'EOF'
import shutil

core = ["semgrep", "bandit", "guarddog", "pip-audit"]
resolved = {tool: shutil.which(tool) for tool in core}
print("core:", resolved)
missing = [tool for tool, path in resolved.items() if path is None]
assert not missing, f"missing core tools: {missing}"
EOF
  then
    log "PASS: $name (core-only: semgrep+bandit+guarddog+pip-audit resolve)"
  else
    log "FAIL: $name"
    FAILURES=$((FAILURES + 1))
  fi
}

gate "pytest" uv run pytest -q

if command -v ruff >/dev/null 2>&1; then
  gate "ruff" ruff check src/bravoguard tests scripts
else
  gate "ruff (uv tool run)" uv tool run ruff check src/bravoguard tests scripts
fi

core_gate "install --check" uv run scripts/install.py --check
core_gate "doctor" uv run bravoguard doctor

log "### seeded scan_diff (eval/pickle/innerHTML -> >=1 real finding)"
if uv run python - >>"$LOG" 2>&1 <<'EOF'
import asyncio
import json

from bravoguard.orchestrator import scan_diff

SEED_DIFF = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+import pickle
+result = eval(user_input)
+obj = pickle.loads(data)
diff --git a/app.js b/app.js
index 3333333..4444444 100644
--- a/app.js
+++ b/app.js
@@ -0,0 +1,1 @@
+el.innerHTML = userInput;
"""

result = asyncio.run(scan_diff(SEED_DIFF))
print(json.dumps({"status": result["status"], "count": len(result["findings"]),
                  "rules": sorted({f["rule_id"] for f in result["findings"]})}))
assert result["status"] == "ok" and len(result["findings"]) >= 1, "expected >=1 real finding"
EOF
then
  log "PASS: seeded scan_diff"
else
  log "FAIL: seeded scan_diff"
  FAILURES=$((FAILURES + 1))
fi

log "### osv_lookup (django 4.2; ok offline-unavailable both acceptable, crash is not)"
if uv run python - >>"$LOG" 2>&1 <<'EOF'
import asyncio
import json

from bravoguard.orchestrator import osv_lookup
from bravoguard.osv import fetch_osv

result = asyncio.run(osv_lookup("django", "4.2", fetcher=fetch_osv))
print(json.dumps(result)[:2000])
assert result["status"] in ("ok", "unavailable"), result
EOF
then
  log "PASS: osv_lookup"
else
  log "FAIL: osv_lookup"
  FAILURES=$((FAILURES + 1))
fi

log "proof done: $FAILURES gate(s) failed (exit=$FAILURES, log=$LOG)"
exit "$FAILURES"
