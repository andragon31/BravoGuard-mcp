# BRAVOGuard custom Semgrep rules (seed)

Seed rules live here. Phase 1 runs `semgrep --config rules/ --json` with `opengrep` as drop-in fallback (same YAML, same JSON/SARIF — covers Semgrep Dec 2024 relicense).

- `python/pickle-eval.yaml` — Python deserialization and code execution (CWE-502 → A08:2025 Software/Data Integrity Failures).
- `frontend/dangerous-html.yaml` — unsafe HTML sinks in React/Angular (CWE-79 → A05:2025 Injection).
- `supply-chain/install-exec.yaml` — shell/subprocess execution in setup.py (CWE-506 → A08:2025).
- `supply-chain/exfil.yaml` — network transmission primitives in setup.py (CWE-200 → A01:2025).
- `supply-chain/obfuscated-payload.yaml` — decode-and-execute of base64/hex/marshal blobs (CWE-506 → A08:2025).
- `supply-chain/remote-download.yaml` — install-time remote download without integrity check (CWE-494 → A08:2025).

Conventions:
- One rule per file, `id` prefixed with `bravoguard-`.
- Every rule sets `metadata.cwe`, `metadata.owasp_2025`, and `metadata.fix_hint` for the Normalizer/Enricher.
- Test each rule with a vulnerable + fixed fixture before adding to Phase 2 evals.
