# BRAVOGuard custom Semgrep rules (seed)

Seed rules live here. Phase 1 runs `semgrep --config rules/ --json` with `opengrep` as drop-in fallback (same YAML, same JSON/SARIF — covers Semgrep Dec 2024 relicense).

- `python/pickle-eval.yaml` — Python deserialization and code execution (CWE-502 → A08:2025 Software/Data Integrity Failures).
- `frontend/dangerous-html.yaml` — unsafe HTML sinks in React/Angular (CWE-79 → A05:2025 Injection).

Conventions:
- One rule per file, `id` prefixed with `bravoguard-`.
- Every rule sets `metadata.cwe`, `metadata.owasp_2025`, and `metadata.fix_hint` for the Normalizer/Enricher.
- Test each rule with a vulnerable + fixed fixture before adding to Phase 2 evals.
