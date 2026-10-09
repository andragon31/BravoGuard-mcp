# Feature: bravoguard-py-js-containers

Objective: Scope BravoGuard to Python + JavaScript/TypeScript + containers (Docker/Podman); add explicit per-language detection and lane routing; close the documented-vs-wired gap; add Py/JS depth lanes and a containers lane with recommendations.
Problem: Lanes run unconditionally (each engine self-filters); semgrep runs only 6 own rules; TruffleHog/Grype/Syft/GuardDog documented but not wired; no JS lint in diffs; no container best-practice lane; epss/kev/reachability fields never populated; PRD Phase 3 (policy gates, baseline, redact) unstarted.
Why: User scoped the MCP to the project's real stacks (Python + JS/TS + Docker/Podman) and required language-detected routing to the correct MCP functions, plus container structure analysis with improvement recommendations.
Scope:
- `src/bravoguard/languages.py` (new: detect_languages, markers + suffix census, suffix-gated vs manifest-gated classification)
- `src/bravoguard/orchestrator.py` (route scan_diff per-file by suffix; scan_repo by detection; lane `skipped+reason` in responses)
- `src/bravoguard/server.py` (response contract: `languages{}`, lane statuses; new flags: `verify_secrets`, image lane opt-in)
- New lanes + normalizers: ruff (no-S), vulture, deptry, oxlint-in-diff, eslint+security, knip, lockfile-lint, npm audit, hadolint (+DL->CWE map), kics (compose/dockerfile only), dockle/dive (opt-in, `recommendations[]`), trufflehog verify, syft store + grype
- `src/bravoguard/enrich.py` (new: EPSS FIRST API + CISA KEV weekly cache join by CVE)
- `src/bravoguard/osv.py` (HTTP-first fetcher, binary fallback)
- `rules/` growth (JWT none, CORS wildcard, SSRF, yaml.load, random-vs-secrets; each with vuln+fixed fixture)
- `policy/` (conftest Rego deny/warn) + baseline/redact params
- `tools-manifest.json` pins + `scripts/install.py` / `scripts/install_external.py` with every new binary; `.oxlintrc.json` (suspicious->warn); trivy `+license`; semgrep python/frontend rule split by suffix
- tests (+fixtures under `tests/fixtures/`), `CHANGELOG.md`, docs (`README.md`, `docs/ARCHITECTURE.md`)
Constraints:
- No lane runs outside its detected language; every skip reports `reason` (never silent).
- Manifest-gated lanes (deptry, knip, lockfile-lint, npm/pip audit, typosquat) never run without their manifest/lockfile.
- Ruff runs WITHOUT S rules (bandit owns security; verified overlap via Context7). oxlint correctness+suspicious via config, no new binary for that.
- No auto-build of container images; dockle/dive only with existing image/tar or explicit flag. `recommendations[]` stays separate from `findings[]`.
- Tests never invoke real binaries (mocked subprocess); smoke test without binaries stays green. No community semgrep registry (relicense risk) — own pack only.
- Out-of-scope languages (go.mod, Cargo.toml, Gemfile, ...) reported as detected-but-unsupported, never faked.
- Single-threaded writes; one worker at a time; work-unit commits on the feature branch. Push/PR/merge are user decisions.
Authorized scope: Write only BravoGuard-mcp on branch `feature/bravoguard-py-js-containers`. Isolated tool installs for live proof allowed (hadolint/dockle/dive/kics binaries). Work-unit commits authorized. Push/PR deferred.
Acceptance criteria:
- [ ] scan_diff routes .py->Python lanes, .js/.ts/.tsx->JS lanes, Dockerfile->hadolint; foreign lanes report skipped+reason
- [ ] scan_repo on py-only/js-only/mixed/container repos runs exactly the applicable lanes (seeded fixture repos per stack)
- [ ] `uv run pytest -q` green + ruff clean at every work-unit commit
- [ ] Every new binary pinned in tools-manifest.json + installer verifies it
- [ ] Seeded vuln per new lane maps to a CWE-mapped finding (or recommendation for dive/efficiency)
Applicable checks: `.venv/bin/python -m pytest -q`, `uv run ruff check src/bravoguard tests scripts` (or .venv equivalent).
TDD: on for runners/normalizers (RED with recorded JSON fixtures -> GREEN -> refactor). Off only for pure-config changes (state why per task).
Delivery: `ask-on-risk`. Work-unit commits; PR N/A until user asks.
Review: native review per work-unit candidate per user-owned RDD switch (inspect before START, once per candidate).

## Tasks
- [x] T0 (parent inline): tracking setup — feature doc + Engram mirror (id 227) + visible todos + branch `feature/bravoguard-py-js-containers`. DONE.
- [x] T1 (Fase 0.1): detect_languages + routing + skipped+reason contract. DONE commit `45c6c0c` (21 files, +1024/-24). Suite 296 passed + 10 skipped, ruff clean. Native review lineage `review-e631ae04200f1822`: approved + acknowledged (authority burned). 3 non-blocking advisories filed as later work: R3-bounded-census (languages.py:80), R3-exclude-routing (orchestrator.py:1304), R3-stat-robustness (languages.py:90). Surfaces were: src/bravoguard/languages.py (new), src/bravoguard/orchestrator.py, tests/test_languages.py (new) + fixtures.
- [x] T2 (Fase 0.2): free config — .oxlintrc.json (suspicious warn), trivy +license, semgrep python/frontend split by suffix. DONE commit `a703525`. Suite 312 passed + 10 skipped, ruff clean. Native review lineage `review-5272061c1aa97ebf`: approved + acknowledged. First capture refused at admission (foreign inspection paths) — relaunched the exact reoffered slot, admitted on retry. 2 non-blocking advisories (reliability: languages census area, orchestrator split area). Surfaces were: .oxlintrc.json (new), orchestrator.py, normalizer.py, tests/test_config.py (new, 16 tests) + fixtures.
- [x] T3 (Fase 1.1): TruffleHog verify lane (opt-in) + normalize_trufflehog. DONE commit `76e6530`. Suite 322 passed + 10 skipped, ruff clean. Native review lineage `review-317951556f419b19`: approved + acknowledged. 2 non-blocking advisories: R3-001 (orchestrator.py:1), R3-002 (test_secrets.py:1). T3 conflict note: worker stopped on 4 frozen T1 asserts (opt-out skipped entry); parent updated them inline (same precedent as T1/T2). Capture lesson: hand-transcribed bindings corrupt long hashes — use machine-to-machine passing via codemode (top-level `collectBindings`, NOT under `result`) for all future captures.
- [ ] T4 (Fase 1.2): Syft SBOM store + Grype lane + CVE secondary dedup. Surfaces: orchestrator.py, normalizer.py, cache.py, tests + fixtures.
- [x] T4 (Fase 1.2): Syft SBOM store + Grype lane + CVE secondary dedup. DONE commit `b75a29d`. Suite 348 passed + 10 skipped, ruff clean. Native review lineage `review-9cd9474f8ac2813a`: approved clean (no advisories) + acknowledged. 5 frozen T1 asserts updated inline by parent (syft/grype skips). Surfaces were: cache.py, languages.py, normalizer.py, orchestrator.py, tests/test_sbom.py (new, 26 tests) + fixtures.
- [x] T5 (Fase 1.3): GuardDog Linux lane (win32 skip with reason). DONE commit `505cae2`. Suite 367 passed + 10 skipped, ruff clean. 5 frozen T1 asserts updated inline by parent (guarddog skips). NATIVE REVIEW DEFERRED (not declined): branch-cumulative candidate exceeds lens context budget (`lens_context_budget_exceeded`, no lineage created); slice-scoped START systematically rejected (`retained-selection-candidate-mismatch` x2 with fresh inspect between). User decision pending: continue functional-only vs disable switch vs restructure. Functional verification stands (19 new tests green + full suite + ruff). Surfaces were: orchestrator.py, normalizer.py, languages.py, tests/test_guarddog.py (new, 19 tests) + fixtures.
- [x] T6 (Fase 2): Python lanes — ruff (no-S), vulture, deptry (manifest-gated). DONE commit `4370f23`. Suite 398 passed + 10 skipped, ruff clean. 18 frozen asserts updated inline by parent (shared fakes now force ruff/vulture/deptry missing -> hermetic skips on every machine; ruff-installed dev boxes no longer diverge). Native review deferred under the same standing T5 decision (cumulative candidate over budget). Surfaces were: orchestrator.py, normalizer.py, languages.py, cli.py, scripts/install.py, scripts/install_external.py, tests/test_python_lanes.py (new, 31 tests) + fixtures.
- [x] T7 (Fase 3): JS lanes — oxlint in scan_diff, eslint+security runner+config, knip, lockfile-lint, npm audit (manifest-gated). DONE commit `47e16b9`. Suite 431 passed + 10 skipped, ruff clean. 11 frozen asserts updated inline by parent (T7 skips; oxlint-diff pre-check forced missing in shared fake for hermeticity). Native review deferred under the standing T5 decision. Surfaces were: orchestrator.py, normalizer.py, languages.py, eslint.config.mjs (new, core-rules cut documented), tools-manifest.json, scripts/install.py, scripts/install_external.py, tests/test_js_lanes.py (new, 33 tests) + fixtures.
- [x] T8 (Fase 4): containers — hadolint + DL->CWE map + fix templates, kics (compose/dockerfile only), dockle/dive opt-in + recommendations[]. DONE commits `d67f6a8` (T7 forcing leftover) + `4a47371`. Suite 474 passed + 10 skipped, ruff clean. 13 frozen asserts updated inline by parent (T8 skips; hadolint/kics forced missing in shared fake). Live-verified pins: hadolint v2.15.1, kics v2.2.0 (go-leg, zero assets), dockle v0.4.15, dive v0.13.1. Native review deferred under the standing T5 decision. Surfaces were: orchestrator.py, normalizer.py, languages.py, suggest.py, server.py, tools-manifest.json, scripts/install*.py, tests/test_containers.py (new, 43 tests) + fixtures.
- [ ] T9 (Fase 5): enrich.py (EPSS+KEV) + osv_lookup HTTP-first. Surfaces: src/bravoguard/enrich.py (new), osv.py, orchestrator.py, tests (mocked network).
- [ ] T10 (Fase 6): rule-pack growth (5+ rules, each vuln+fixed fixture) + conftest policy/ + baseline/redact. Surfaces: rules/, policy/ (new), orchestrator.py, server.py, tests.

## Progress
- Branch `feature/bravoguard-py-js-containers` from master `21051ce`. Base: 269 passed, 10 skipped.
- T0 done. T1 done (45c6c0c, review ok). T2 done (a703525, review ok). T3 done (76e6530, review ok). T4 done (b75a29d, review ok clean). T5 done (505cae2, functional ok, review deferred). T6 done (4370f23, functional ok, review deferred — same standing decision). T7 delegated.

## Verification evidence
- Per task `<command>: <observed result>`; parent spot-checks one check per delegated task.

## Route declaration
- T0 parent inline (tracking only, no source writes).
- T1+ delegated one worker at a time (multi-file write trigger); verifier for full suites.
- No SDD artifacts.
