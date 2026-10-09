// BravoGuard T7 specialist lane config (flat config, ESLint 10).
//
// Enables ONLY core security-adjacent rules — no plugins, zero extra deps,
// hermetic by design:
//
// - no-eval / no-implied-eval / no-new-func: dynamic code execution
//   (eval injection, CWE-95-adjacent; cwe stays empty in findings because
//   the core rule docs list no CWE — honesty over inference).
// - no-script-url: javascript: URLs (XSS-adjacent).
//
// DOCUMENTED CUTS (per T7 spec — do not expand without installer support):
//
// - eslint-plugin-security 4.2.0 EXISTS on the registry (verified via
//   `npm view eslint-plugin-security version`) but is CUT: it needs a second
//   npm package plus installer support, and the lane must run hermetically.
// - Hooks/Next/a11y scope CUT: each needs a heavy plugin dep
//   (eslint-plugin-react-hooks, @next/eslint-plugin-next,
//   eslint-plugin-jsx-a11y) with no installer support; pulling them trades a
//   hermetic lane for a dependency fan-out.
// - Type-aware rules CUT: they need project service / type information,
//   out of scope for a fast diff/repo lane (spec: STOP, do not expand).
//
// The orchestrator passes this file explicitly via
// `eslint --config <repo-root>/eslint.config.mjs` (flat-config discovery is
// CWD-relative and misses arbitrary targets — same rationale as oxlint
// `--config`). Re-verify read-only via `eslint --help` when the binary is
// present before changing lane flags.
export default [
  {
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
    },
  },
];
