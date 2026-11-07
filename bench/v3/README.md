# Benchmark v3 (sealed, run once on 2026-11-06)

This directory is the frozen record of the third pre-registered benchmark, which evaluated Anti-REA **v0.3**. It holds the pre-registration and the harness as they ran, plus the results. Run outputs are in `bench/runs/v3-dev` and `bench/runs/v3-eval`.

- **Verdict:** H1 and H1b not supported. AR-1 scored 90.0%, the highest measured, against tuned TruffleHog's 84.5% (p = 0.16) and tuned gitleaks' 77.5% (p = 0.002). All 20 AR-1 errors were the fail-closed policy on clean encrypted zips and DMGs. See [docs/research/BENCHMARK-RESULTS.md](../../docs/research/BENCHMARK-RESULTS.md).
- **Frozen hash:** `363c69c6…f6ee`. It covers the v0.3 `src/` tree, which has since changed, so these files cannot reproduce the run against the current source.
