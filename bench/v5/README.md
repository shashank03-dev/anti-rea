# Benchmark v5 (sealed, run once on 2026-11-07)

This directory is the frozen record of the fifth pre-registered benchmark, which evaluated Anti-REA **v0.5**. It holds the pre-registration and the harness as they ran, plus the results. Run outputs are in `bench/runs/v5-dev` and `bench/runs/v5-eval`.

- **Verdict:**
  - AR-1 scored 89.2%, AR-2 91.2%, tuned TruffleHog 80.8% and tuned gitleaks 75.4%.
  - H1c is supported: AR-2 is significantly better than every baseline.
  - H1b is not supported (AR-1 vs TH-T: p = 0.013 against the p < 0.01 bar).
  - H1 (Δ ≥ 15 points) is not supported.
  - See [docs/research/BENCHMARK-RESULTS.md](../../docs/research/BENCHMARK-RESULTS.md).
- **Frozen hash:** `88f2bb1e…eb7d`.
- **`anti-rea-0.5.0/`** is the compiled v0.5 tool as evaluated.
  - It was rebuilt after the run from v0.5 source. That source was reconstructed by reversing the v0.6 edits. Its frozen hash (`src`, harness and `package.json`) equals the pre-registered `88f2bb1e…eb7d` exactly.
  - Re-running it on the v5 eval corpus reproduces all **260/260** recorded AR-1 decisions.
  - Later benchmarks run it as a same-corpus regression baseline.
- The harness files here were copied before any v6 edit, so `freeze.mjs`'s INCLUDE list still points at the v5 paths.
