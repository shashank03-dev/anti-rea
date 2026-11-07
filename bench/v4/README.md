# Benchmark v4 (sealed, run once on 2026-11-07)

This directory is the frozen record of the fourth pre-registered benchmark, which evaluated Anti-REA **v0.4**. It holds the pre-registration and the harness as they ran, plus the results. Run outputs are in `bench/runs/v4-dev` and `bench/runs/v4-eval`.

- **Verdict:** H1 and H1b not supported. AR-1 scored 85.0%, against tuned TruffleHog's 81.7% (p = 0.35) and tuned gitleaks' 75.0% (p = 0.006). AR-2 scored 86.7%. See [docs/research/BENCHMARK-RESULTS.md](../../docs/research/BENCHMARK-RESULTS.md).
- **Frozen hash:** `d261b18b…0157`.
- **`anti-rea-0.4.0/`** is the compiled v0.4 tool exactly as evaluated (`build/src` at the frozen hash). Later benchmarks run it as a same-corpus regression baseline.
