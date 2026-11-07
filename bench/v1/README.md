# Benchmark v1 (sealed, run once on 2026-11-06)

This directory is the frozen record of the first pre-registered benchmark,
which evaluated Anti-REA **v0.1**. It holds the pre-registration, the
harness and scorer exactly as they ran, and the results.

- Verdict: H1 **not supported**. Tuned TruffleHog was better (93.9% vs 84.4%).
  See [docs/research/BENCHMARK-RESULTS.md](../../docs/research/BENCHMARK-RESULTS.md).
- The frozen hash `652f6a45…98c2` covers the v0.1 `src/` tree, which has
  since changed. These files are kept for the record. They cannot reproduce
  the run against the current source.
- The v2 benchmark, which evaluates v0.2, is in the parent directory with its
  own pre-registration, new seed and new families.
