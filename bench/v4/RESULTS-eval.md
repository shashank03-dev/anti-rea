# Benchmark results — eval set

Generated from `bench/runs/eval/results.jsonl` by `bench/score.mjs`. Frozen tool+harness sha256 `d261b18be86df483434431b659da310e4d4d6b92a481ebe1647f4b45c4660157`. Node v26.11.1, darwin-arm64.

Tools: gitleaks `8.30.1`, trufflehog `trufflehog 3.99.8`, detect-secrets `1.5.0`.

## Release-decision accuracy

| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |
|---|---|---|---|---|---|---|---|
| AR-0 | 164/240 = 68.3% | [62.0, 74.2] | 20.0% | 40.0% | 0 | 0 | 117 |
| AR-1 | 204/240 = 85.0% | [79.8, 89.3] | 20.0% | 11.4% | 0 | 0 | 126 |
| AR-1o | 204/240 = 85.0% | [79.8, 89.3] | 0.0% | 25.7% | 0 | 0 | 126 |
| GL-D | 107/240 = 44.6% | [38.2, 51.1] | 23.0% | 78.6% | 0 | 2 | 193 |
| GL-T | 180/240 = 75.0% | [69.0, 80.3] | 11.0% | 35.0% | 0 | 3 | 208 |
| TH-D | 149/240 = 62.1% | [55.6, 68.2] | 0.0% | 65.0% | 0 | 6 | 543 |
| TH-T | 196/240 = 81.7% | [76.2, 86.4] | 0.0% | 31.4% | 0 | 6 | 521 |
| DS-D | 120/240 = 50.0% | [43.5, 56.5] | 58.0% | 44.3% | 0 | 6349 | 731 |
| AR-2 | 208/240 = 86.7% | [81.7, 90.7] | 20.0% | 8.6% | 0 | 6 | 705 |

## Accuracy per family

| Family (truth) | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 40.0% | 100.0% |
| LEAK-DECLARED (block) | 100.0% | 100.0% | 100.0% | 15.0% | 90.0% | 50.0% | 90.0% | 60.0% | 100.0% |
| PUBLIC-DECLARED (pass) | 100.0% | 100.0% | 100.0% | 40.0% | 100.0% | 100.0% | 100.0% | 45.0% | 100.0% |
| SERVER-IMPL (block) | 0.0% | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 100.0% | 55.0% | 100.0% |
| PRIVATE-ARTIFACT (block) | 0.0% | 100.0% | 100.0% | 0.0% | 65.0% | 5.0% | 100.0% | 65.0% | 100.0% |
| UNDECLARED-LEAK (block) | 73.3% | 73.3% | 73.3% | 45.0% | 66.7% | 61.7% | 61.7% | 53.3% | 80.0% |
| UNVERIFIABLE (block) | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 5.0% | 5.0% | 50.0% | 100.0% |
| UNVERIFIABLE-CLEAN (pass) | 0.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 45.0% | 0.0% |
| EXAMPLE-DOCS (pass) | 100.0% | 100.0% | 100.0% | 45.0% | 45.0% | 100.0% | 100.0% | 35.0% | 100.0% |
| COMPRESSED-CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 45.0% | 100.0% |

## Paired comparisons (exact McNemar, two-sided)

| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |
|---|---|---|---|---|
| AR-1 vs GL-D | 120 | 23 | 40.4% | 4.92e-17 |
| AR-1 vs GL-T | 47 | 23 | 10.0% | 5.58e-3 |
| AR-1 vs TH-D | 79 | 24 | 22.9% | 4.98e-8 |
| AR-1 vs TH-T | 32 | 24 | 3.3% | 3.50e-1 |
| AR-1 vs DS-D | 99 | 15 | 35.0% | 2.36e-16 |
| AR-2 vs GL-D | 124 | 23 | 42.1% | 6.08e-18 |
| AR-2 vs GL-T | 51 | 23 | 11.7% | 1.52e-3 |
| AR-2 vs TH-D | 79 | 20 | 24.6% | 1.79e-9 |
| AR-2 vs TH-T | 32 | 20 | 5.0% | 1.26e-1 |
| AR-2 vs DS-D | 101 | 13 | 36.7% | 4.77e-18 |
| AR-1o vs GL-D | 100 | 3 | 40.4% | 3.59e-26 |
| AR-1o vs GL-T | 27 | 3 | 10.0% | 8.43e-6 |
| AR-1o vs TH-D | 60 | 5 | 22.9% | 4.87e-13 |
| AR-1o vs TH-T | 13 | 5 | 3.3% | 9.63e-2 |
| AR-1o vs DS-D | 100 | 16 | 35.0% | 4.96e-16 |

## Needle recall by wrapper

| Family / wrapper | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| LEAK-DECLARED / W10-zst | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W11-deb | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W14-lz4 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W15-zip-bzip2 | 4/4 | 4/4 | 4/4 | 0/4 | 4/4 | 3/4 | 4/4 | 0/4 | 4/4 |
| LEAK-DECLARED / W2-asar | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 |
| LEAK-DECLARED / W3-zip | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 0/3 | 3/3 | 0/3 | 3/3 |
| LEAK-DECLARED / W5-tgz | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 1/3 | 3/3 | 0/3 | 3/3 |
| LEAK-DECLARED / W8-xz | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W9-bz2 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, bare) | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, ctor) | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, env) | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 0/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, bare) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, ctor) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W1-plain (INSIDE, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (INSIDE, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (INSIDE, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (INSIDE, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, bare) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, ctor) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, env) | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, method) | 1/2 | 1/2 | 1/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 1/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, bare) | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, method) | 2/3 | 2/3 | 2/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 2/3 |
| UNDECLARED-LEAK / W2-asar (INSIDE, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, method) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (NAMED, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, config) | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 | 2/3 | 2/3 | 1/3 | 3/3 |
| UNDECLARED-LEAK / W2-asar (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, bare) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, config) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, ctor) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, env) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, method) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, config) | 2/2 | 2/2 | 2/2 | 0/2 | 1/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, ctor) | 1/2 | 1/2 | 1/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 1/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, env) | 1/2 | 1/2 | 1/2 | 0/2 | 1/2 | 0/2 | 0/2 | 0/2 | 1/2 |
| UNDECLARED-LEAK / W3-zip (INSIDE, bare) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (INSIDE, config) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (INSIDE, ctor) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, bare) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, env) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, method) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNVERIFIABLE / W13-enc-zip | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 | 0/11 |
| UNVERIFIABLE / W16-dmg | 0/9 | 0/9 | 0/9 | 0/9 | 0/9 | 0/9 | 0/9 | 0/9 | 0/9 |

## UNDECLARED-LEAK by stratum × render style (correct / n)

| Stratum / style | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| INSIDE / env | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| INSIDE / config | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| INSIDE / ctor | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| INSIDE / method | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| INSIDE / bare | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 |
| NAMED / env | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 2/3 | 2/3 | 2/3 | 3/3 |
| NAMED / config | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 | 3/3 | 3/3 | 1/3 | 3/3 |
| NAMED / ctor | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 2/3 | 2/3 | 3/3 | 3/3 |
| NAMED / method | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| NAMED / bare | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| HELDOUT-PREFIXED / env | 1/3 | 1/3 | 1/3 | 2/3 | 3/3 | 1/3 | 1/3 | 2/3 | 1/3 |
| HELDOUT-PREFIXED / config | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 0/3 | 0/3 | 1/3 | 3/3 |
| HELDOUT-PREFIXED / ctor | 1/3 | 1/3 | 1/3 | 0/3 | 0/3 | 2/3 | 2/3 | 2/3 | 2/3 |
| HELDOUT-PREFIXED / method | 1/3 | 1/3 | 1/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 1/3 |
| HELDOUT-PREFIXED / bare | 0/3 | 0/3 | 0/3 | 1/3 | 1/3 | 0/3 | 0/3 | 2/3 | 0/3 |
| HELDOUT-UNPREFIXED / env | 2/3 | 2/3 | 2/3 | 1/3 | 2/3 | 0/3 | 0/3 | 0/3 | 2/3 |
| HELDOUT-UNPREFIXED / config | 3/3 | 3/3 | 3/3 | 1/3 | 2/3 | 3/3 | 3/3 | 2/3 | 3/3 |
| HELDOUT-UNPREFIXED / ctor | 1/3 | 1/3 | 1/3 | 0/3 | 0/3 | 0/3 | 0/3 | 1/3 | 1/3 |
| HELDOUT-UNPREFIXED / method | 2/3 | 2/3 | 2/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 2/3 |
| HELDOUT-UNPREFIXED / bare | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 | 3/3 | 1/3 | 3/3 |

## Pre-registered hypotheses

- **H1: NOT SUPPORTED** — GL-D: Δ=40.4% p=4.92e-17 (need Δ≥15.0%, p<0.002); GL-T: Δ=10.0% p=5.58e-3 (need Δ≥15.0%, p<0.002); TH-D: Δ=22.9% p=4.98e-8 (need Δ≥15.0%, p<0.002); TH-T: Δ=3.3% p=3.50e-1 (need Δ≥15.0%, p<0.002); DS-D: Δ=35.0% p=2.36e-16 (need Δ≥15.0%, p<0.002)
- **H1b: NOT SUPPORTED** — GL-D: Δ=40.4% p=4.92e-17 (need Δ>0, p<0.01); GL-T: Δ=10.0% p=5.58e-3 (need Δ>0, p<0.01); TH-D: Δ=22.9% p=4.98e-8 (need Δ>0, p<0.01); TH-T: Δ=3.3% p=3.50e-1 (need Δ>0, p<0.01); DS-D: Δ=35.0% p=2.36e-16 (need Δ>0, p<0.01)
- **H2: SUPPORTED** — AR-2 acc 86.7% vs AR-1 85.0%; UNDECLARED-LEAK false passes AR-2 12 vs AR-1 16
- **H3: SUPPORTED** — AR-1 silent passes on secrets inside uninspectable content: 0/20
- **H5 (expected loss): CONFIRMED (Anti-REA loses)** — false blocks on clean uninspectable content: AR-1 20/20, TH-D 0/20
- **H4 (keyed detector generalises): SUPPORTED** — held-out unprefixed, env/config style: blocked 5/6 (need ≥80%)
- **H4c (call styles): NOT SUPPORTED** — held-out formats, ctor/method style: blocked 5/12 (need ≥50%); bare style (no credential signal, predicted loss, not scored): blocked 0/6
- **H6 (decoders): SUPPORTED** — COMPRESSED-CLEAN correct 20/20 (need ≥95%); LEAK-DECLARED via W7-base64/W8-xz/W9-bz2/W10-zst/W11-deb/W12-percent/W14-lz4/W15-zip-bzip2 blocked with needle found 11/11 (need all)
- **H7 (held-out secret-marked prefixes): NOT SUPPORTED** — secret-marked prefixes blocked 2/5 across all styles (need ≥80%); unmarked prefixes blocked 4/10
- **H8 (noise): SUPPORTED** — AR-1 spurious findings: 0 (need ≤20)
- **H9 (undeclared leaks): SUPPORTED** — UNDECLARED-LEAK correct: AR-1 44, TH-T 37, GL-T 40 of 60 (need AR-1 ≥ TH-T)
- **H9b (undeclared leaks, significance): NOT SUPPORTED** — AR-1 vs TH-T on UNDECLARED-LEAK: 11 : 4 discordant, exact McNemar p=1.18e-1 (need AR-1 ahead and p<0.05)
- **H10 (secondary: AR-1o vs TH-T): NOT SUPPORTED** — AR-1o (uninspectable content warns) vs TH-T: Δ=3.3%, 13 : 5, p=9.63e-2 (need Δ>0, p<0.01)
