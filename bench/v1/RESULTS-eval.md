# Benchmark results — eval set

Generated from `bench/runs/eval/results.jsonl` by `bench/score.mjs`. Frozen tool+harness sha256 `652f6a4585a8288856467ab20030778bbf69b02cf26c4aca7d5180256c1898c2`. Node v26.11.1, darwin-arm64.

Tools: gitleaks `8.30.1`, trufflehog `trufflehog 3.99.8`, detect-secrets `1.5.0`.

## Release-decision accuracy

| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |
|---|---|---|---|---|---|---|---|
| AR-0 | 110/180 = 61.1% | [53.6, 68.3] | 25.0% | 50.0% | 0 | 0 | 91 |
| AR-1 | 152/180 = 84.4% | [78.3, 89.4] | 25.0% | 8.0% | 0 | 0 | 107 |
| GL-D | 74/180 = 41.1% | [33.8, 48.7] | 30.0% | 82.0% | 0 | 9 | 271 |
| GL-T | 150/180 = 83.3% | [77.1, 88.5] | 21.3% | 13.0% | 0 | 12 | 264 |
| TH-D | 127/180 = 70.6% | [63.3, 77.1] | 7.5% | 47.0% | 0 | 14 | 591 |
| TH-T | 169/180 = 93.9% | [89.3, 96.9] | 7.5% | 5.0% | 0 | 14 | 663 |
| DS-D | 70/180 = 38.9% | [31.7, 46.4] | 30.0% | 86.0% | 0 | 53 | 625 |
| AR-2 | 154/180 = 85.6% | [79.6, 90.3] | 30.0% | 2.0% | 0 | 14 | 741 |

## Accuracy per family

| Family (truth) | AR-0 | AR-1 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|
| CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 95.0% | 100.0% |
| LEAK-DECLARED (block) | 85.0% | 95.0% | 20.0% | 65.0% | 75.0% | 85.0% | 15.0% | 100.0% |
| PUBLIC-DECLARED (pass) | 100.0% | 100.0% | 60.0% | 95.0% | 90.0% | 90.0% | 35.0% | 90.0% |
| SERVER-IMPL (block) | 0.0% | 100.0% | 0.0% | 100.0% | 15.0% | 100.0% | 10.0% | 100.0% |
| PRIVATE-ARTIFACT (block) | 0.0% | 100.0% | 0.0% | 70.0% | 0.0% | 100.0% | 10.0% | 100.0% |
| UNDECLARED-LEAK (block) | 65.0% | 65.0% | 65.0% | 100.0% | 90.0% | 90.0% | 20.0% | 90.0% |
| UNVERIFIABLE (block) | 100.0% | 100.0% | 5.0% | 100.0% | 85.0% | 100.0% | 15.0% | 100.0% |
| UNVERIFIABLE-CLEAN (pass) | 0.0% | 0.0% | 90.0% | 90.0% | 90.0% | 90.0% | 90.0% | 0.0% |
| EXAMPLE-DOCS (pass) | 100.0% | 100.0% | 30.0% | 30.0% | 90.0% | 90.0% | 60.0% | 90.0% |

## Paired comparisons (exact McNemar, two-sided)

| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |
|---|---|---|---|---|
| AR-1 vs GL-D | 102 | 24 | 43.3% | 1.21e-12 |
| AR-1 vs GL-T | 28 | 26 | 1.1% | 8.92e-1 |
| AR-1 vs TH-D | 49 | 24 | 13.9% | 4.63e-3 |
| AR-1 vs TH-T | 7 | 24 | -9.4% | 3.33e-3 |
| AR-1 vs DS-D | 102 | 20 | 45.6% | 1.96e-14 |
| AR-2 vs GL-D | 99 | 19 | 44.4% | 3.06e-14 |
| AR-2 vs GL-T | 25 | 21 | 2.2% | 6.59e-1 |
| AR-2 vs TH-D | 45 | 18 | 15.0% | 8.98e-4 |
| AR-2 vs TH-T | 3 | 18 | -8.3% | 1.49e-3 |
| AR-2 vs DS-D | 104 | 20 | 46.7% | 6.96e-15 |

## Needle recall by wrapper

| Family / wrapper | AR-0 | AR-1 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|
| LEAK-DECLARED / W1-plain | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| LEAK-DECLARED / W2-asar | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W3-zip | 6/6 | 6/6 | 0/6 | 6/6 | 5/6 | 6/6 | 0/6 | 6/6 |
| LEAK-DECLARED / W4-zip-in-asar | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W5-tgz | 3/3 | 3/3 | 0/3 | 3/3 | 2/3 | 3/3 | 0/3 | 3/3 |
| LEAK-DECLARED / W6-utf16-binary | 5/5 | 5/5 | 0/5 | 0/5 | 2/5 | 2/5 | 0/5 | 5/5 |
| LEAK-DECLARED / W7-base64 | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (inside AR detectors) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (outside AR detectors) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 |
| UNDECLARED-LEAK / W2-asar (inside AR detectors) | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 0/6 | 6/6 |
| UNDECLARED-LEAK / W2-asar (outside AR detectors) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (inside AR detectors) | 5/5 | 5/5 | 0/5 | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 |
| UNDECLARED-LEAK / W3-zip (outside AR detectors) | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| UNVERIFIABLE / W8-xz | 0/20 | 0/20 | 0/20 | 20/20 | 16/20 | 20/20 | 0/20 | 16/20 |

## Pre-registered hypotheses

- **H1: NOT SUPPORTED** — GL-D: Δ=43.3% p=1.21e-12 (need Δ≥15.0%, p<0.002); GL-T: Δ=1.1% p=8.92e-1 (need Δ≥15.0%, p<0.002); TH-D: Δ=13.9% p=4.63e-3 (need Δ≥15.0%, p<0.002); TH-T: Δ=-9.4% p=3.33e-3 (need Δ≥15.0%, p<0.002); DS-D: Δ=45.6% p=1.96e-14 (need Δ≥15.0%, p<0.002)
- **H2: SUPPORTED** — AR-2 acc 85.6% vs AR-1 84.4%; UNDECLARED-LEAK false passes AR-2 2 vs AR-1 7
- **H3: SUPPORTED** — AR-1 silent passes on secrets inside unsupported content: 0
- **H4 (expected loss): NOT CONFIRMED** — recall on undeclared formats outside AR detectors: AR-1 7/7, TH-D 5/7
- **H5 (expected loss): CONFIRMED (Anti-REA loses)** — false blocks on clean undecodable content: AR-1 20/20, TH-D 2/20
