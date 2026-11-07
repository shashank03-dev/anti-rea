# Benchmark results — eval set

Generated from `bench/runs/eval/results.jsonl` by `bench/score.mjs`. Frozen tool+harness sha256 `8921d50f945022ef968d1782e466e3b43e127839c983f08cbe633ebb172c2e60`. Node v26.11.1, darwin-arm64.

Tools: gitleaks `8.30.1`, trufflehog `trufflehog 3.99.8`, detect-secrets `1.5.0`.

## Release-decision accuracy

| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |
|---|---|---|---|---|---|---|---|
| AR-0 | 132/200 = 66.0% | [59.0, 72.5] | 20.0% | 48.0% | 0 | 217 | 123 |
| AR-1 | 172/200 = 86.0% | [80.4, 90.5] | 20.0% | 8.0% | 0 | 217 | 141 |
| AR-1o | 172/200 = 86.0% | [80.4, 90.5] | 0.0% | 28.0% | 0 | 217 | 142 |
| GL-D | 105/200 = 52.5% | [45.3, 59.6] | 18.0% | 77.0% | 0 | 12 | 190 |
| GL-T | 176/200 = 88.0% | [82.7, 92.2] | 10.0% | 14.0% | 0 | 18 | 242 |
| TH-D | 138/200 = 69.0% | [62.1, 75.3] | 10.0% | 52.0% | 0 | 35 | 589 |
| TH-T | 179/200 = 89.5% | [84.4, 93.4] | 10.0% | 11.0% | 0 | 35 | 564 |
| DS-D | 95/200 = 47.5% | [40.4, 54.7] | 30.0% | 75.0% | 0 | 94 | 557 |
| AR-2 | 170/200 = 85.0% | [79.3, 89.6] | 27.0% | 3.0% | 0 | 252 | 788 |

## Accuracy per family

| Family (truth) | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 80.0% | 100.0% |
| LEAK-DECLARED (block) | 100.0% | 100.0% | 100.0% | 35.0% | 80.0% | 65.0% | 80.0% | 30.0% | 100.0% |
| PUBLIC-DECLARED (pass) | 100.0% | 100.0% | 100.0% | 60.0% | 100.0% | 90.0% | 90.0% | 70.0% | 90.0% |
| SERVER-IMPL (block) | 0.0% | 100.0% | 100.0% | 0.0% | 100.0% | 5.0% | 100.0% | 15.0% | 100.0% |
| PRIVATE-ARTIFACT (block) | 0.0% | 100.0% | 100.0% | 10.0% | 80.0% | 25.0% | 100.0% | 15.0% | 100.0% |
| UNDECLARED-LEAK (block) | 60.0% | 60.0% | 60.0% | 70.0% | 95.0% | 85.0% | 85.0% | 50.0% | 85.0% |
| UNVERIFIABLE (block) | 100.0% | 100.0% | 0.0% | 0.0% | 75.0% | 60.0% | 80.0% | 15.0% | 100.0% |
| UNVERIFIABLE-CLEAN (pass) | 0.0% | 0.0% | 100.0% | 90.0% | 90.0% | 85.0% | 85.0% | 85.0% | 0.0% |
| EXAMPLE-DOCS (pass) | 100.0% | 100.0% | 100.0% | 60.0% | 60.0% | 80.0% | 80.0% | 25.0% | 80.0% |
| COMPRESSED-CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 95.0% | 95.0% | 90.0% | 95.0% |

## Paired comparisons (exact McNemar, two-sided)

| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |
|---|---|---|---|---|
| AR-1 vs GL-D | 89 | 22 | 33.5% | 9.63e-11 |
| AR-1 vs GL-T | 21 | 25 | -2.0% | 6.59e-1 |
| AR-1 vs TH-D | 56 | 22 | 17.0% | 1.49e-4 |
| AR-1 vs TH-T | 15 | 22 | -3.5% | 3.24e-1 |
| AR-1 vs DS-D | 98 | 21 | 38.5% | 4.40e-13 |
| AR-2 vs GL-D | 86 | 21 | 32.5% | 1.60e-10 |
| AR-2 vs GL-T | 18 | 24 | -3.0% | 4.41e-1 |
| AR-2 vs TH-D | 49 | 17 | 16.0% | 1.01e-4 |
| AR-2 vs TH-T | 8 | 17 | -4.5% | 1.08e-1 |
| AR-2 vs DS-D | 96 | 21 | 37.5% | 1.20e-12 |
| AR-1o vs GL-D | 71 | 4 | 33.5% | 6.81e-17 |
| AR-1o vs GL-T | 18 | 22 | -2.0% | 6.36e-1 |
| AR-1o vs TH-D | 51 | 17 | 17.0% | 4.45e-5 |
| AR-1o vs TH-T | 14 | 21 | -3.5% | 3.11e-1 |
| AR-1o vs DS-D | 84 | 7 | 38.5% | 7.12e-18 |

## Needle recall by wrapper

| Family / wrapper | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| LEAK-DECLARED / W1-plain | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| LEAK-DECLARED / W10-zst | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W11-deb | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W12-percent | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 3/4 | 2/4 | 4/4 |
| LEAK-DECLARED / W3-zip | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 1/3 | 3/3 | 0/3 | 3/3 |
| LEAK-DECLARED / W4-zip-in-asar | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W5-tgz | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W6-utf16-binary | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W7-base64 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W8-xz | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 2/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (INSIDE) | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| UNDECLARED-LEAK / W1-plain (NAMED-V2) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 | 0/3 | 3/3 |
| UNDECLARED-LEAK / W2-asar (NAMED-V2) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED) | 3/4 | 3/4 | 3/4 | 0/4 | 3/4 | 1/4 | 1/4 | 0/4 | 3/4 |
| UNDECLARED-LEAK / W3-zip (INSIDE) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED-V2) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNVERIFIABLE / W13-enc-zip | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |
| UNVERIFIABLE / W14-lz4 | 0/15 | 0/15 | 0/15 | 0/15 | 15/15 | 11/15 | 15/15 | 0/15 | 11/15 |

## Pre-registered hypotheses

- **H1: NOT SUPPORTED** — GL-D: Δ=33.5% p=9.63e-11 (need Δ≥15.0%, p<0.002); GL-T: Δ=-2.0% p=6.59e-1 (need Δ≥15.0%, p<0.002); TH-D: Δ=17.0% p=1.49e-4 (need Δ≥15.0%, p<0.002); TH-T: Δ=-3.5% p=3.24e-1 (need Δ≥15.0%, p<0.002); DS-D: Δ=38.5% p=4.40e-13 (need Δ≥15.0%, p<0.002)
- **H1b: NOT SUPPORTED** — GL-D: Δ=33.5% p=9.63e-11 (need Δ>0, p<0.01); GL-T: Δ=-2.0% p=6.59e-1 (need Δ>0, p<0.01); TH-D: Δ=17.0% p=1.49e-4 (need Δ>0, p<0.01); TH-T: Δ=-3.5% p=3.24e-1 (need Δ>0, p<0.01); DS-D: Δ=38.5% p=4.40e-13 (need Δ>0, p<0.01)
- **H2: NOT SUPPORTED** — AR-2 acc 85.0% vs AR-1 86.0%; UNDECLARED-LEAK false passes AR-2 3 vs AR-1 8
- **H3: SUPPORTED** — AR-1 silent passes on secrets inside uninspectable content: 0/20
- **H4 (expected loss): CONFIRMED (Anti-REA loses)** — correct decisions on undeclared unprefixed formats: AR-1 0/5, TH-T 2/5
- **H5 (expected loss): CONFIRMED (Anti-REA loses)** — false blocks on clean uninspectable content: AR-1 20/20, TH-D 3/20
- **H6 (v0.2 fixes): SUPPORTED** — COMPRESSED-CLEAN correct 20/20 (need ≥95%); LEAK-DECLARED via W7-base64/W8-xz/W9-bz2/W10-zst/W11-deb/W12-percent blocked with needle found 11/11 (need all)
- **H7 (structural rule generalises): NOT EVALUABLE** — held-out secret-marked prefixes blocked 0/0 (need ≥80%); held-out unmarked prefixes blocked 0/3 (predicted loss)
