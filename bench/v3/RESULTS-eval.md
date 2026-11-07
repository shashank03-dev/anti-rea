# Benchmark results — eval set

Generated from `bench/runs/eval/results.jsonl` by `bench/score.mjs`. Frozen tool+harness sha256 `363c69c654472e16fb8daf65f1a5695b557809dbd5d0a4f0f9b6c6c8d7e7f6ee`. Node v26.11.1, darwin-arm64.

Tools: gitleaks `8.30.1`, trufflehog `trufflehog 3.99.8`, detect-secrets `1.5.0`.

## Release-decision accuracy

| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |
|---|---|---|---|---|---|---|---|
| AR-0 | 140/200 = 70.0% | [63.1, 76.3] | 20.0% | 40.0% | 0 | 0 | 132 |
| AR-1 | 180/200 = 90.0% | [85.0, 93.8] | 20.0% | 0.0% | 0 | 0 | 155 |
| AR-1o | 180/200 = 90.0% | [85.0, 93.8] | 0.0% | 20.0% | 0 | 0 | 158 |
| GL-D | 104/200 = 52.0% | [44.8, 59.1] | 28.0% | 68.0% | 0 | 42 | 219 |
| GL-T | 155/200 = 77.5% | [71.1, 83.1] | 20.0% | 25.0% | 0 | 55 | 250 |
| TH-D | 127/200 = 63.5% | [56.4, 70.2] | 0.0% | 73.0% | 0 | 1 | 543 |
| TH-T | 169/200 = 84.5% | [78.7, 89.2] | 0.0% | 31.0% | 0 | 1 | 564 |
| DS-D | 100/200 = 50.0% | [42.9, 57.1] | 45.0% | 55.0% | 0 | 197 | 608 |
| AR-2 | 180/200 = 90.0% | [85.0, 93.8] | 20.0% | 0.0% | 0 | 1 | 723 |

## Accuracy per family

| Family (truth) | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| CLEAN (pass) | 100.0% | 100.0% | 100.0% | 90.0% | 90.0% | 100.0% | 100.0% | 65.0% | 100.0% |
| LEAK-DECLARED (block) | 100.0% | 100.0% | 100.0% | 40.0% | 85.0% | 75.0% | 85.0% | 45.0% | 100.0% |
| PUBLIC-DECLARED (pass) | 100.0% | 100.0% | 100.0% | 35.0% | 80.0% | 100.0% | 100.0% | 40.0% | 100.0% |
| SERVER-IMPL (block) | 0.0% | 100.0% | 100.0% | 20.0% | 100.0% | 0.0% | 100.0% | 50.0% | 100.0% |
| PRIVATE-ARTIFACT (block) | 0.0% | 100.0% | 100.0% | 20.0% | 70.0% | 0.0% | 100.0% | 55.0% | 100.0% |
| UNDECLARED-LEAK (block) | 100.0% | 100.0% | 100.0% | 65.0% | 100.0% | 60.0% | 60.0% | 40.0% | 100.0% |
| UNVERIFIABLE (block) | 100.0% | 100.0% | 0.0% | 15.0% | 20.0% | 0.0% | 0.0% | 35.0% | 100.0% |
| UNVERIFIABLE-CLEAN (pass) | 0.0% | 0.0% | 100.0% | 95.0% | 90.0% | 100.0% | 100.0% | 60.0% | 0.0% |
| EXAMPLE-DOCS (pass) | 100.0% | 100.0% | 100.0% | 45.0% | 45.0% | 100.0% | 100.0% | 35.0% | 100.0% |
| COMPRESSED-CLEAN (pass) | 100.0% | 100.0% | 100.0% | 95.0% | 95.0% | 100.0% | 100.0% | 75.0% | 100.0% |

## Paired comparisons (exact McNemar, two-sided)

| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |
|---|---|---|---|---|
| AR-1 vs GL-D | 95 | 19 | 38.0% | 2.42e-13 |
| AR-1 vs GL-T | 43 | 18 | 12.5% | 1.87e-3 |
| AR-1 vs TH-D | 73 | 20 | 26.5% | 2.92e-8 |
| AR-1 vs TH-T | 31 | 20 | 5.5% | 1.61e-1 |
| AR-1 vs DS-D | 92 | 12 | 40.0% | 1.95e-16 |
| AR-2 vs GL-D | 95 | 19 | 38.0% | 2.42e-13 |
| AR-2 vs GL-T | 43 | 18 | 12.5% | 1.87e-3 |
| AR-2 vs TH-D | 73 | 20 | 26.5% | 2.92e-8 |
| AR-2 vs TH-T | 31 | 20 | 5.5% | 1.61e-1 |
| AR-2 vs DS-D | 92 | 12 | 40.0% | 1.95e-16 |
| AR-1o vs GL-D | 79 | 3 | 38.0% | 3.80e-20 |
| AR-1o vs GL-T | 29 | 4 | 12.5% | 1.09e-5 |
| AR-1o vs TH-D | 53 | 0 | 26.5% | 2.22e-16 |
| AR-1o vs TH-T | 11 | 0 | 5.5% | 9.77e-4 |
| AR-1o vs DS-D | 87 | 7 | 40.0% | 1.12e-18 |

## Needle recall by wrapper

| Family / wrapper | AR-0 | AR-1 | AR-1o | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|
| LEAK-DECLARED / W1-plain | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 | 3/3 | 2/3 | 3/3 |
| LEAK-DECLARED / W10-zst | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W12-percent | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W15-zip-bzip2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W3-zip | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W4-zip-in-asar | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W5-tgz | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W6-utf16-binary | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W7-base64 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W8-xz | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W9-bz2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, call) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, env) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 1/3 | 3/3 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE, call) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, config) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, config) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, env) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, config) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, env) | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 |
| UNVERIFIABLE / W13-enc-zip | 0/13 | 0/13 | 0/13 | 0/13 | 0/13 | 0/13 | 0/13 | 0/13 | 0/13 |
| UNVERIFIABLE / W16-dmg | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 | 0/7 |

## Pre-registered hypotheses

- **H1: NOT SUPPORTED** — GL-D: Δ=38.0% p=2.42e-13 (need Δ≥15.0%, p<0.002); GL-T: Δ=12.5% p=1.87e-3 (need Δ≥15.0%, p<0.002); TH-D: Δ=26.5% p=2.92e-8 (need Δ≥15.0%, p<0.002); TH-T: Δ=5.5% p=1.61e-1 (need Δ≥15.0%, p<0.002); DS-D: Δ=40.0% p=1.95e-16 (need Δ≥15.0%, p<0.002)
- **H1b: NOT SUPPORTED** — GL-D: Δ=38.0% p=2.42e-13 (need Δ>0, p<0.01); GL-T: Δ=12.5% p=1.87e-3 (need Δ>0, p<0.01); TH-D: Δ=26.5% p=2.92e-8 (need Δ>0, p<0.01); TH-T: Δ=5.5% p=1.61e-1 (need Δ>0, p<0.01); DS-D: Δ=40.0% p=1.95e-16 (need Δ>0, p<0.01)
- **H2: NOT SUPPORTED** — AR-2 acc 90.0% vs AR-1 90.0%; UNDECLARED-LEAK false passes AR-2 0 vs AR-1 0
- **H3: SUPPORTED** — AR-1 silent passes on secrets inside uninspectable content: 0/20
- **H5 (expected loss): CONFIRMED (Anti-REA loses)** — false blocks on clean uninspectable content: AR-1 20/20, TH-D 0/20
- **H4 (keyed detector generalises): SUPPORTED** — held-out unprefixed, env/config style: blocked 4/4 (need ≥80%); call style (no key name, predicted loss): blocked 0/0
- **H6 (decoders): SUPPORTED** — COMPRESSED-CLEAN correct 20/20 (need ≥95%); LEAK-DECLARED via W7-base64/W8-xz/W9-bz2/W10-zst/W11-deb/W12-percent/W14-lz4/W15-zip-bzip2 blocked with needle found 10/10 (need all)
- **H7 (held-out prefixed): SUPPORTED** — secret-marked prefixes blocked 1/1 (need ≥80%); unmarked prefixes blocked 3/3 (expected only when key-named)
- **H8 (noise): SUPPORTED** — AR-1 spurious findings: 0 (need ≤20; v0.2 had 217 on v2)
- **H9 (undeclared leaks): SUPPORTED** — UNDECLARED-LEAK correct: AR-1 20, TH-T 12, GL-T 20 of 20 (need AR-1 ≥ TH-T)
