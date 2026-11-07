# Benchmark results — eval set

Generated from `bench/runs/eval/results.jsonl` by `bench/score.mjs`. Frozen tool+harness sha256 `6099fbf64928e75cfac18a16ba74bca86693ebb8dbd9989e6b5de7219e54dfb0`. Node v26.11.1, darwin-arm64.

Tools: gitleaks `8.30.1`, trufflehog `trufflehog 3.99.8`, detect-secrets `1.5.0`.

## Release-decision accuracy

| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |
|---|---|---|---|---|---|---|---|
| AR-0 | 198/260 = 76.2% | [70.5, 81.2] | 20.0% | 26.3% | 0 | 0 | 116 |
| AR-1 | 238/260 = 91.5% | [87.5, 94.6] | 20.0% | 1.3% | 0 | 0 | 127 |
| AR-1o | 238/260 = 91.5% | [87.5, 94.6] | 0.0% | 13.8% | 0 | 0 | 126 |
| AR-1@0.4 | 212/260 = 81.5% | [76.3, 86.1] | 31.0% | 10.6% | 0 | 0 | 128 |
| AR-1@0.5 | 238/260 = 91.5% | [87.5, 94.6] | 20.0% | 1.3% | 0 | 0 | 125 |
| GL-D | 122/260 = 46.9% | [40.7, 53.2] | 20.0% | 73.8% | 0 | 0 | 188 |
| GL-T | 195/260 = 75.0% | [69.3, 80.1] | 9.0% | 35.0% | 0 | 0 | 194 |
| TH-D | 171/260 = 65.8% | [59.7, 71.5] | 2.0% | 54.4% | 0 | 9 | 465 |
| TH-T | 211/260 = 81.2% | [75.9, 85.7] | 2.0% | 29.4% | 0 | 9 | 570 |
| DS-D | 104/260 = 40.0% | [34.0, 46.2] | 18.0% | 86.3% | 0 | 12 | 636 |
| AR-2 | 238/260 = 91.5% | [87.5, 94.6] | 21.0% | 0.6% | 0 | 9 | 612 |

## Accuracy per family

| Family (truth) | AR-0 | AR-1 | AR-1o | AR-1@0.4 | AR-1@0.5 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| LEAK-DECLARED (block) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 10.0% | 55.0% | 60.0% | 70.0% | 5.0% | 100.0% |
| PUBLIC-DECLARED (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 45.0% | 100.0% | 100.0% | 100.0% | 75.0% | 100.0% |
| SERVER-IMPL (block) | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 100.0% | 5.0% | 100.0% | 10.0% | 100.0% |
| PRIVATE-ARTIFACT (block) | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | 70.0% | 5.0% | 100.0% | 0.0% | 100.0% |
| UNDECLARED-LEAK (block) | 97.5% | 97.5% | 97.5% | 78.8% | 97.5% | 50.0% | 73.8% | 72.5% | 72.5% | 23.8% | 98.8% |
| UNVERIFIABLE (block) | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.0% | 0.0% | 5.0% | 5.0% | 0.0% | 100.0% |
| UNVERIFIABLE-CLEAN (pass) | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% | 100.0% | 100.0% | 95.0% | 95.0% | 95.0% | 0.0% |
| EXAMPLE-DOCS (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 55.0% | 55.0% | 100.0% | 100.0% | 45.0% | 100.0% |
| COMPRESSED-CLEAN (pass) | 100.0% | 100.0% | 100.0% | 45.0% | 100.0% | 100.0% | 100.0% | 95.0% | 95.0% | 95.0% | 95.0% |

## Paired comparisons (exact McNemar, two-sided)

| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |
|---|---|---|---|---|
| AR-1 vs GL-D | 137 | 21 | 44.6% | 4.66e-22 |
| AR-1 vs GL-T | 64 | 21 | 16.5% | 3.28e-6 |
| AR-1 vs TH-D | 87 | 20 | 25.8% | 3.80e-11 |
| AR-1 vs TH-T | 47 | 20 | 10.4% | 1.31e-3 |
| AR-1 vs DS-D | 154 | 20 | 51.5% | 8.19e-27 |
| AR-1 vs AR-1@0.5 | 0 | 0 | 0.0% | 1.00e+0 |
| AR-1 vs AR-1@0.4 | 26 | 0 | 10.0% | 2.98e-8 |
| AR-2 vs GL-D | 138 | 22 | 44.6% | 9.84e-22 |
| AR-2 vs GL-T | 65 | 22 | 16.5% | 4.35e-6 |
| AR-2 vs TH-D | 86 | 19 | 25.8% | 2.30e-11 |
| AR-2 vs TH-T | 46 | 19 | 10.4% | 1.09e-3 |
| AR-2 vs DS-D | 155 | 21 | 51.5% | 1.95e-26 |
| AR-1o vs GL-D | 117 | 1 | 44.6% | 7.16e-34 |
| AR-1o vs GL-T | 44 | 1 | 16.5% | 2.61e-12 |
| AR-1o vs TH-D | 69 | 2 | 25.8% | 2.17e-18 |
| AR-1o vs TH-T | 29 | 2 | 10.4% | 4.63e-7 |
| AR-1o vs DS-D | 135 | 1 | 51.5% | 3.15e-39 |

## Needle recall by wrapper

| Family / wrapper | AR-0 | AR-1 | AR-1o | AR-1@0.4 | AR-1@0.5 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| LEAK-DECLARED / W10-zst | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W11-deb | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 |
| LEAK-DECLARED / W14-lz4 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W2-asar | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W3-zip | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W4-zip-in-asar | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W5-tgz | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W6-utf16-binary | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 0/4 | 0/4 | 2/4 | 2/4 | 0/4 | 4/4 |
| LEAK-DECLARED / W7-base64 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W8-xz | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, ctor) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 2/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, method) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 | 1/3 | 1/3 | 2/3 | 3/3 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, bare) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, config) | 1/2 | 1/2 | 1/2 | 1/2 | 1/2 | 2/2 | 2/2 | 0/2 | 0/2 | 2/2 | 1/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (INSIDE, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (INSIDE, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (INSIDE, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, bare) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 | 0/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, config) | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, ctor) | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, method) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, bare) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, method) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, bare) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 |
| UNDECLARED-LEAK / W2-asar (INSIDE, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, bare) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (NAMED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (NAMED, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (NAMED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, bare) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, ctor) | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, bare) | 1/2 | 1/2 | 1/2 | 0/2 | 1/2 | 0/2 | 0/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 1/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, method) | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (INSIDE, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (INSIDE, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (INSIDE, method) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 3/3 |
| UNDECLARED-LEAK / W3-zip (NAMED, bare) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, method) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNVERIFIABLE / W13-enc-zip | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 |
| UNVERIFIABLE / W17-enc-dmg | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |

## UNDECLARED-LEAK by stratum × render style (correct / n)

| Stratum / style | AR-0 | AR-1 | AR-1o | AR-1@0.4 | AR-1@0.5 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| INSIDE / env | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 4/4 | 4/4 | 0/4 | 4/4 |
| INSIDE / config | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 |
| INSIDE / ctor | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 |
| INSIDE / method | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 | 4/4 | 4/4 | 0/4 | 4/4 |
| INSIDE / bare | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 |
| NAMED / env | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 |
| NAMED / config | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 3/4 | 3/4 | 1/4 | 4/4 |
| NAMED / ctor | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 |
| NAMED / method | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 3/4 | 3/4 | 1/4 | 4/4 |
| NAMED / bare | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 4/4 | 4/4 | 0/4 | 4/4 |
| HELDOUT-PREFIXED / env | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 3/4 | 3/4 | 2/4 | 4/4 |
| HELDOUT-PREFIXED / config | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 2/4 | 4/4 | 3/4 | 3/4 | 0/4 | 4/4 |
| HELDOUT-PREFIXED / ctor | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 | 2/4 | 2/4 | 3/4 | 3/4 | 1/4 | 4/4 |
| HELDOUT-PREFIXED / method | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 0/4 | 0/4 | 2/4 | 2/4 | 2/4 | 4/4 |
| HELDOUT-PREFIXED / bare | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 | 1/4 | 2/4 | 3/4 | 3/4 | 1/4 | 4/4 |
| HELDOUT-UNPREFIXED / env | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 3/4 | 2/4 | 2/4 | 0/4 | 4/4 |
| HELDOUT-UNPREFIXED / config | 3/4 | 3/4 | 3/4 | 3/4 | 3/4 | 4/4 | 4/4 | 0/4 | 0/4 | 2/4 | 3/4 |
| HELDOUT-UNPREFIXED / ctor | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 0/4 | 0/4 | 1/4 | 1/4 | 2/4 | 4/4 |
| HELDOUT-UNPREFIXED / method | 4/4 | 4/4 | 4/4 | 0/4 | 4/4 | 0/4 | 0/4 | 1/4 | 1/4 | 1/4 | 4/4 |
| HELDOUT-UNPREFIXED / bare | 3/4 | 3/4 | 3/4 | 0/4 | 3/4 | 0/4 | 0/4 | 2/4 | 2/4 | 0/4 | 4/4 |

## Pre-registered hypotheses

- **H1: NOT SUPPORTED** — GL-D: Δ=44.6% p=4.66e-22 (need Δ≥15.0%, p<0.002); GL-T: Δ=16.5% p=3.28e-6 (need Δ≥15.0%, p<0.002); TH-D: Δ=25.8% p=3.80e-11 (need Δ≥15.0%, p<0.002); TH-T: Δ=10.4% p=1.31e-3 (need Δ≥15.0%, p<0.002); DS-D: Δ=51.5% p=8.19e-27 (need Δ≥15.0%, p<0.002)
- **H1b: SUPPORTED** — GL-D: Δ=44.6% p=4.66e-22 (need Δ>0, p<0.01); GL-T: Δ=16.5% p=3.28e-6 (need Δ>0, p<0.01); TH-D: Δ=25.8% p=3.80e-11 (need Δ>0, p<0.01); TH-T: Δ=10.4% p=1.31e-3 (need Δ>0, p<0.01); DS-D: Δ=51.5% p=8.19e-27 (need Δ>0, p<0.01)
- **H1c (recommended config AR-2): SUPPORTED** — GL-D: Δ=44.6% p=9.84e-22 (need Δ>0, p<0.01); GL-T: Δ=16.5% p=4.35e-6 (need Δ>0, p<0.01); TH-D: Δ=25.8% p=2.30e-11 (need Δ>0, p<0.01); TH-T: Δ=10.4% p=1.09e-3 (need Δ>0, p<0.01); DS-D: Δ=51.5% p=1.95e-26 (need Δ>0, p<0.01)
- **H2: SUPPORTED** — AR-2 acc 91.5% vs AR-1 91.5%; UNDECLARED-LEAK false passes AR-2 1 vs AR-1 2
- **H3: SUPPORTED** — AR-1 silent passes on secrets inside uninspectable content: 0/20
- **H5 (expected loss): CONFIRMED (Anti-REA loses)** — false blocks on clean uninspectable content: AR-1 20/20, TH-D 1/20
- **H4 (keyed detector generalises): SUPPORTED** — held-out unprefixed, env/config style: blocked 7/8 (need ≥80%)
- **H4c (call styles): SUPPORTED** — held-out formats, ctor/method style: blocked 16/16 (need ≥70%)
- **H4d (bare factory calls): SUPPORTED** — held-out formats, bare style: blocked 7/8 (need ≥50%)
- **H6 (decoders): SUPPORTED** — COMPRESSED-CLEAN correct 20/20 (need ≥95%); LEAK-DECLARED via W7-base64/W8-xz/W9-bz2/W10-zst/W11-deb/W12-percent/W14-lz4/W15-zip-bzip2/W16-dmg blocked with needle found 9/9 (need all)
- **H7 (held-out secret-marked prefixes): SUPPORTED** — secret-marked prefixes blocked 6/6 across all styles (need ≥80%); unmarked prefixes blocked 14/14
- **H8 (noise): SUPPORTED** — AR-1 spurious findings: 0 (need ≤20)
- **H9 (undeclared leaks): SUPPORTED** — UNDECLARED-LEAK correct: AR-1 78, TH-T 58, GL-T 59 of 80 (need AR-1 ≥ TH-T)
- **H9b (undeclared leaks, significance): SUPPORTED** — AR-1 vs TH-T on UNDECLARED-LEAK: 21 : 1 discordant, exact McNemar p=1.10e-5 (need AR-1 ahead and p<0.05)
- **H10 (secondary: AR-1o vs TH-T): SUPPORTED** — AR-1o (uninspectable content warns) vs TH-T: Δ=10.4%, 29 : 2, p=4.63e-7 (need Δ>0, p<0.01)
- **H11 (v0.6 vs v0.5, no regression): SUPPORTED** — AR-1 91.5% vs AR-1@0.5 91.5%: Δ=0.0%, 0 : 0, p=1.00e+0 (need Δ≥0 and 0 regressions)
- **H11b (v0.6 vs v0.4, same corpus): SUPPORTED** — AR-1 91.5% vs AR-1@0.4 81.5%: Δ=10.0%, 26 : 0, p=2.98e-8 (need Δ>0, p<0.01)
