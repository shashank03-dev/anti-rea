# Benchmark results — eval set

Generated from `bench/runs/eval/results.jsonl` by `bench/score.mjs`. Frozen tool+harness sha256 `88f2bb1ef3a40f75bd660676cd5c81bb9b6fbde1e7f46b5a0dd18191b3d2eb7d`. Node v26.11.1, darwin-arm64.

Tools: gitleaks `8.30.1`, trufflehog `trufflehog 3.99.8`, detect-secrets `1.5.0`.

## Release-decision accuracy

| Config | Accuracy | 95% CI (exact) | False block | False pass | Tool errors | Spurious findings | Median ms |
|---|---|---|---|---|---|---|---|
| AR-0 | 192/260 = 73.8% | [68.1, 79.1] | 20.0% | 30.0% | 0 | 4 | 113 |
| AR-1 | 232/260 = 89.2% | [84.8, 92.7] | 20.0% | 5.0% | 0 | 4 | 121 |
| AR-1o | 232/260 = 89.2% | [84.8, 92.7] | 0.0% | 17.5% | 0 | 4 | 121 |
| AR-1@0.4 | 210/260 = 80.8% | [75.4, 85.4] | 27.0% | 14.4% | 0 | 4 | 122 |
| GL-D | 115/260 = 44.2% | [38.1, 50.5] | 22.0% | 76.9% | 0 | 14 | 193 |
| GL-T | 196/260 = 75.4% | [69.7, 80.5] | 15.0% | 30.6% | 0 | 18 | 200 |
| TH-D | 167/260 = 64.2% | [58.1, 70.1] | 0.0% | 58.1% | 0 | 6 | 492 |
| TH-T | 210/260 = 80.8% | [75.4, 85.4] | 0.0% | 31.3% | 0 | 6 | 496 |
| DS-D | 120/260 = 46.2% | [40.0, 52.4] | 27.0% | 70.6% | 0 | 109 | 503 |
| AR-2 | 237/260 = 91.2% | [87.0, 94.3] | 20.0% | 1.9% | 0 | 10 | 623 |

## Accuracy per family

| Family (truth) | AR-0 | AR-1 | AR-1o | AR-1@0.4 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|---|
| CLEAN (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 95.0% | 100.0% |
| LEAK-DECLARED (block) | 100.0% | 100.0% | 100.0% | 100.0% | 20.0% | 95.0% | 75.0% | 90.0% | 20.0% | 100.0% |
| PUBLIC-DECLARED (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 50.0% | 90.0% | 100.0% | 100.0% | 50.0% | 100.0% |
| SERVER-IMPL (block) | 0.0% | 100.0% | 100.0% | 100.0% | 5.0% | 100.0% | 0.0% | 100.0% | 30.0% | 100.0% |
| PRIVATE-ARTIFACT (block) | 0.0% | 100.0% | 100.0% | 100.0% | 0.0% | 80.0% | 0.0% | 100.0% | 30.0% | 100.0% |
| UNDECLARED-LEAK (block) | 90.0% | 90.0% | 90.0% | 71.3% | 40.0% | 70.0% | 65.0% | 65.0% | 32.5% | 96.3% |
| UNVERIFIABLE (block) | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 25.0% | 100.0% |
| UNVERIFIABLE-CLEAN (pass) | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% | 100.0% | 85.0% | 0.0% |
| EXAMPLE-DOCS (pass) | 100.0% | 100.0% | 100.0% | 100.0% | 40.0% | 40.0% | 100.0% | 100.0% | 45.0% | 100.0% |
| COMPRESSED-CLEAN (pass) | 100.0% | 100.0% | 100.0% | 65.0% | 100.0% | 95.0% | 100.0% | 100.0% | 90.0% | 100.0% |

## Paired comparisons (exact McNemar, two-sided)

| Comparison | A right / B wrong | A wrong / B right | Δ accuracy | p |
|---|---|---|---|---|
| AR-1 vs GL-D | 138 | 21 | 45.0% | 2.68e-22 |
| AR-1 vs GL-T | 58 | 22 | 13.8% | 7.01e-5 |
| AR-1 vs TH-D | 90 | 25 | 25.0% | 8.37e-10 |
| AR-1 vs TH-T | 47 | 25 | 8.5% | 1.28e-2 |
| AR-1 vs DS-D | 131 | 19 | 43.1% | 9.06e-22 |
| AR-1 vs AR-1@0.4 | 22 | 0 | 8.5% | 4.77e-7 |
| AR-2 vs GL-D | 142 | 20 | 46.9% | 7.45e-24 |
| AR-2 vs GL-T | 61 | 20 | 15.8% | 5.66e-6 |
| AR-2 vs TH-D | 90 | 20 | 26.9% | 8.64e-12 |
| AR-2 vs TH-T | 47 | 20 | 10.4% | 1.31e-3 |
| AR-2 vs DS-D | 134 | 17 | 45.0% | 9.74e-24 |
| AR-1o vs GL-D | 118 | 1 | 45.0% | 3.61e-34 |
| AR-1o vs GL-T | 38 | 2 | 13.8% | 1.49e-9 |
| AR-1o vs TH-D | 70 | 5 | 25.0% | 9.82e-16 |
| AR-1o vs TH-T | 27 | 5 | 8.5% | 1.13e-4 |
| AR-1o vs DS-D | 119 | 7 | 43.1% | 2.11e-27 |

## Needle recall by wrapper

| Family / wrapper | AR-0 | AR-1 | AR-1o | AR-1@0.4 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|---|
| LEAK-DECLARED / W1-plain | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| LEAK-DECLARED / W10-zst | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 4/5 | 5/5 | 0/5 | 5/5 |
| LEAK-DECLARED / W12-percent | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W14-lz4 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W15-zip-bzip2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W3-zip | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W4-zip-in-asar | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W5-tgz | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W6-utf16-binary | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W7-base64 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| LEAK-DECLARED / W8-xz | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| LEAK-DECLARED / W9-bz2 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, ctor) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, env) | 1/2 | 1/2 | 1/2 | 1/2 | 2/2 | 2/2 | 1/2 | 1/2 | 2/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-PREFIXED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, env) | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 1/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (HELDOUT-UNPREFIXED, method) | 3/3 | 3/3 | 3/3 | 1/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 3/3 |
| UNDECLARED-LEAK / W1-plain (INSIDE, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (INSIDE, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (INSIDE, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W1-plain (INSIDE, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, bare) | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 | 2/3 | 0/3 | 3/3 |
| UNDECLARED-LEAK / W1-plain (NAMED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W1-plain (NAMED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, bare) | 1/2 | 1/2 | 1/2 | 0/2 | 0/2 | 0/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, config) | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, ctor) | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-PREFIXED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, bare) | 2/3 | 2/3 | 2/3 | 0/3 | 0/3 | 0/3 | 2/3 | 2/3 | 0/3 | 3/3 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, config) | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 1/2 | 1/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (HELDOUT-UNPREFIXED, method) | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (INSIDE, bare) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, config) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, env) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (INSIDE, method) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W2-asar (NAMED, config) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, ctor) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, env) | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W2-asar (NAMED, method) | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 1/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, bare) | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, config) | 2/2 | 2/2 | 2/2 | 1/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, ctor) | 2/2 | 2/2 | 2/2 | 1/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, env) | 1/2 | 1/2 | 1/2 | 1/2 | 0/2 | 2/2 | 1/2 | 1/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-PREFIXED, method) | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, bare) | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, config) | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 2/3 | 0/3 | 0/3 | 0/3 | 3/3 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, ctor) | 1/2 | 1/2 | 1/2 | 1/2 | 0/2 | 0/2 | 1/2 | 1/2 | 0/2 | 1/2 |
| UNDECLARED-LEAK / W3-zip (HELDOUT-UNPREFIXED, env) | 1/2 | 1/2 | 1/2 | 1/2 | 0/2 | 1/2 | 0/2 | 0/2 | 0/2 | 1/2 |
| UNDECLARED-LEAK / W3-zip (INSIDE, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (INSIDE, config) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (INSIDE, env) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (INSIDE, method) | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, bare) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNDECLARED-LEAK / W3-zip (NAMED, config) | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, ctor) | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, env) | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 |
| UNDECLARED-LEAK / W3-zip (NAMED, method) | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 1/1 |
| UNVERIFIABLE / W13-enc-zip | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 | 0/12 |
| UNVERIFIABLE / W17-enc-dmg | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |

## UNDECLARED-LEAK by stratum × render style (correct / n)

| Stratum / style | AR-0 | AR-1 | AR-1o | AR-1@0.4 | GL-D | GL-T | TH-D | TH-T | DS-D | AR-2 |
|---|---|---|---|---|---|---|---|---|---|---|
| INSIDE / env | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 4/4 | 4/4 | 1/4 | 4/4 |
| INSIDE / config | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 |
| INSIDE / ctor | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 |
| INSIDE / method | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 4/4 | 4/4 | 0/4 | 4/4 |
| INSIDE / bare | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 |
| NAMED / env | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 3/4 | 3/4 | 0/4 | 4/4 |
| NAMED / config | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 |
| NAMED / ctor | 4/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 | 3/4 | 3/4 | 0/4 | 4/4 |
| NAMED / method | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 4/4 | 4/4 | 2/4 | 4/4 |
| NAMED / bare | 4/4 | 4/4 | 4/4 | 4/4 | 3/4 | 4/4 | 3/4 | 3/4 | 2/4 | 4/4 |
| HELDOUT-PREFIXED / env | 2/4 | 2/4 | 2/4 | 2/4 | 2/4 | 4/4 | 2/4 | 2/4 | 2/4 | 4/4 |
| HELDOUT-PREFIXED / config | 4/4 | 4/4 | 4/4 | 2/4 | 2/4 | 4/4 | 2/4 | 2/4 | 1/4 | 4/4 |
| HELDOUT-PREFIXED / ctor | 3/4 | 3/4 | 3/4 | 1/4 | 0/4 | 2/4 | 2/4 | 2/4 | 0/4 | 4/4 |
| HELDOUT-PREFIXED / method | 4/4 | 4/4 | 4/4 | 2/4 | 0/4 | 0/4 | 1/4 | 1/4 | 0/4 | 4/4 |
| HELDOUT-PREFIXED / bare | 3/4 | 3/4 | 3/4 | 0/4 | 0/4 | 2/4 | 2/4 | 2/4 | 3/4 | 4/4 |
| HELDOUT-UNPREFIXED / env | 3/4 | 3/4 | 3/4 | 3/4 | 1/4 | 2/4 | 2/4 | 2/4 | 1/4 | 3/4 |
| HELDOUT-UNPREFIXED / config | 4/4 | 4/4 | 4/4 | 3/4 | 0/4 | 2/4 | 0/4 | 0/4 | 0/4 | 4/4 |
| HELDOUT-UNPREFIXED / ctor | 3/4 | 3/4 | 3/4 | 3/4 | 0/4 | 0/4 | 2/4 | 2/4 | 1/4 | 3/4 |
| HELDOUT-UNPREFIXED / method | 4/4 | 4/4 | 4/4 | 1/4 | 0/4 | 0/4 | 0/4 | 0/4 | 2/4 | 4/4 |
| HELDOUT-UNPREFIXED / bare | 2/4 | 2/4 | 2/4 | 0/4 | 0/4 | 0/4 | 2/4 | 2/4 | 1/4 | 3/4 |

## Pre-registered hypotheses

- **H1: NOT SUPPORTED** — GL-D: Δ=45.0% p=2.68e-22 (need Δ≥15.0%, p<0.002); GL-T: Δ=13.8% p=7.01e-5 (need Δ≥15.0%, p<0.002); TH-D: Δ=25.0% p=8.37e-10 (need Δ≥15.0%, p<0.002); TH-T: Δ=8.5% p=1.28e-2 (need Δ≥15.0%, p<0.002); DS-D: Δ=43.1% p=9.06e-22 (need Δ≥15.0%, p<0.002)
- **H1b: NOT SUPPORTED** — GL-D: Δ=45.0% p=2.68e-22 (need Δ>0, p<0.01); GL-T: Δ=13.8% p=7.01e-5 (need Δ>0, p<0.01); TH-D: Δ=25.0% p=8.37e-10 (need Δ>0, p<0.01); TH-T: Δ=8.5% p=1.28e-2 (need Δ>0, p<0.01); DS-D: Δ=43.1% p=9.06e-22 (need Δ>0, p<0.01)
- **H1c (recommended config AR-2): SUPPORTED** — GL-D: Δ=46.9% p=7.45e-24 (need Δ>0, p<0.01); GL-T: Δ=15.8% p=5.66e-6 (need Δ>0, p<0.01); TH-D: Δ=26.9% p=8.64e-12 (need Δ>0, p<0.01); TH-T: Δ=10.4% p=1.31e-3 (need Δ>0, p<0.01); DS-D: Δ=45.0% p=9.74e-24 (need Δ>0, p<0.01)
- **H2: SUPPORTED** — AR-2 acc 91.2% vs AR-1 89.2%; UNDECLARED-LEAK false passes AR-2 3 vs AR-1 8
- **H3: SUPPORTED** — AR-1 silent passes on secrets inside uninspectable content: 0/20
- **H5 (expected loss): CONFIRMED (Anti-REA loses)** — false blocks on clean uninspectable content: AR-1 20/20, TH-D 0/20
- **H4 (keyed detector generalises): SUPPORTED** — held-out unprefixed, env/config style: blocked 7/8 (need ≥80%)
- **H4c (call styles): SUPPORTED** — held-out formats, ctor/method style: blocked 14/16 (need ≥70%)
- **H4d (bare factory calls): SUPPORTED** — held-out formats, bare style: blocked 5/8 (need ≥50%)
- **H6 (decoders): SUPPORTED** — COMPRESSED-CLEAN correct 20/20 (need ≥95%); LEAK-DECLARED via W7-base64/W8-xz/W9-bz2/W10-zst/W11-deb/W12-percent/W14-lz4/W15-zip-bzip2/W16-dmg blocked with needle found 14/14 (need all)
- **H7 (held-out secret-marked prefixes): SUPPORTED** — secret-marked prefixes blocked 6/6 across all styles (need ≥80%); unmarked prefixes blocked 10/14
- **H8 (noise): SUPPORTED** — AR-1 spurious findings: 4 (need ≤20)
- **H9 (undeclared leaks): SUPPORTED** — UNDECLARED-LEAK correct: AR-1 72, TH-T 52, GL-T 56 of 80 (need AR-1 ≥ TH-T)
- **H9b (undeclared leaks, significance): SUPPORTED** — AR-1 vs TH-T on UNDECLARED-LEAK: 25 : 5 discordant, exact McNemar p=3.25e-4 (need AR-1 ahead and p<0.05)
- **H10 (secondary: AR-1o vs TH-T): SUPPORTED** — AR-1o (uninspectable content warns) vs TH-T: Δ=8.5%, 27 : 5, p=1.13e-4 (need Δ>0, p<0.01)
- **H11 (v0.5 vs v0.4, same corpus): SUPPORTED** — AR-1 89.2% vs AR-1@0.4 80.8%: Δ=8.5%, 22 : 0, p=4.77e-7 (need Δ>0, p<0.01)
