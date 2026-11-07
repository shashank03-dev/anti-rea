# Benchmark results: Anti-REA vs. current secret scanners as release gates

There have been five pre-registered studies. Each was run once, on a sealed corpus, with the same tool versions (gitleaks 8.30.1, TruffleHog 3.99.8, detect-secrets 1.5.0), fully offline.

| Study | Anti-REA | N | Seed | Pre-registration | Raw results |
|---|---|---|---|---|---|
| **v5** | **v0.5** | 260 | `0x88f2bb1e`, derived from frozen hash `88f2bb1e…eb7d` | [link](../../bench/PREREGISTRATION.md) | [link](../../bench/RESULTS-eval.md) |
| v4 | v0.4 | 240 | `0xd261b18b` | [link](../../bench/v4/PREREGISTRATION.md) | [link](../../bench/v4/RESULTS-eval.md) |
| v3 | v0.3 | 200 | `0x363c69c6` | [link](../../bench/v3/PREREGISTRATION.md) | [link](../../bench/v3/RESULTS-eval.md) |
| v2 | v0.2 | 200 | `0x8921d50f` | [link](../../bench/v2/PREREGISTRATION.md) | [link](../../bench/v2/RESULTS-eval.md) |
| v1 | v0.1 | 180 | `0x5eed2026` | [link](../../bench/v1/PREREGISTRATION.md) | [link](../../bench/v1/RESULTS-eval.md) |

## v5 (Anti-REA v0.5), run 2026-11-07

### Answer

**v0.5 is significantly better than v0.4 and than every baseline except tuned TruffleHog, where it misses the pre-registered significance bar by a small margin. With TruffleHog's findings imported (AR-2, the recommended configuration), it is significantly better than every baseline.** "Substantially better" in the strict primary sense (H1: Δ ≥ 15 points against every baseline) is still **not supported**.

| Config | Accuracy (95% CI) | False block | False pass | Spurious | Median time |
|---|---|---|---|---|---|
| **AR-2** Anti-REA + TruffleHog import | **91.2%** [87.0, 94.3] | 20% | **1.9%** | 10 | 623 ms |
| **AR-1** Anti-REA v0.5 | **89.2%** [84.8, 92.7] | 20% | 5.0% | 4 | **121 ms** |
| AR-1o v0.5, uninspectable content warns | 89.2% | 0% | 17.5% | 4 | 121 ms |
| AR-1@0.4 frozen v0.4, same corpus | 80.8% | 27% | 14.4% | 4 | 122 ms |
| **TH-T** TruffleHog, tuned | 80.8% [75.4, 85.4] | 0% | 31.3% | 6 | 496 ms |
| **GL-T** gitleaks, tuned | 75.4% | 15% | 30.6% | 18 | 200 ms |
| AR-0 v0.5, no owner knowledge | 73.8% | 20% | 30.0% | 4 | 113 ms |
| TH-D TruffleHog, defaults | 64.2% | 0% | 58.1% | 6 | 492 ms |
| DS-D detect-secrets | 46.2% | 27% | 70.6% | 109 | 503 ms |
| GL-D gitleaks, defaults | 44.2% | 22% | 76.9% | 14 | 193 ms |

Paired tests (exact McNemar, N = 260):

| Comparison | A right, B wrong | A wrong, B right | Δ | p |
|---|---|---|---|---|
| AR-1 vs **AR-1@0.4** | **22** | **0** | +8.5 | **5e-7** |
| AR-1 vs TH-T | 47 | 25 | +8.5 | 0.013 |
| AR-1 vs GL-T | 58 | 22 | +13.8 | 7e-5 |
| AR-1 vs TH-D | 90 | 25 | +25.0 | 8e-10 |
| AR-1 vs DS-D | 131 | 19 | +43.1 | 9e-22 |
| AR-1 vs GL-D | 138 | 21 | +45.0 | 3e-22 |
| **AR-2 vs TH-T** | 47 | 20 | **+10.4** | **0.0013** |
| AR-2 vs GL-T | 61 | 20 | +15.8 | 6e-6 |
| AR-1o vs TH-T | 27 | 5 | +8.5 | 1e-4 |

### Hypotheses (scored mechanically)

| Hypothesis | Verdict | Prediction |
|---|---|---|
| H1 Δ ≥ 15 and p < 0.002 vs every baseline | not supported (TH-T +8.5, GL-T +13.8) | not supported |
| H1b Δ > 0 and p < 0.01 vs every baseline | **not supported**: TH-T p = 0.013 | likely not supported |
| **H1c** AR-2 vs every baseline, p < 0.01 | **supported** (TH-T p = 0.0013) | as H1b |
| H2 AR-2 ≥ AR-1, fewer undeclared false passes | supported (91.2% vs 89.2%; 3 vs 8) | uncertain |
| H3 no silent pass on uninspectable content | supported (0/20) | supported |
| H4 held-out unprefixed, env/config ≥ 80% | supported (7/8) | likely supported |
| H4c held-out ctor/method ≥ 70% | supported (14/16) | likely supported |
| H4d held-out bare factory calls ≥ 50% | supported (5/8) | likely supported |
| H5 expected loss on clean encrypted content | confirmed (20/20 vs 0/20) | confirmed |
| H6 decoders incl. DMG | supported (20/20; 14/14) | supported |
| H7 held-out secret-marked prefixes, all styles | supported (6/6) | likely supported |
| H8 noise ≤ 20 | supported (4, all warn-only JWT-shaped strings in the Firefox background) | supported |
| H9 / H9b undeclared leaks vs TH-T | supported (72 vs 52 of 80; 25 : 5, p = 3e-4) | likely supported |
| H10 AR-1o vs TH-T, p < 0.01 | supported (p = 1e-4) | likely supported |
| **H11 v0.5 vs v0.4, same corpus** | **supported (22 : 0, p = 5e-7)** | likely supported |

### What improved, measured on the same sealed corpus as v0.4

v0.5 got 22 scenarios right that v0.4 got wrong, and **0 the other way round**.
- **7 clean releases containing a DMG.** v0.4 cannot read DMGs, so it blocked them.
- **15 undeclared held-out leaks:**
  - single-case and compound values;
  - unsuffixed constructors;
  - configuration methods;
  - assigned factory calls.

On held-out credentials v0.5 scored 32/40, against v0.4's 17/40 and TH-T's 15/40. Undeclared leaks overall:

| Held-out, style | AR-1 v0.5 | v0.4 | TH-T | GL-T |
|---|---|---|---|---|
| env | 5/8 | 5/8 | 4/8 | 6/8 |
| config | **8/8** | 5/8 | 2/8 | 6/8 |
| ctor | 6/8 | 4/8 | 4/8 | 2/8 |
| method | **8/8** | 3/8 | 1/8 | 0/8 |
| bare | 5/8 | 0/8 | 4/8 | 2/8 |

### Where the errors are

AR-1 made 28 errors.
- **20 are UNVERIFIABLE-CLEAN:** clean releases containing an AES-encrypted DMG or a ZipCrypto zip. No tool can read these. AR-1 blocks all 40 such releases, while TruffleHog passes all 40, including the 20 that hide a secret.
- **8 are undeclared held-out leaks,** 7 of them predicted:
  - **Klaviyo private keys, 3:** they start with `pk_`, which Anti-REA treats as a public prefix. This was the deliberate trap.
  - **fal's `<uuid>:<hex>` key pairs, 3:** a value-test gap listed in V05-CHANGES before the run.
  - **A Railway UUID in a bare factory call, 1:** a positional UUID is treated as an identifier, which was tuned out during calibration.
  - **Airtable under `AIRTABLE_PAT`, 1, unpredicted:** "PAT" is not a credential noun.
- Excluding the two encrypted families, AR-1 is 212/220 (96.4%) and TH-T 190/220 (86.4%).

### Caveats

- **Author-designed corpus.** The corpus, the provider table and the tool are all by the author, and the call rules were designed after v4's misses. The new providers and the 12-call method list reduce, but do not remove, that bias.
- **DMG favours Anti-REA.** No baseline reads DMGs, so the W16-dmg and clean-DMG scenarios favour Anti-REA by construction.
- **Validation set E failed.** It turned up a v0.2 bug in which the word "mask" counted as a secret marker, producing 690 false leads. That was fixed after E, so the v5 background is the only unseen real code. See [CALIBRATION.md](CALIBRATION.md), round 5.
- **Pre-registration errata.** The H4 sample sizes in §5 were stated wrongly (double-counted). The verdicts are unaffected; see PREREGISTRATION §9.

## v4 (Anti-REA v0.4), run 2026-11-07

### Answer

**Anti-REA v0.4 is still the most accurate configuration measured, but not *substantially* better than tuned TruffleHog. H1 and H1b are both not supported.** On this harder benchmark the margin is smaller than in v3: 85.0% against 81.7%, p = 0.35.

v4 deliberately forces the cases v3 never drew. Every credential group appears in every render style, including credentials passed straight into calls, and the 16 held-out formats never appeared in development or calibration.

| Config | Accuracy (95% CI) | False block | False pass | Spurious findings | Median time |
|---|---|---|---|---|---|
| AR-2 Anti-REA + TruffleHog import | **86.7%** [81.7, 90.7] | 20% | 8.6% | 6 | 705 ms |
| **AR-1** Anti-REA, asset model | **85.0%** [79.8, 89.3] | 20% | 11.4% | **0** | **126 ms** |
| AR-1o Anti-REA, uninspectable content warns (secondary) | 85.0% [79.8, 89.3] | 0% | 25.7% | 0 | 126 ms |
| **TH-T** TruffleHog, tuned | 81.7% [76.2, 86.4] | 0% | 31.4% | 6 | 521 ms |
| **GL-T** gitleaks, tuned | 75.0% [69.0, 80.3] | 11% | 35.0% | 3 | 208 ms |
| AR-0 Anti-REA, no owner knowledge | 68.3% | 20% | 40.0% | 0 | 117 ms |
| TH-D TruffleHog, defaults | 62.1% | 0% | 65.0% | 6 | 543 ms |
| DS-D detect-secrets | 50.0% | 58% | 44.3% | 6,349 | 731 ms |
| GL-D gitleaks, defaults | 44.6% | 23% | 78.6% | 2 | 193 ms |

Paired tests (exact McNemar), AR-1 against each baseline:

| Baseline | AR-1 right, baseline wrong | AR-1 wrong, baseline right | Δ | p |
|---|---|---|---|---|
| TH-T | 32 | 24 | +3.3 | 0.35 |
| GL-T | 47 | 23 | +10.0 | 0.006 |
| TH-D | 79 | 24 | +22.9 | 5e-8 |
| DS-D | 99 | 15 | +35.0 | 2e-16 |
| GL-D | 120 | 23 | +40.4 | 5e-17 |

### Hypotheses (scored mechanically by `bench/score.mjs`)

| Hypothesis | Verdict | Author's prediction |
|---|---|---|
| H1 substantial superiority | not supported | not supported |
| H1b superiority over every baseline | not supported (TH-T p = 0.35) | uncertain |
| H2 AR-2 ≥ AR-1 with fewer undeclared false passes | supported (86.7% vs 85.0%; 12 vs 16) | — |
| H3 no silent pass on uninspectable content | supported (0/20) | supported |
| H4 keyed detector, held-out unprefixed, env/config | **supported (5/6)** | likely not supported |
| H4c call styles, held-out, ctor/method ≥ 50% | **not supported (5/12)** | borderline |
| H5 expected loss on clean uninspectable content | confirmed (20/20 vs 0/20) | confirmed |
| H6 decoders | supported (20/20; 11/11) | supported |
| H7 held-out secret-marked prefixes, all styles | not supported (2/5) | likely not supported |
| H8 noise ≤ 20 | supported (0) | supported |
| H9 undeclared leaks: AR-1 ≥ TH-T | supported (44 vs 37 of 60; GL-T 40) | uncertain |
| H9b … significantly | not supported (11 : 4, p = 0.12) | uncertain |
| H10 AR-1o vs TH-T, p < 0.01 | not supported (13 : 5, p = 0.096) | uncertain |

### Where the errors are

AR-1 made 36 errors.
- **20 are UNVERIFIABLE-CLEAN.** These are clean releases containing an encrypted zip or a DMG, blocked by the fail-closed policy, exactly as in v3. TruffleHog passed all 40 uninspectable releases, which means it silently passed 19 of the 20 that held a secret.
- **16 are undeclared leaks in the held-out strata.** AR-1 got all 30 INSIDE and NAMED scenarios right.

| Held-out, style | AR-1 | TH-T | GL-T |
|---|---|---|---|
| env | 3/6 | 1/6 | 5/6 |
| config | **6/6** | 3/6 | 5/6 |
| ctor | 2/6 | 2/6 | 0/6 |
| method | 3/6 | 0/6 | 0/6 |
| bare | 0/6 | 3/6 | 1/6 |

Diagnosed after the run. These are observations, not re-scoring:
- **A design flaw in the value test: 4 misses I did not predict.** `generatedValue` requires at least one uppercase letter unless the value is pure hex. So it rejects **every** lowercase-only key, and every key that is a prefix plus hex. Synthetic checks after the run confirm 0% acceptance for these shapes:
  - Cerebras `csk-<lowercase alnum>`, in env (S132) and `setApiKey` (S140);
  - Firecrawl `fc-<hex>`, in env (S133);
  - LangSmith `lsv2_sk_<hex>_<hex>`, even in `new Client("…")` (S138).

  Many real providers issue lowercase or hex keys, so this is the most important finding of v4.
- **Predicted misses:**
  - bare factory calls (6);
  - Ably's `app.key:secret` format, in env and ctor;
  - client classes with no client suffix (`new Resend`, `new Exa`);
  - methods that aren't credential-named (`init`).
- **Where TruffleHog wins:** its provider-specific keyword detectors recognise Datadog, AssemblyAI and W&B keys even in bare calls, which Anti-REA cannot. That is why AR-2, which imports TruffleHog's findings, is the best configuration measured (86.7%).

### What this shows

- The v0.4 call-style rules work where the call itself names a credential:
  - `setApiKey` and `setToken`;
  - constructors whose class name ends in a client suffix (Client, Api, SDK).

  They do not generalise beyond those patterns. Held-out call styles came out at 5/12, against TruffleHog's 2/12.
- Excluding the two uninspectable families, AR-1 is 184/200 and TH-T 177/200.
- **The honest summary across four studies:**
  - Anti-REA is consistently the most accurate configuration that does not depend on another scanner.
  - It is much better than default scanners and than tuned gitleaks.
  - It is not significantly better than tuned TruffleHog.
  - Its lead comes from owner-declared assets, archive decoding, and failing closed on uninspectable content.

## v3 (Anti-REA v0.3), run 2026-11-06

### Answer

**Anti-REA v0.3 has the highest accuracy measured, but it is still not *substantially* better than the best current tool. H1 and H1b are both not supported.**

| Config | Accuracy (95% CI) | False block | False pass | Spurious findings | Median time |
|---|---|---|---|---|---|
| **AR-1** Anti-REA, asset model | **90.0%** [85.0, 93.8] | 20% | **0%** | **0** | **155 ms** |
| AR-2 Anti-REA + TruffleHog import | 90.0% [85.0, 93.8] | 20% | 0% | 1 | 723 ms |
| AR-1o Anti-REA, uninspectable content warns (secondary) | 90.0% [85.0, 93.8] | 0% | 20% | 0 | 158 ms |
| **TH-T** TruffleHog, tuned | 84.5% [78.7, 89.2] | 0% | 31% | 1 | 564 ms |
| **GL-T** gitleaks, tuned | 77.5% [71.1, 83.1] | 20% | 25% | 55 | 250 ms |
| AR-0 Anti-REA, no owner knowledge | 70.0% | 20% | 40% | 0 | 132 ms |
| TH-D TruffleHog, defaults | 63.5% | 0% | 73% | 1 | 543 ms |
| GL-D gitleaks, defaults | 52.0% | 28% | 68% | 42 | 219 ms |
| DS-D detect-secrets | 50.0% | 45% | 55% | 197 | 608 ms |

Paired tests (exact McNemar):

| Comparison | Δ | Discordant (A right : B right) | p | Clears H1 (Δ ≥ 15, p < 0.002)? | Clears H1b (Δ > 0, p < 0.01)? |
|---|---|---|---|---|---|
| AR-1 vs DS-D | +40.0 | 92 : 12 | 2e-16 | yes | yes |
| AR-1 vs GL-D | +38.0 | 95 : 19 | 2e-13 | yes | yes |
| AR-1 vs TH-D | +26.5 | 73 : 20 | 3e-8 | yes | yes |
| AR-1 vs GL-T | +12.5 | 43 : 18 | 0.0019 | no (Δ < 15) | **yes** |
| AR-1 vs **TH-T** | **+5.5** | 31 : 20 | **0.16** | no | **no** |

**So:**
- Anti-REA v0.3 is **significantly better than tuned gitleaks** and every default configuration.
- It is **numerically ahead of tuned TruffleHog**, but that 5.5-point lead is not statistically distinguishable from chance on 200 scenarios.
- The claim "substantially better than current tools" is **not** made.

### Hypotheses (mechanical verdicts)

| | Verdict | Evidence |
|---|---|---|
| H1 substantially better | **Not supported** | It fails against TH-T (Δ 5.5, p 0.16) and GL-T (Δ 12.5) |
| H1b better at any margin | **Not supported** | It fails against TH-T only |
| H2 composition helps | Not supported | AR-2 equals AR-1 (90.0% each). There was nothing left to fix: AR-1 had 0 undeclared false passes. |
| H3 no silent pass | Supported | 0/20 uninspectable leaks shipped |
| H4 keyed detector generalises | Supported, **on 4 scenarios** | Held-out unprefixed formats in env/config style were blocked 4/4. The predicted-loss call style was **never drawn** for held-out formats. |
| H5 fail-closed cost (expected) | Confirmed | 20/20 false blocks, against TH-D 0/20 |
| H6 decoders | Supported | COMPRESSED-CLEAN 20/20. Every new-wrapper leak (base64, xz, bz2, zst, percent, lz4, zip-bzip2) was blocked with its needle found (10/10). |
| H7 held-out prefixed | Supported, **on 1 scenario** | The single secret-marked one (Supabase `sb_secret_`) was blocked. The 3 unmarked ones were blocked via their key names. |
| H8 noise | Supported | **0** spurious findings, against 217 for v0.2 on v2 |
| H9 undeclared leaks ≥ TH-T | Supported | 20/20 for AR-1, 20/20 for GL-T, 12/20 for TH-T |

### Where the errors are

- **AR-1 (20 errors):** all 20 are UNVERIFIABLE-CLEAN, the pre-registered fail-closed choice on clean encrypted zips and DMGs.
- **TH-T (31 errors):**
  - 20 UNVERIFIABLE: it **silently shipped every secret inside an encrypted zip or DMG**;
  - 8 UNDECLARED-LEAK: held-out and unprefixed formats in config/env style;
  - 3 LEAK-DECLARED: UTF-16 in a native binary, and zip-in-asar.
- **GL-T (45 errors):** spread over 8 families. The largest are EXAMPLE-DOCS (11) and UNVERIFIABLE (16).

### What this does and does not show

1. **Uninspectable content is a coin flip between policies, not a win.** Nobody can read the encrypted-zip and DMG wrappers.
   - Anti-REA blocks all 40 such releases: it catches 20 leaks and wrongly blocks 20 clean ones.
   - TruffleHog passes all 40: it correctly passes 20 clean ones and silently ships 20 leaks.

   Both score 20/40 there. With those two families removed, AR-1 is 160/160 and TH-T 149/160. **Anti-REA's measured lead comes from the other 8 families.** Mainly:
   - undeclared credentials (+8);
   - wrappers the baselines cannot open (+3).
2. **The secondary AR-1o** (uninspectable content warns) is 90.0%, against TH-T's 84.5%: 11 discordant scenarios to 0, p = 0.001. That beats every baseline. But AR-1o was pre-registered as *secondary, report only*, so it does not change the H1/H1b verdicts. It also silently ships uninspectable leaks, just as the scanners do.
3. **Known blind spot untested.** The random draw contained only 2 "call"-style undeclared scenarios: a credential passed straight to a client with no credential-named key. Both were formats Anti-REA already knows (Stripe, npm). The case Anti-REA is predicted to miss, a held-out or unprefixed credential in call style, **did not occur in this eval**, and neither did the `SEGMENT_WRITE_KEY` gap disclosed from dev. The 20/20 on UNDECLARED-LEAK should be read with that in mind.
4. **Small strata.** H4 rests on 4 scenarios and H7 on 1. They show the mechanism working on unseen formats, not a precise rate.
5. **Author-designed corpus**, as in v1 and v2. The new background (VS Code extensions, LLVM, `libLLVM`) was never scanned during development, but the families, held-out formats and render styles were chosen by the author.

### Trajectory across the three studies

| | v1 (v0.1) | v2 (v0.2) | v3 (v0.3) |
|---|---|---|---|
| AR-1 accuracy | 84.4% | 86.0% | 90.0% |
| Best tuned baseline | TH-T 93.9% | TH-T 89.5% | TH-T 84.5% |
| AR-1 vs best baseline | −9.4, p 0.003 (worse) | −3.5, p 0.32 (tie) | +5.5, p 0.16 (tie, ahead) |
| AR-1 errors outside the fail-closed policy | 8 | 8 | **0** |
| AR-1 spurious findings | 0 | 217 | 0 |

The corpora differ between studies, so the rows are not directly comparable. Each study's baseline numbers belong to its own corpus.

## v2 (Anti-REA v0.2), run 2026-11-06

### Answer

**Anti-REA v0.2 is still not substantially better than current tools. H1 and the weaker H1b are both not supported.**

It is now statistically **tied** with tuned TruffleHog and tuned gitleaks:
- against TH-T: 86.0% vs 89.5%, p = 0.32;
- against GL-T: 86.0% vs 88.0%, p = 0.66.

In v1, TruffleHog's lead over Anti-REA was significant (p = 0.003). Anti-REA clearly beats the default configurations of all three scanners. Everything v0.2 set out to fix measurably works (H6). What remains is a design trade-off plus one real weakness.

| Config | Accuracy (95% CI) | False block | False pass | Median time |
|---|---|---|---|---|
| **TH-T** TruffleHog, tuned | **89.5%** [84.4, 93.4] | 10% | 11% | 564 ms |
| **GL-T** gitleaks, tuned | 88.0% [82.7, 92.2] | 10% | 14% | 242 ms |
| **AR-1** Anti-REA, asset model | 86.0% [80.4, 90.5] | 20% | 8% | **141 ms** |
| AR-1o Anti-REA, uninspectable content warns | 86.0% [80.4, 90.5] | **0%** | 28% | 142 ms |
| AR-2 Anti-REA + TruffleHog import | 85.0% [79.3, 89.6] | 27% | **3%** | 788 ms |
| TH-D TruffleHog, defaults | 69.0% | 10% | 52% | 589 ms |
| AR-0 Anti-REA, no owner knowledge | 66.0% | 20% | 48% | 123 ms |
| GL-D gitleaks, defaults | 52.5% | 18% | 77% | 190 ms |
| DS-D detect-secrets | 47.5% | 30% | 75% | 557 ms |

Paired tests for AR-1 (exact McNemar):

| AR-1 vs | Δ | p |
|---|---|---|
| DS-D | +38.5 | 4.4e-13 |
| GL-D | +33.5 | 9.6e-11 |
| TH-D | +17.0 | 1.5e-4 |
| GL-T | −2.0 | 0.66 |
| TH-T | −3.5 | 0.32 |

### Hypotheses (mechanical verdicts from `bench/score.mjs`)

| | Verdict | Evidence |
|---|---|---|
| H1 Δ ≥ 15 points vs every baseline | **Not supported** | It ties GL-T and TH-T |
| H1b better than every baseline at any margin | **Not supported** | Same reason |
| H2 composition helps | Not supported | AR-2 is 85.0% vs AR-1's 86.0%. Undeclared-leak false passes fell from 8 to 3, but the imported TruffleHog findings add false blocks on public values and documented examples |
| H3 no silent pass on uninspectable content | Supported | 0/20 secrets inside encrypted zip or lz4 shipped |
| H4 loses on unprefixed formats (expected) | **Confirmed** | AR-1 made 0/5 correct decisions; TH-T 2/5 and GL-T 4/5 |
| H5 fail-closed costs false blocks (expected) | **Confirmed** | AR-1 blocked 20/20 clean; TH-D blocked 3/20 |
| H6 the v0.2 fixes work | **Supported** | COMPRESSED-CLEAN 20/20 correct. Every leak via base64, xz, zst, .deb or percent-encoding was blocked with its needle found (11/11) |
| H7 structural rule generalises | Not evaluable | The eval draw had no secret-marked held-out prefixes. All 3 held-out prefixed scenarios were unmarked (Resend, Figma) and shipped with a warning, as predicted |

### Where AR-1's 28 errors come from

| Family | Errors | Cause |
|---|---|---|
| UNVERIFIABLE-CLEAN | 20 | **Design choice.** It fails closed on encrypted zip and lz4, which it cannot read. AR-1o makes the opposite choice and scores the same 86.0%: it gains these 20, then silently ships all 20 UNVERIFIABLE leaks. |
| UNDECLARED-LEAK, unprefixed | 5 | **Real weakness.** Twilio (3) and Cloudflare (2) tokens have no prefix, so Anti-REA only warns via the credential-name heuristic. GL-T blocked 4/5. |
| UNDECLARED-LEAK, held-out unmarked prefix | 3 | **Real weakness, predicted.** Resend `re_` and Figma `figd_` prefixes do not say "secret", so they only warn. All three baselines' tuned configs blocked 3/3. |

v1's two error sources are gone:
- Clean `.tar.xz`, `.tar.bz2`, `.tar.zst` and `.deb` releases now pass: COMPRESSED-CLEAN 20/20.
- Base64 and percent-encoded leaks are found.

TH-T's 21 errors are spread across 7 families; GL-T's 24 across 6.

### What Anti-REA does measurably better (v2)

- **Declared-leak recall across wrappers.** LEAK-DECLARED 100% (20/20), against 80% for both TH-T and GL-T. The baselines' misses:
  - **`.deb`**: 2/2 for Anti-REA, 0/2 for every baseline;
  - **UTF-16 strings in a native binary**: 2/2 vs 0/2;
  - **zip inside `app.asar`**: 1/1 vs 0/1.
- **Owner semantics without plaintext in config.**
  - PUBLIC-DECLARED: 100%, against TH-T's 90% (TruffleHog has no value allowlist).
  - EXAMPLE-DOCS: 100%, against TH-T 80% and GL-T 60%.
  - PRIVATE-ARTIFACT: 100%, against GL-T 80%.
- **Fewest false passes of any single tool.** AR-1 lets 8% of truth-block releases ship, against 11% for TH-T and 14% for GL-T. With imports (AR-2) that falls to **3%**.
- **Speed:** 141 ms median per release, against 242 ms for GL-T and 564 ms for TH-T.

### What got worse, and is reported as is

**Warn-level noise.** AR-1 produced 217 spurious findings, against 0 for v0.1 in v1. Most are the new warn-only `prefixed-token` rule:
- 140 on mangled symbols in the real `libnode` slice;
- most of the rest on TypeScript's localised diagnostic files.

None changes a decision, but a reviewer would see them. It was observed on dev, and **deliberately not fixed** because the pre-registration forbids changing `src/` in response to dev results. This is a concrete v0.3 item: apply the structural rule to native binaries only via UTF-16 views, or require the secret marker for any lead at all.

### Interpretation

- **The asset-model approach clearly helps.** AR-0 (66%) vs AR-1 (86%) is the same tool with and without owner knowledge. It beats every scanner on what the owner declares: declared leaks, server-only code, private artifacts, public values and documented examples.
- **It still loses on detector breadth for undeclared credentials.** Dedicated scanners have hundreds of keyword-anchored detectors for unprefixed formats. Anti-REA either imports them (AR-2) or misses them.
- **The headline aggregate depends on one policy choice.** Failing closed on unreadable content costs 20 false blocks and buys 20 caught leaks, at the same accuracy. Which matters more is the owner's call. That is why it is a gate setting.
- **Limits:**
  - These numbers describe an author-designed corpus. v2 added families where v0.2's decoders matter, which favours Anti-REA, and it still did not win the aggregate.
  - Some strata are small: 3 held-out prefixed scenarios, 5 unprefixed. Treat per-stratum figures as indicative.

## v1 (Anti-REA v0.1), run 2026-11-06

**Run:** 2026-11-06. One run of the sealed eval set: 180 scenarios, seed `0x5eed2026`, 20 per family. The frozen tool and harness hash was `652f6a45…98c2`, which matches the [pre-registration](../../bench/v1/PREREGISTRATION.md) after amendments A1–A2. Both amendments fixed output parsing only.

Tools: gitleaks 8.30.1, TruffleHog 3.99.8 and detect-secrets 1.5.0, all fully offline. Raw output: [bench/v1/RESULTS-eval.md](../../bench/v1/RESULTS-eval.md) and [summary JSON](../../bench/v1/RESULTS-eval.summary.json).

### Answer to the pre-registered question

**No. On this corpus Anti-REA is not substantially better than current tools. H1 is not supported.**

| Config | Accuracy (95% CI) | False block | False pass | Spurious findings | Median time |
|---|---|---|---|---|---|
| **TH-T** TruffleHog, tuned | **93.9%** [89.3, 96.9] | 7.5% | 5.0% | 14 | 663 ms |
| AR-2 Anti-REA + TruffleHog import | 85.6% [79.6, 90.3] | 30.0% | **2.0%** | 14 | 741 ms |
| **AR-1** Anti-REA, asset model | 84.4% [78.3, 89.4] | 25.0% | 8.0% | **0** | **107 ms** |
| GL-T gitleaks, tuned | 83.3% [77.1, 88.5] | 21.3% | 13.0% | 12 | 264 ms |
| TH-D TruffleHog, defaults | 70.6% [63.3, 77.1] | 7.5% | 47.0% | 14 | 591 ms |
| AR-0 Anti-REA, no owner knowledge | 61.1% [53.6, 68.3] | 25.0% | 50.0% | 0 | 91 ms |
| GL-D gitleaks, defaults | 41.1% [33.8, 48.7] | 30.0% | 82.0% | 9 | 271 ms |
| DS-D detect-secrets | 38.9% [31.7, 46.4] | 30.0% | 86.0% | 53 | 625 ms |

Paired comparisons, AR-1 vs each baseline (exact McNemar). The pre-registered bar was Δ ≥ 15 points *and* p < 0.002 against **every** baseline:

| AR-1 vs | Δ accuracy | p | Meets bar? |
|---|---|---|---|
| DS-D | +45.6 | 2.0e-14 | yes |
| GL-D | +43.3 | 1.2e-12 | yes |
| TH-D | +13.9 | 4.6e-3 | no (Δ and p both short) |
| GL-T | +1.1 | 0.89 | no: statistically indistinguishable |
| **TH-T** | **−9.4** | **3.3e-3** | **no: TruffleHog tuned is better** |

### Hypotheses

| | Verdict | Evidence |
|---|---|---|
| H1 substantially better than all baselines | **Not supported** | It loses to TH-T, ties GL-T, and falls short against TH-D |
| H2 composition helps | Supported | AR-2's accuracy is ≥ AR-1's. Undeclared-leak false passes fall from 7 to 2 |
| H3 no silent pass on uninspectable content | Supported | 0/20 secrets inside `.tar.xz` shipped (Anti-REA fails closed) |
| H4 loses on formats outside its detectors | Scorer: "not confirmed". **By decision: confirmed** | See the note below |
| H5 fail-closed costs false blocks | Confirmed | It blocked 20/20 clean `.tar.xz` releases; TruffleHog blocked 2/20 |

**Note on H4.** The scorer counts *any* finding as recall, so AR-1 "detected" 7/7 outside-format needles. But all 7 tripped only `lowConfidenceCredentialLead`, which warns, so **all 7 releases shipped**: DigitalOcean, Hugging Face ×3, Anthropic and Shopify ×2. That is exactly the predicted loss. The mechanical verdict is left as-is, because changing the scorer after the run is not allowed.

### Where the 28 AR-1 errors come from

| Family | Errors | Cause |
|---|---|---|
| UNVERIFIABLE-CLEAN | 20 | Anti-REA cannot decode xz, so it fails closed on clean content |
| UNDECLARED-LEAK | 7 | Formats outside its 9 detectors only warn |
| LEAK-DECLARED | 1 | Base64-wrapped secret; no decoder |

**71% of AR-1's errors come from one design choice: failing closed on a format it can't read.** TH-T's 11 errors are spread over five families.

### What Anti-REA measurably does better

Per needle and per family, on the same scenarios:

- **zip nested inside `app.asar`:** 2/2 for Anti-REA, **0/2 for every baseline**, tuned ones included.
- **UTF-16LE strings in a native binary:** 5/5 for Anti-REA, 2/5 for the best baseline (TruffleHog). gitleaks got 0/5.
- **Public-by-design values and documented example keys:** 100% / 100% correct passes. GL-T got 95% / 30%, TH-T 90% / 90%. The asset model avoids false blocks *without putting plaintext values in a config*.
- **Server-only implementations and private artifacts:** 100% / 100%, equal to TH-T. GL-T got 100% / 70%, and the untuned tools 0–15%.
- **Noise and speed:** zero spurious findings, and about 4–6× faster than the baselines (107 ms median against 264–663 ms).
- **As a decision layer (AR-2):** the **lowest false-pass rate measured (2.0%)**. Against TH-T, AR-2 was right where TH-T was wrong in 3 scenarios, and wrong where TH-T was right in 18. Most of those 18 are the UNVERIFIABLE-CLEAN false blocks.

### Interpretation and limits

- These numbers describe **this author-designed corpus**. Its family mix has no known real-world prevalence, so the per-family table matters more than the aggregate. The 20 xz scenarios alone swing AR-1's aggregate by 11 points.
- The tuned baseline configs were written by the author from the same owner facts Anti-REA received. They are published per scenario under `bench/runs/eval/corpus/*/`. A more expert configuration might score higher.
- The dev-set results seen during harness validation already pointed this way. The hypotheses were not changed (§8 of the pre-registration).

### What would have to change, and how it must be tested

These two design gaps explain most of the loss:

1. Decode xz and bzip2, so Anti-REA fails closed only on formats that truly can't be read.
2. Block format-specific leads produced via `--import`, while keeping generic-entropy leads at warn.

Changing them now and re-scoring this corpus would be fitting to the test. Any v0.3 claim needs a **new pre-registration on a fresh seed**.
