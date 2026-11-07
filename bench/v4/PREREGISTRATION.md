# Pre-registration v4: Anti-REA v0.4 vs. current secret scanners as release gates

**Registered:** 2026-11-07. The eval corpus had not been generated, and no tool had been run on it, at registration time.

Earlier studies, archived:
- [bench/v1/](../v1/): v0.1, H1 not supported. Tuned TruffleHog was significantly better.
- [bench/v2/](../v2/): v0.2, H1 not supported. Statistically tied with tuned TruffleHog and gitleaks.
- [bench/v3/](../v3/): v0.3, H1 not supported. 90.0% against tuned TruffleHog's 84.5% (p = 0.16).

**Frozen tool and harness:** frozen-sha256: `d261b18be86df483434431b659da310e4d4d6b92a481ebe1647f4b45c4660157`

`node bench/freeze.mjs` computes the hash over `src/`, `bench/freeze.mjs`, `bench/corpus.mjs`, `bench/run.mjs`, `bench/score.mjs`, `bench/policy.json`, `bench/policy.open.json` and `package.json`.

**Eval seed:** the first 32 bits of the frozen hash, `0xd261b18b`. `bench/run.mjs --set eval` refuses to run if the tree does not match the hash, or if the corpus seed was not derived from it.

## 1. Question

**Primary.** Given the same owner knowledge, is Anti-REA substantially better than current secret scanners at the ship/block decision? This is unchanged since v1.

**Secondary.** v3 never tested credentials passed to code instead of assigned to a key (its random draw produced 2 call-style scenarios, both known formats). Do the v0.4 changes close that gap on formats never used in development? The changes are listed in [docs/research/V04-CHANGES.md](../../docs/research/V04-CHANGES.md):
- `*_KEY` constant names and more key nouns;
- detection of credentials passed to credential-named functions and API client constructors;
- hex bodies behind strong secret markers;
- false-lead guards.

## 2. Systems

The tool versions and configurations are the same as v2 and v3: gitleaks 8.30.1, TruffleHog 3.99.8, detect-secrets 1.5.0. The configurations are AR-0, AR-1 (primary), AR-1o (secondary), AR-2, GL-D, GL-T, TH-D, TH-T and DS-D. The tuned gitleaks and TruffleHog configs carry the same owner knowledge as in v3, including amendment A1. Everything runs fully offline, and the decision rule is unchanged.

## 3. Corpus (v4)

**Size.** There are 9 families × 20 scenarios, plus a forced UNDECLARED-LEAK factorial of 60, so **N = 240**. Family definitions are v3's.

**New background.** These are real bytes never scanned during v0.4 development or calibration, and never used in v1–v3:
- the Zen browser's front-end JavaScript and JSON, extracted from `browser/omni.ja`;
- the Zig 0.17 standard library's `.zig` sources;
- the native addon: 1 MiB slices of Homebrew ffmpeg's `libavcodec` plus its Mach-O header.

The pool holds 2,401 files. `index.json` records the sha256 of every pool file, of `omni.ja` and of the native source.

**UNDECLARED-LEAK is now forced, not drawn.** Every stratum × render-style cell gets exactly 3 scenarios: 4 strata × 5 styles × 3 = 60. Within a stratum, providers rotate in table order from a seeded offset.

**Strata:**
- **INSIDE** and **NAMED**: as in v3.
- **HELDOUT-PREFIXED (eval pool, new):**

  | Provider | Format |
  |---|---|
  | LangSmith | `lsv2_sk_<32 hex>_<10 hex>` |
  | OpenRouter | `sk-or-v1-<64 hex>` |
  | Cerebras | `csk-<48 lowercase alnum>` |
  | Firecrawl | `fc-<32 hex>` |
  | Jina | `jina_<60>` |
  | Brevo | `xkeysib-<64 hex>-<16>` |
  | Render | `rnd_<32>` |
  | Resend | `re_<8>_<24>` |

- **HELDOUT-UNPREFIXED (eval pool, new):**

  | Provider | Env name | Value shape |
  |---|---|---|
  | Datadog | `DD_API_KEY` | 32 hex |
  | AssemblyAI | | 32 hex |
  | Weights & Biases | | 40 hex |
  | Exa | | UUID |
  | Ably | | `app.key:secret` |
  | Upstash | `UPSTASH_REDIS_REST_TOKEN` | |
  | Mux | `MUX_TOKEN_SECRET` | 75-character base64 |
  | Mailjet | `MJ_APIKEY_PRIVATE` | 32 hex |

The **dev** set uses v3's held-out formats instead (already exposed by the v3 run). Dev and eval provider pools are disjoint. None of the eval-pool formats appeared in any detector development or calibration.

**Render styles**, defined in `bench/corpus.mjs`. Each provider entry lists its env name, config option, client class and factory. The names follow the providers' SDK conventions as the author recalls them; they are **not verified per provider**.
- **env**: `DD_API_KEY = "…"`, or the wrapper's JSON or env-file form.
- **config**: `{"provider": "…", "<SDK option>": "…"}`. The option is the provider's own, such as `apiKey`, `key`, `token`, `tokenSecret` or `apiSecret`.
- **ctor**: `new <SDK class>("…")`. The classes are: `Client`, `OpenRouter`, `Cerebras`, `FirecrawlApp`, `JinaClient`, `TransactionalEmailsApi`, `RenderApi`, `Resend`, `ApiClient`, `AssemblyAI`, `Api`, `Exa`, `Ably.Realtime`, `Redis`, `Mux` and `Mailjet.Client`.
- **method**: `<obj>.<method>("…")`. The method rotates over `setApiKey`, `init`, `setToken` and `authenticate`, so half are credential-named.
- **bare**: `<factory>("…")`. There is no credential signal at all.

**Other wrappers** are as in v3. UNVERIFIABLE and UNVERIFIABLE-CLEAN use encrypted zip and DMG.

## 4. Metrics

The metrics are the same as v3: exact Clopper–Pearson intervals, exact McNemar tests, per-family breakdowns, spurious findings and median time. v4 adds a **stratum × style table** for UNDECLARED-LEAK.

## 5. Hypotheses (scored mechanically by `bench/score.mjs`)

- **H1 (primary).** For every baseline, Δ ≥ 15 points **and** McNemar p < 0.002.
- **H1b.** For every baseline, Δ > 0 **and** p < 0.01.
- **H2.** AR-2's accuracy ≥ AR-1's, **and** AR-2 has strictly fewer UNDECLARED-LEAK false passes.
- **H3.** AR-1 has 0 false passes on UNVERIFIABLE.
- **H4 (keyed detector generalises).** On held-out unprefixed formats in env or config style (n = 6), AR-1 blocks at least 80%.
- **H4c (call styles, new).** On both held-out strata in ctor or method style (n = 12), AR-1 blocks at least 50%. Bare style is a **predicted loss**; it is reported, not scored.
- **H5 (expected loss).** On UNVERIFIABLE-CLEAN, AR-1 has more false blocks than TH-D.
- **H6 (decoders).** AR-1 is correct on at least 95% of COMPRESSED-CLEAN, **and** every LEAK-DECLARED scenario via W7–W12, W14 or W15 is blocked with its needle found.
- **H7 (held-out secret-marked prefixes).** OpenRouter, LangSmith and Cerebras are blocked at least 80% of the time **across all five styles**.
- **H8 (noise).** AR-1 has at most 20 spurious findings in total.
- **H9.** AR-1's correct decisions on UNDECLARED-LEAK are at least TH-T's.
- **H9b (new).** AR-1 beats TH-T on UNDECLARED-LEAK, with exact McNemar p < 0.05 within the family.
- **H10 (secondary, new).** AR-1o vs TH-T over all scenarios: Δ > 0 and p < 0.01.

**Author's predictions,** reasoned from the rules and the provider table, written before the eval run:
- **H1: not supported.** The 20 UNVERIFIABLE-CLEAN false blocks are by design, so AR-1 can reach at most 220/240.
- **H1b: uncertain.**
- **H3, H5, H6 and H8: supported or confirmed.**
- **H4: likely not supported.** Ably's `.`/`:` format is outside the keyed value charset. `MJ_APIKEY_PRIVATE` ends in no credential noun. The config option `key` (W&B, Ably) is not a noun. That gives about 6/8 per style, before the ~5% random-value recall loss.
- **H4c: borderline.**
  - Constructors match for `Client`, `JinaClient`, `TransactionalEmailsApi`, `RenderApi`, `ApiClient`, `Api` and `Mailjet.Client`, and OpenRouter is caught structurally.
  - Methods are matched only for `setApiKey` and `setToken`.
- **H7: likely not supported.**
  - OpenRouter: every style, via the hex rule.
  - LangSmith: missed in bare style; its hex body defeats the structural rule.
  - Cerebras: lowercase-only, so the structural rule rejects it; caught only under key names or `setApiKey`/`setToken`.
- **H9: uncertain.** TruffleHog's keyword detectors may cover several held-out providers (Brevo, Resend, Datadog, Ably, Mailjet, Mux, AssemblyAI) in every style.
- **H9b and H10: uncertain.**

## 6. Procedure

1. Harness validation on dev only (seed `0x5eed0004`): 4 per family, and 1 per UNDECLARED cell, so N = 56.
2. Changes allowed only to harness parsing and invocation, and to the baseline configs' fairness. **No `src/` change in response to dev results.**
3. Freeze. Then generate the eval corpus and run everything once.

## 7. Threats to validity

- **The author designed the corpus, the provider table and the tool.**
  - The detector rules were written before the eval provider table. But the table's class and method names were chosen by the author, who knows the rules.
  - The ctor and method predictions above are therefore close to mechanical. What the run adds is measured behaviour: end-to-end recall on random values, the effect of wrappers, and above all the **baselines' behaviour**, which the author cannot predict.
  - Per-cell results are primary for interpretation.
- **Unverified SDK naming.** Provider class, factory and option names are from memory, not checked against each SDK.
- **Calibration history** (see [docs/research/CALIBRATION.md](../../docs/research/CALIBRATION.md), round 4):
  - The v0.4 rules were tuned on set A.
  - Validation set C exposed false leads, which were fixed.
  - Validation set D then exposed more: a CamelCase identifier, a repetitive pattern, and a published Supabase local-dev key. Those were fixed after D, so **D is no longer a clean held-out result.** The v4 background is the next unseen data.
  - One correction came while writing the provider table: plain `new Client(…)` had not matched the constructor rule, contrary to the rule's stated intent.
- **Background from installed applications.** The bytes are machine-specific and auditable by sha256, but not redistributable.
- **Strata cells are small** (3 per cell). Hypotheses pool cells: H4 n = 6, H4c n = 12, H7 about 6.

## 8. Amendments and dev-set disclosure

None yet.

**Dev-set disclosure** (N = 56):

| Config | Correct |
|---|---|
| AR-2 | 49/56 |
| AR-1 | 47/56 |
| AR-1o | 47/56 |
| TH-T | 44/56 |
| GL-T | 42/56 |
| AR-0 | 39/56 |
| TH-D | 36/56 |
| GL-D | 26/56 |
| DS-D | 25/56 |

Results on dev:
- **H1, H1b, H9b and H10:** not supported.
- **H2, H3, H4c, H6, H8 and H9:** held.
- **H5:** confirmed.
- **H4:** 1/2, not supported.
- **H7:** not evaluable, because the dev pool has no eval-marked providers.

AR-1's 9 dev errors:
- **4 are UNVERIFIABLE-CLEAN**, by design.
- **4 are predicted misses:**
  - `new Perplexity("…")`;
  - two bare calls;
  - Deepgram under the config option `key`.
- **1 is a real recall miss** (S034): `sdk.setApiKey("tvly-…")`. The random value together with its `tvly-` prefix exceeds `generatedValue`'s word-run limit of 0.45, so it is rejected. This is the ~5% random-value recall loss measured in calibration. It was deliberately not changed, because that would be a `src/` change in response to dev results.
