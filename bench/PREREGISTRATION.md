# Pre-registration v5: Anti-REA v0.5 vs. current secret scanners (and vs. v0.4) as release gates

**Registered:** 2026-11-07. The eval corpus had not been generated, and no tool had been run on it, at registration time.

Earlier studies, archived:
- [bench/v1/](v1/): v0.1, lost to tuned TruffleHog.
- [bench/v2/](v2/): v0.2, a tie.
- [bench/v3/](v3/): v0.3, 90.0% vs 84.5%, p = 0.16.
- [bench/v4/](v4/): v0.4, 85.0% vs 81.7%, p = 0.35.

**Frozen tool and harness:** frozen-sha256: `88f2bb1ef3a40f75bd660676cd5c81bb9b6fbde1e7f46b5a0dd18191b3d2eb7d`

`node bench/freeze.mjs` computes the hash over:
- `src/`;
- `bench/freeze.mjs`, `bench/corpus.mjs`, `bench/run.mjs` and `bench/score.mjs`;
- `bench/policy.json` and `bench/policy.open.json`;
- `package.json`;
- **`bench/v4/anti-rea-0.4.0/`**, the compiled v0.4 tool exactly as evaluated in v4.

**Eval seed:** the first 32 bits of the frozen hash, `0x88f2bb1e`. `bench/run.mjs --set eval` refuses to run if the tree does not match the hash, or if the corpus seed was not derived from it.

## 1. Questions

1. **Primary (unchanged since v1).** Given the same owner knowledge, is Anti-REA substantially better than current secret scanners at the ship/block decision?
2. **Improvement.** On the same sealed corpus, is v0.5 better than the frozen v0.4?
3. **Generalisation.** Do the v0.5 fixes for v4's diagnosed losses hold on formats and call shapes never used in development? The fixes are listed in [docs/research/V05-CHANGES.md](../docs/research/V05-CHANGES.md):
   - single-case and compound values;
   - any constructor, configuration methods and assigned factory calls;
   - CONSTANT_CASE credential names;
   - DMG reading.

## 2. Systems

The tool versions are the same as v2–v4: gitleaks 8.30.1, TruffleHog 3.99.8, detect-secrets 1.5.0.

The configurations are as in v4, plus one new one:

| Config | Description | Role |
|---|---|---|
| AR-1 | Anti-REA v0.5, asset model | primary |
| **AR-1@0.4** (new) | the v0.4 build, same manifest and policy | same-corpus comparison |
| AR-0 | no owner knowledge | |
| AR-1o | uninspectable content warns | secondary |
| AR-2 | Anti-REA + TruffleHog import | **recommended configuration** |
| GL-D, GL-T | gitleaks, defaults and tuned | baselines |
| TH-D, TH-T | TruffleHog, defaults and tuned | baselines |
| DS-D | detect-secrets | baseline |

Everything runs fully offline, and the decision rule is unchanged.

## 3. Corpus (v5)

**Size:** 9 families × 20 scenarios, plus a forced UNDECLARED-LEAK factorial of 4 strata × 5 styles × **4** (= 80), so **N = 260**.

**New background.** These are real bytes never scanned during v0.5 development, any calibration round, or v1–v4:
- the Zen browser's **toolkit** JavaScript and JSON (`Contents/Resources/omni.ja`; v4 used the separate `browser/omni.ja`);
- Homebrew bash-completion scripts;
- the native addon: slices of Homebrew `libx265`.

The pool holds 1,534 files, with every sha256 recorded in `index.json`.

**DMG is now a readable wrapper:**
- **LEAK-DECLARED** gains W16-dmg (UDZO, HFS+).
- **COMPRESSED-CLEAN** draws 2 of {xz, bz2, zst, deb, lz4, zip-bzip2, **dmg**}.
- **UNVERIFIABLE** and **UNVERIFIABLE-CLEAN** use formats no tool can read without a password: an encrypted zip (ZipCrypto) and an **AES-256 encrypted DMG**.

**Held-out strata (eval pool, new).** Dev uses v4's eval pool, already exposed by the v4 run.

- **HELDOUT-PREFIXED:**

  | Provider | Format |
  |---|---|
  | DeepSeek | `sk-<32 hex>` |
  | Langfuse | `sk-lf-<uuid>` |
  | Anyscale | `esecret_<26 lowercase alnum>` |
  | Fireworks | `fw_<24>` |
  | Together | `tgp_v1_<43 url-safe>` |
  | Notion | `ntn_<11 digits><35>` |
  | Airtable | `pat<14>.<64 hex>` |
  | **Klaviyo** | `pk_<34 hex>` |

  Klaviyo's *private* keys use the `pk_` prefix that most issuers reserve for public keys. It is a deliberate counter-example to Anti-REA's public-prefix rule.

- **HELDOUT-UNPREFIXED:**

  | Provider | Env name | Value shape |
  |---|---|---|
  | fal | `FAL_KEY` | `<uuid>:<32 hex>` |
  | Railway | `RAILWAY_TOKEN` | UUID |
  | Algolia | `ALGOLIA_ADMIN_API_KEY` | 32 hex |
  | Pusher | `PUSHER_APP_SECRET` | 20 hex |
  | Cloudinary | `CLOUDINARY_API_SECRET` | 27 url-safe |
  | Zendesk | `ZENDESK_API_TOKEN` | 40 alnum |
  | Mixpanel | `MIXPANEL_API_SECRET` | 32 hex |
  | Bitly | `BITLY_ACCESS_TOKEN` | 40 hex |

The SDK option, class and factory names for each provider are listed in `bench/corpus.mjs`. They are from the author's memory of the SDKs and **not verified per provider**.

**Render styles** are as in v4, with one change. **Method** calls are drawn by the seeded generator from **12** credential-passing calls from real SDK usage, not v4's fixed 4:
- `analytics.load`, `Bugsnag.start`, `client.login`, `api.setKey`;
- `Purchases.configure`, `posthog.init`, `amplitude.init`, `sgMail.setApiKey`;
- `twitter.setBearerToken`, `octokit.auth`, `sdk.useKey`, `crisp.authenticate`.

v0.5's configuration-verb list was written after v4's misses, so a short fixed list would test the rules against their own design.

## 4. Metrics

The metrics are as in v4: exact Clopper–Pearson intervals, exact McNemar tests, per-family breakdowns, the stratum × style table, spurious findings and median time.

## 5. Hypotheses (scored mechanically by `bench/score.mjs`)

**Primary and superiority**
- **H1 (primary).** AR-1 vs every baseline: Δ ≥ 15 points **and** McNemar p < 0.002.
- **H1b.** AR-1 vs every baseline: Δ > 0 **and** p < 0.01.
- **H1c (recommended configuration).** AR-2 vs every baseline: Δ > 0 **and** p < 0.01.
- **H2.** AR-2's accuracy ≥ AR-1's, **and** AR-2 has strictly fewer UNDECLARED-LEAK false passes.

**Uninspectable content and decoders**
- **H3.** AR-1 has 0 false passes on UNVERIFIABLE.
- **H5 (expected loss).** On UNVERIFIABLE-CLEAN, AR-1 has more false blocks than TH-D.
- **H6 (decoders, now including DMG).** AR-1 is correct on at least 95% of COMPRESSED-CLEAN, **and** every LEAK-DECLARED scenario via W7–W12 or W14–W16 is blocked with its needle found.

**Held-out credentials**
- **H4.** Held-out unprefixed, env or config style (n = 16): AR-1 blocks at least 80%.
- **H4c.** Held-out formats, ctor or method style (n = 32): **at least 70%**. In v4 the target was 50% and the result 5/12.
- **H4d (new).** Held-out formats, bare factory style (n = 16): at least 50%. This was a predicted loss in v4 (0/6).
- **H7.** Held-out secret-marked prefixes (DeepSeek, Langfuse, Anyscale) across all five styles: at least 80%.

**Noise and undeclared leaks**
- **H8 (noise).** AR-1 has at most 20 spurious findings.
- **H9.** UNDECLARED-LEAK correct: AR-1 ≥ TH-T.
- **H9b.** AR-1 beats TH-T on UNDECLARED-LEAK, with McNemar p < 0.05.

**Secondary and improvement**
- **H10 (secondary).** AR-1o vs TH-T: Δ > 0 and p < 0.01.
- **H11 (new, improvement).** AR-1 vs AR-1@0.4 on the same corpus: Δ > 0 and exact McNemar p < 0.01.

**Author's predictions,** reasoned from the rules and the provider table, written before the eval run:
- **H1: not supported.** The UNVERIFIABLE pair cancels out (AR blocks both, the baselines pass both). The gain over TH-T comes mostly from about 80 UNDECLARED scenarios, which is not enough for 15 points.
- **H1b: likely not supported.** TH-T looks beatable at p < 0.01. Tuned gitleaks' generic keyword rules did well on env/config in v4 (dev: AR-1 vs GL-T, p = 0.18).
- **H1c: as H1b.**
- **H2: uncertain.** On dev it tied, 51 vs 51.
- **H3, H5, H6 and H8: supported or confirmed.**
- **H4: likely supported** (about 14/16). fal's `<uuid>:<hex>` is rejected by the value test, a known gap listed in V05-CHANGES §2.
- **H4c: likely supported.**
  - Klaviyo (`pk_`) and fal fail in every style.
  - `api.setKey` and `sdk.useKey` match no method rule.
- **H4d: likely supported.** Klaviyo, fal and Railway fail: Railway's bare UUID is treated as an identifier.
- **H7: likely supported.**
  - DeepSeek through the hex rule.
  - Anyscale through `esecret` plus the single-case body.
  - Langfuse through the keyed and call rules (its UUID body defeats the structural rule).
- **H9 and H9b: likely supported.**
- **H10: likely supported.**
- **H11: likely supported.** v0.4 cannot read DMGs, so it blocks clean DMGs in COMPRESSED-CLEAN, and it misses the single-case, compound and call-style cells.

## 6. Procedure

1. Harness validation on dev only (seed `0x5eed0005`, N = 56).
2. Changes allowed only to harness parsing and invocation, and to baseline-config fairness. **No `src/` change in response to dev results.**
3. Freeze. Then generate the eval corpus and run everything once.

## 7. Threats to validity

- **The author designed the corpus, the provider table and the tool.**
  - The v0.5 call rules were designed after seeing v4's call-style misses. v5 counters this with new providers, new SDK names and a broader, seeded method list. But the author picked those too, knowing the rules.
  - **Per-cell results and the AR-1@0.4 comparison are primary for interpretation.**
- **DMG favours Anti-REA.** No baseline reads DMG, so W16-dmg and clean-DMG scenarios favour Anti-REA by construction, as earlier decoder families did. DMG is, however, the standard macOS release format.
- **Calibration history** (see [docs/research/CALIBRATION.md](../docs/research/CALIBRATION.md), round 5):
  - The v0.5 rules were tuned on sets A, C and D, all of which were already tuning data.
  - They were validated once on a **new set E** (7.6 GB). **E failed:**
    - 690 structural leads in mingw-w64's GCC binaries, from a v0.2 bug in which `[a-z]*sk` matched "mask";
    - 30 keyed leads, which were OAuth client secrets shipped in Adobe apps, so true leads.
  - The mask bug was fixed after E, so **E is tuning data now.** The v5 background is the next unseen data.
- **Unverified SDK naming.** Provider class, factory and option names are from memory.
- **Background from installed applications.** The bytes are machine-specific; their sha256s are recorded.
- **Cells are small** (4 per cell).

## 8. Amendments and dev-set disclosure

None. One note: the dev run used src/version.ts at "0.4.0"; the version string was bumped to 0.5.0 before freezing, which changes no rule.

**Dev-set disclosure** (N = 56):

| Config | Correct |
|---|---|
| AR-1 | 51/56 (91.1%) |
| AR-1o | 51/56 |
| AR-2 | 51/56 |
| AR-1@0.4 | 46/56 (82.1%) |
| GL-T | 45/56 |
| AR-0 | 43/56 |
| TH-T | 41/56 (73.2%) |
| TH-D | 32/56 |
| GL-D | 27/56 |
| DS-D | 23/56 |

Results on dev:
- **Supported or confirmed:** H3, H4 (2/2), H4c (3/4), H4d (2/2), H5, H6, H8, H9, H9b (9 : 0, p = 0.004) and H10.
- **Not supported:** H1, H1b (GL-T p = 0.18; TH-T p = 0.03), H1c, H2 (a tie) and H11 (5 : 0, p = 0.06).
- **Not evaluable:** H7, because the dev pool has no eval-marked providers.

AR-1's 5 dev errors:
- **4 are UNVERIFIABLE-CLEAN**, by design.
- **1 is a recall miss** (S034): `setApiKey("rnd_<32>")`, whose random body happened to have a word-run fraction of 0.50, above the 0.45 limit. This is the ~4.5% loss measured for 32-character values. It was not changed, because changing `src/` in response to dev results isn't allowed.

The single spurious finding for every Anti-REA configuration is a warn-only JWT-shaped string in the Firefox toolkit background (`aboutLogging/jwt.mjs`).

## 9. Post-run errata (no effect on any verdict)

These were added after the eval run. The thresholds and the scoring code are unchanged.
- **Wrong sample sizes in §5.** The n values double-counted the cells. With 4 scenarios per cell, the counts are:
  - H4 (one stratum × 2 styles): **8**, not 16;
  - H4c (2 strata × 2 styles): **16**, not 32;
  - H4d (2 strata × 1 style): **8**, not 16.
  
  The hypotheses are percentage thresholds computed by `score.mjs` from the actual cells, so no verdict depends on these figures.
- **One AR-1 miss was not in the predictions:** Airtable in env style (`AIRTABLE_PAT`). "PAT" is not a credential noun. The author noticed this while reasoning about the provider table but did not write it into §5.
