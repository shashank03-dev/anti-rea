# Pre-registration v6: Anti-REA v0.6 vs. current secret scanners (and vs. v0.5), plus a platform sub-study

**Registered:** 2026-11-07. The eval corpora (main and platform) had not been generated, and no tool had been run on them, at registration time.

Earlier studies, archived:
- [bench/v1/](v1/): v0.1, lost to tuned TruffleHog.
- [bench/v2/](v2/): v0.2, a tie.
- [bench/v3/](v3/): v0.3, 90.0% vs 84.5%, p = 0.16.
- [bench/v4/](v4/): v0.4, 85.0% vs 81.7%, p = 0.35.
- [bench/v5/](v5/): v0.5, 89.2% vs 80.8%, p = 0.013. The recommended AR-2 configuration reached 91.2% (p = 0.0013).

**Frozen tool and harness:** frozen-sha256: `6099fbf64928e75cfac18a16ba74bca86693ebb8dbd9989e6b5de7219e54dfb0`

`node bench/freeze.mjs` computes the hash over:
- `src/`;
- `bench/freeze.mjs`, `bench/corpus.mjs`, `bench/run.mjs`, `bench/score.mjs` and **`bench/platform.mjs`**;
- `bench/policy.json`, `bench/policy.open.json` and **`bench/policy.platform.json`**;
- `package.json`;
- `bench/v4/anti-rea-0.4.0/` and **`bench/v5/anti-rea-0.5.0/`**, the compiled v0.4 and v0.5 tools as evaluated.

**Eval seeds:**
- main corpus: the first 32 bits of the frozen hash, `0x6099fbf6`;
- platform corpus: bits 32–63, `0x4928e75c`.

`bench/run.mjs --set eval` and `bench/platform.mjs --set eval` refuse to run if the tree does not match the hash, or if the corpus seed was not derived from it.

## 1. Questions

1. **Primary (unchanged since v1).** Given the same owner knowledge, is Anti-REA substantially better than current secret scanners at the ship/block decision?
2. **Regression.** On the same sealed corpus, does v0.6 lose anything v0.5 got right? v0.6's content-lane changes are small:
   - three detector fixes for v5's misses;
   - symlinks recorded as notes;
   - a Hugging Face format guard from calibration set F.
   
   See [docs/research/V06-CHANGES.md](../docs/research/V06-CHANGES.md).
3. **Generalisation.** Do the detectors hold on 16 provider formats never used in development or in any earlier benchmark?
4. **Platform (new).** Does the v0.6 platform lane decide correctly on signed macOS/Electron bundles? Does it agree with `codesign(1)` on tampering? Does it beat a scripted `codesign` policy check?

## 2. Systems

Tool versions are the same as v2–v5: gitleaks 8.30.1, TruffleHog 3.99.8, detect-secrets 1.5.0.

Main study: the configurations are as in v5, plus **AR-1@0.5**.

| Config | Description | Role |
|---|---|---|
| AR-1 | Anti-REA v0.6, asset model | primary |
| **AR-1@0.5** (new) | the v0.5 build, same manifest and policy | regression comparison |
| AR-1@0.4 | the v0.4 build | earlier comparison |
| AR-0 | no owner knowledge | |
| AR-1o | uninspectable content warns | secondary |
| AR-2 | Anti-REA + TruffleHog import | **recommended configuration** |
| GL-D, GL-T | gitleaks, defaults and tuned | baselines |
| TH-D, TH-T | TruffleHog, defaults and tuned | baselines |
| DS-D | detect-secrets | baseline |

Platform sub-study:

| Config | Description |
|---|---|
| AR-1 | Anti-REA v0.6. The manifest declares `platform.macos.requireHardenedRuntime`, `platform.electron.fuses.RunAsNode = false` and `platform.electron.requireAsarIntegrity`. The policy requires the platform lane. |
| CS-D | `codesign --verify --deep --strict` |
| CS-T | CS-D, plus the hardened-runtime flag from `codesign -dvvv`, plus a forbidden-entitlement check from `codesign -d --entitlements`, using the same three entitlements as Anti-REA's default. This is the check a release engineer would script. |

Everything runs fully offline, and the decision rule is unchanged.

## 3. Main corpus (v6)

**Size:** as in v5. There are 9 families × 20 scenarios, plus the forced UNDECLARED-LEAK factorial of 4 strata × 5 styles × 4 (= 80), so **N = 260**. The families and wrappers are unchanged; DMG wrappers were added in v5.

**New background.** These are real bytes never scanned during v0.6 development, in any calibration round (A–F), or in v1–v5:
- Homebrew git 2.56.0's `share/` tree: AsciiDoc and HTML docs, man pages, perl modules, gitweb, hook templates, bash/zsh completion and message catalogs;
- abseil's C++ headers;
- the native addon: slices of Homebrew `libvpx`.

The pool holds 1,333 files, with every sha256 recorded in `index.json`.

**Held-out strata.** Dev uses v5's eval pool, already exposed by the v5 run. The eval pool is new:

- **HELDOUT-PREFIXED:**

  | Provider | Format |
  |---|---|
  | Groq | `gsk_<52>` |
  | xAI | `xai-<80>` |
  | Perplexity | `pplx-<48>` |
  | Replicate | `r8_<37>` |
  | Linear | `lin_api_<40>` |
  | Doppler | `dp.st.prd.<43>` |
  | Pinecone | `pcsk_<5>_<60>` |
  | **Mapbox secret** | `sk.eyJ1Ijoi…` (a JWT-like base64url body with `.` separators) |

- **HELDOUT-UNPREFIXED:**

  | Provider | Env name | Value shape |
  |---|---|---|
  | Mistral | `MISTRAL_API_KEY` | 32 alnum |
  | Cohere | `CO_API_KEY` | 40 alnum |
  | ElevenLabs | `ELEVENLABS_API_KEY` | 32 hex |
  | **Postmark** | `POSTMARK_SERVER_TOKEN` | UUID |
  | Contentful | `CONTENTFUL_ACCESS_TOKEN` | 43 url-safe |
  | Twilio | `TWILIO_AUTH_TOKEN` | 32 hex |
  | Segment | `SEGMENT_WRITE_KEY` | 32 alnum |
  | Okta | `OKTA_API_TOKEN` | `00<40 url-safe>` |

Two are deliberate counter-examples:
- **Mapbox:** the `.` separators and JWT shape;
- **Postmark:** a bare UUID, the shape v0.6 still treats as an identifier when it is passed positionally. The v5 Railway miss was not fixed.

Linear has a dedicated format detector in Anti-REA. It is also likely known to gitleaks and TruffleHog.

SDK option, class and factory names are from the author's memory and are **not verified**. The render styles and the 12 seeded method calls are the same as v5.

## 3b. Platform corpus (new)

Each scenario is an `Example.app` bundle:
- its main executable is a copy of `/usr/bin/true` (universal);
- it contains an `app.asar` holding real background bytes, with a matching `ElectronAsarIntegrity` entry in Info.plist;
- it contains an Electron fuse wire file;
- it has three real background files as resources.

Every bundle is ad-hoc signed by `codesign` with the hardened runtime unless stated otherwise. Then it is left alone or tampered with.

| Family (truth) | Kinds | Eval n |
|---|---|---|
| P-CLEAN (pass) | intact | 20 |
| P-TAMPER (block) | modified resource, added file, deleted resource, modified code page (every slice), modified Info.plist, modified `app.asar` header | 6 × 4 = 24 |
| P-HARDENING (block) | signed with `get-task-allow`, signed without the hardened runtime, `RunAsNode` fuse enabled, ASAR integrity hash wrong (signed afterwards) | 4 × 4 = 16 |

The order is seeded, N = 60, and dev N = 15.

## 4. Metrics

Main study: as in v5. Platform study: accuracy per config and per kind, and exact McNemar tests.

## 5. Hypotheses (scored mechanically by `bench/score.mjs` and `bench/platform.mjs --score`)

Thresholds are as in v5 unless stated otherwise. The sample sizes below are the actual cell counts: 4 per stratum × style cell.

**Primary and superiority**
- **H1 (primary).** AR-1 vs every baseline: Δ ≥ 15 points **and** McNemar p < 0.002.
- **H1b.** AR-1 vs every baseline: Δ > 0 **and** p < 0.01.
- **H1c (recommended configuration).** AR-2 vs every baseline: Δ > 0 **and** p < 0.01.
- **H2.** AR-2 accuracy ≥ AR-1 **and** strictly fewer UNDECLARED-LEAK false passes.

**Uninspectable content and decoders**
- **H3.** AR-1 has 0 false passes on UNVERIFIABLE.
- **H5 (expected loss).** On UNVERIFIABLE-CLEAN, AR-1 has more false blocks than TH-D.
- **H6.** COMPRESSED-CLEAN ≥ 95% correct, **and** every LEAK-DECLARED scenario via W7–W12 or W14–W16 is blocked with its needle found.

**Held-out credentials**
- **H4.** Held-out unprefixed, env or config style (n = 8): at least 80%.
- **H4c.** Held-out formats, ctor or method style (n = 16): at least 70%.
- **H4d.** Held-out formats, bare style (n = 8): at least 50%.
- **H7.** Held-out secret-marked prefixes (**Groq `gsk_`, Pinecone `pcsk_`, Mapbox `sk.`**) across all five styles: at least 80%.

**Noise and undeclared leaks**
- **H8.** AR-1 has at most 20 spurious findings.
- **H9.** UNDECLARED-LEAK correct: AR-1 ≥ TH-T.
- **H9b.** On UNDECLARED-LEAK, AR-1 is ahead of TH-T with p < 0.05.

**Secondary and regression**
- **H10.** AR-1o vs TH-T: Δ > 0 and p < 0.01.
- **H11 (changed: regression, not significance).** AR-1 vs AR-1@0.5: Δ ≥ 0 **and 0 scenarios that v0.5 got right and v0.6 gets wrong.** v0.6's content-lane changes are too small for a significance test to be meaningful.
- **H11b.** AR-1 vs AR-1@0.4: Δ > 0 and p < 0.01.

**Platform (new)**
- **H12.** AR-1 is correct on at least 95% of the 60 platform scenarios.
- **H12b.** AR-1 and CS-D make the same decision on every P-CLEAN and P-TAMPER scenario (44/44).
- **H12c.** AR-1 vs CS-T: AR-1 ahead **and** exact McNemar p < 0.01.

**Author's predictions,** reasoned from the rules and the provider tables, written before the eval run. The detector was not run on samples of the eval formats.

**Main study**
- **H1: not supported**, for the same structural reason as v5. The UNVERIFIABLE pair cancels out, and about 80 UNDECLARED scenarios are too few for 15 points.
- **H1b: uncertain.** v5 was p = 0.013 against TH-T, and the new providers change the cells.
- **H1c: likely supported,** as in v5.
- **H2: uncertain.**
- **H3, H5, H6 and H8: supported or confirmed.** For H8, git's credential documentation contains example URL passwords. These would be warn-only spurious findings.
- **H4: likely supported.** Every unprefixed provider has a credential-noun name.
- **H4c: likely supported.** The expected misses are Postmark ctor and method (positional UUID), plus `api.setKey` and `sdk.useKey` draws, which no method rule matches (dev miss S039).
- **H4d: likely supported.** Postmark fails (bare UUID).
- **H7: uncertain.**
  - Groq and Pinecone should match the structural marker rule (`[a-z]{0,3}sk`) in every style.
  - Mapbox's `sk.` with a JWT-like dotted body may be read as a JWT or as a member expression when unquoted. If it fails outside the keyed styles, H7 falls below 80%.
- **H9: likely supported. H9b: uncertain. H10: likely supported.**
- **H11: likely supported.** The only v0.6 change that can turn a correct v0.5 block into a miss is the Hugging Face guard. It rejects about 0.6% of random tokens, and Hugging Face appears in about 2–3 NAMED scenarios. That gives about a 2% chance of one regression.
- **H11b: likely supported,** because v0.4 cannot read DMGs.

**Platform study**
- **H12: supported (60/60). H12b: supported.**
- **H12c: likely supported, by construction:**
  - CS-T does not read Electron fuses or ASAR integrity, so the 8 RunAsNode and integrity-mismatch scenarios go 8 : 0 to AR-1, with p = 0.0078.
  - This measures the value of declaring Electron hardening in one gate. It is **not** a claim that `codesign` is wrong: those bundles are validly signed.

## 6. Procedure

1. Harness validation on dev only: main seed `0x5eed0006` with N = 56, and platform seed `0x91a7f006` with N = 15.
2. Changes allowed only to harness parsing and invocation, and to baseline-config fairness. **No `src/` change in response to dev results.**
3. Freeze. Then generate both eval corpora and run everything once.

## 7. Threats to validity

- **The author designed the corpora, the provider tables, the platform kinds and the tool.** The platform kinds map one-to-one onto rules the author wrote. H12 and H12c therefore test correctness of implementation against `codesign` and the declared policy, not discovery of unknown attacks. **H12b is the externally referenced check.**
- **Calibration history** ([docs/research/CALIBRATION.md](../docs/research/CALIBRATION.md), round 6):
  - The v0.6 rules re-ran over sets A–E (17.1 GB, all tuning data) with results identical to v0.5's final run.
  - **Validation set F failed** (1.58 GB, never scanned before: `/System/Applications` and 11 Homebrew packages). It produced **1 false blocking lead**: Objective-C `hf_…` selectors in Home.app matched the Hugging Face format.
  - A guard was added afterwards: CamelCase coverage ≥ 0.7 and vowel share ≥ 0.28. Its recall cost on random tokens was measured at 0.6%.
  - **F is tuning data now.** The v6 background is the next unseen data.
- **Unverified SDK naming and key shapes,** from the author's memory.
- **The platform bundles are ad-hoc signed** copies of a system binary, not Developer-ID-signed apps. Chain trust is out of scope for both Anti-REA and the CS configs here.
- **Background from installed packages.** The bytes are machine-specific; sha256s are recorded.
- **Small cells** (4 per cell; 4 per platform kind).

## 8. Amendments and dev-set disclosure

**Dev-set disclosure, main** (N = 56). These are the results after the Hugging Face guard from calibration set F. The run was repeated because that `src/` change came from calibration, not from dev results. The guard changed no dev decision.

| Config | Correct |
|---|---|
| AR-1 | 51/56 (91.1%) |
| AR-1o | 51/56 |
| AR-2 | 51/56 |
| AR-1@0.5 | 49/56 (87.5%) |
| AR-1@0.4 | 45/56 |
| TH-T | 45/56 (80.4%) |
| AR-0 | 43/56 |
| GL-T | 40/56 |
| TH-D | 38/56 |
| GL-D | 27/56 |
| DS-D | 21/56 |

Results on dev:
- **Supported or confirmed:** H3, H4 (2/2), H4c (3/4), H4d (2/2), H5, H6, H8, H9 and H11 (2 : 0, no regressions).
- **Not supported:** H1, H1b (TH-T p = 0.18), H1c, H2 (a tie), H9b (4 : 0, p = 0.125), H10 (p = 0.03) and H11b (6 : 0, p = 0.03).
- **Not evaluable:** H7.

AR-1's 5 dev errors:
- 4 are UNVERIFIABLE-CLEAN, by design.
- 1 is Cloudinary via `api.setKey("…")` (S039), a method name no rule matches. It was not changed (no `src/` change in response to dev).

**Dev-set disclosure, platform** (N = 15):
- AR-1 15/15, CS-D 11/15, CS-T 13/15.
- H12 and H12b supported.
- H12c not supported on dev (2 : 0, p = 0.5; dev has one scenario per kind).
