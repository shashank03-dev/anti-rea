# Pre-registration v2: Anti-REA v0.2 vs. current secret scanners as release gates

**Registered:** 2026-11-06. The eval corpus had not been generated, and no tool had run on it, at registration time. The v1 study, which evaluated v0.1 and found H1 *not supported*, is archived in [bench/v1/](v1/).

**Frozen tool and harness:** frozen-sha256: `8921d50f945022ef968d1782e466e3b43e127839c983f08cbe633ebb172c2e60`

`node bench/freeze.mjs` computes the hash over `src/`, `bench/freeze.mjs`, `bench/corpus.mjs`, `bench/run.mjs`, `bench/score.mjs`, `bench/policy.json`, `bench/policy.open.json` and `package.json`.

`bench/run.mjs --set eval` refuses to run in two cases:
- the tree does not match this hash;
- the corpus seed was not derived from this hash.

**Eval seed.** The seed is the first 32 bits of the frozen hash, so it is fixed by the code under test and cannot be chosen afterwards. Its value is `0x8921d50f`.

## 1. Question

The question is unchanged from v1. Given the **same owner knowledge**, is Anti-REA substantially more accurate than current secret scanners at the ship/block decision for a release?

v2 adds a second question. Do the v0.2 changes fix the two causes of v0.1's v1 loss, and do they generalise to formats the author did not tune for?

## 2. Systems and configurations

The systems are the same as v1, at the same tool versions: gitleaks 8.30.1, TruffleHog 3.99.8 and detect-secrets 1.5.0. Everything runs fully offline. The tuned baseline configs are generated from the same owner facts as the manifest, as in v1.

| ID | System | Configuration |
|---|---|---|
| AR-0 | Anti-REA v0.2 | no owner knowledge |
| AR-1 | Anti-REA v0.2 | owner asset model, default gates (**primary**) |
| AR-1o | Anti-REA v0.2 | as AR-1, but `requiredLaneInconclusive: warn`. **Secondary, report only.** It shows the cost and benefit of failing closed. |
| AR-2 | Anti-REA v0.2 | AR-1 plus the imported TH-D findings |
| GL-D / GL-T | gitleaks | defaults / tuned (archives depth 8, decode depth 5, owner rules and allowlist) |
| TH-D / TH-T | trufflehog | defaults / tuned (owner custom detectors, `--fail-on-scan-errors`) |
| DS-D | detect-secrets | defaults |

The decision rule is the same as v1. Anti-REA blocks on exit 2 (or any other non-zero exit). A baseline blocks on any finding or a non-zero exit.

## 3. Corpus (v2)

`node bench/corpus.mjs --set eval` generates 20 scenarios per family over 10 families, so **N = 200**. The background is the same as v1: real third-party bytes and a real `libnode` slice.

Every undeclared credential is rendered with a provider-named variable (for example `GROQ_API_KEY = "…"`). That gives keyword-based detectors such as TruffleHog's their usual context. v1 used a generic `SERVICE_TOKEN` name.

| Family | Truth | Content |
|---|---|---|
| CLEAN | pass | background only |
| LEAK-DECLARED | block | one declared server-only credential (the v1 set) in one of **12** wrappers: plain, asar, zip, zip-in-asar, tar.gz, UTF-16LE in a native binary, base64, **tar.xz, tar.bz2, tar.zst, .deb (ar + data.tar.xz), percent-encoded in a URL** |
| PUBLIC-DECLARED | pass | as v1 |
| SERVER-IMPL | block | declared server-only markers in asar, zip, tar.gz, **tar.xz or tar.bz2** |
| PRIVATE-ARTIFACT | block | as v1 |
| UNDECLARED-LEAK | block | one undeclared credential, with a stratum drawn uniformly from four (listed below) |
| UNVERIFIABLE | block | a declared credential inside an **encrypted zip** (ZipCrypto) or an **lz4** tarball. Anti-REA v0.2 cannot read either. |
| UNVERIFIABLE-CLEAN | pass | the same two wrappers, holding only real background bytes |
| EXAMPLE-DOCS | pass | as v1 |
| **COMPRESSED-CLEAN** | pass | two of {tar.xz, tar.bz2, tar.zst, .deb} holding only real background bytes |

The four UNDECLARED-LEAK strata:
- **INSIDE:** formats v0.1 already detected (PEM, GitHub, Slack, Stripe live, AWS).
- **NAMED-V2:** v1's eight "outside" formats. v0.2 added named detectors for them **after seeing v1**, so this stratum is *not* held out.
- **HELDOUT-PREFIXED:** real prefixed formats with **no** named Anti-REA detector: Groq `gsk_`, Replicate `r8_`, Fly `fo1_`, PlanetScale `pscale_tkn_`, Notion `secret_`, Supabase `sbp_` (hex), Resend `re_`, Figma `figd_`.
- **HELDOUT-UNPREFIXED:** formats with no distinctive prefix: Mailchimp, Datadog, Cloudflare, Heroku (UUID), Algolia, Twilio auth token, Vercel.

Selection of the held-out formats: the author chose them from memory as well-known SaaS credentials, before generating any corpus that contains them. The author also knew which ones the structural rule's secret-marker list would match. They are not a random sample of real-world formats.

## 4. Metrics

Same as v1: release-decision accuracy with exact Clopper–Pearson 95% intervals, and exact McNemar tests against each baseline. Also reported: per-family accuracy, needle recall per wrapper and stratum, false-block and false-pass rates, spurious findings, tool errors and median time.

## 5. Hypotheses and decision criteria

`bench/score.mjs` scores all of these mechanically.

- **H1 (primary, "substantially better").** This is the same bar as v1. For **every** baseline, AR-1 minus the baseline must be at least 15 percentage points, **and** the McNemar p-value must be below 0.002.
- **H1b (secondary, superiority).** For every baseline, AR-1 minus the baseline must be greater than 0, with p below 0.01 (0.05/5).
- **H2 (composition).** AR-2's accuracy must be at least AR-1's, **and** AR-2 must have strictly fewer UNDECLARED-LEAK false passes.
- **H3 (no silent pass).** AR-1 must have 0 false passes on UNVERIFIABLE.
- **H4 (expected loss).** On HELDOUT-UNPREFIXED scenarios, AR-1 is expected to make fewer correct **release decisions** than TH-T. v1's H4 scored needle recall, which counted warn-only detections as hits; v2 scores decisions.
- **H5 (expected loss).** On UNVERIFIABLE-CLEAN, AR-1 is expected to have more false blocks than TH-D.
- **H6 (v0.2 fixes work).** Both of these must hold:
  - AR-1 is correct on at least 95% of COMPRESSED-CLEAN;
  - every LEAK-DECLARED scenario using wrappers W7–W12 is blocked, with its needle found.
- **H7 (structural rule generalises).** On HELDOUT-PREFIXED scenarios with a secret-marked prefix (Groq, PlanetScale, Notion), AR-1 must block at least 80%. **Predicted loss:** the unmarked held-out prefixes (Replicate, Fly, Supabase, Resend, Figma) mostly ship. They are reported, not scored.

**Author's predictions, written before the eval run:**
- H1: **not supported**. The predicted cause is the 20 UNVERIFIABLE-CLEAN false blocks, plus the held-out losses.
- H1b: uncertain.
- H3, H6, H7: supported.
- H4, H5: confirmed.

## 6. Procedure

1. The baselines are installed as in v1, with checksums verified.
2. **Harness validation on the dev set only** (seed `0x5eed0002`, 4 per family, N = 40).
   - Changes to output parsing or invocation in `bench/run.mjs` and `bench/score.mjs` are allowed, and must be listed in §8.
   - **No change to `src/` is allowed in response to dev results.**
3. Freeze. Write the hash and derived seed into this file. Generate the eval corpus, run every configuration **once**, score it, and report everything.

## 7. Threats to validity

- **The author designed the corpus and the tool.**
  - v2 adds families where v0.2's new decoders matter: COMPRESSED-CLEAN, and the new LEAK-DECLARED wrappers. That favours Anti-REA by construction.
  - The NAMED-V2 stratum is fitted to v1.
  - The held-out strata, UNVERIFIABLE-CLEAN and EXAMPLE-DOCS are where the baselines are expected to do well.
  - **Per-family and per-stratum results are the primary basis for interpretation, not the aggregate.**
- **Calibration** of the structural rule used real third-party apps (CALIBRATION.md), not benchmark bytes. The benchmark background was never scanned with v0.2 detectors before freezing, except by the dev run in step 2.
- **Synthetic needles**, **author-written tuned configs** and **a single platform**: as in v1.
- **Gate semantics:** "any finding = block", as in v1.

## 8. Amendments and dev-set disclosure

No amendments. Step 2 found no harness defects: every baseline's output was parsed correctly, and no change was made to `bench/run.mjs` or `bench/score.mjs`. The one change made after the dev run is the version string, which moved from 0.1.0 to 0.2.0 in `package.json` and `src/version.ts`. It has no effect on behaviour.

**Dev-set disclosure (N = 40, seed `0x5eed0002`).** Validating the harness meant running every configuration, so the author has seen these accuracies:
- AR-1 34/40 and AR-1o 34/40;
- AR-2 33/40;
- TH-T 32/40;
- GL-T 29/40;
- AR-0 26/40;
- TH-D 25/40;
- DS-D 22/40;
- GL-D 20/40.

On dev, H1 and H1b were not supported, H3, H5 and H6 held, and H4 and H7 were not evaluable (no scenarios in those strata). Hypotheses and thresholds were not changed in response.

**Observed on dev and deliberately not fixed** (doing so would change `src/` in response to dev results):
- AR-1 raises one *warn-only* `prefixed-token` lead on a string in TypeScript's localised `diagnosticMessages.generated.json` files. These are benchmark background files. The lead does not change any decision, but it counts as a "spurious finding": 16 on dev, against 0 for v0.1 in v1.
- Two baseline behaviours worth noting:
  - gitleaks logs "could not read file" on encrypted zip entries, and TruffleHog skips them silently. Both still exit 0, so they pass.
  - Both flag a credentialed example URI and `generic-api-key` values inside a real `@types/node` file once it is inside a compressed archive.
