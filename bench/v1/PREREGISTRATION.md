# Pre-registration: Anti-REA vs. current secret scanners as release gates

**Registered:** 2026-11-06, before any baseline tool was executed and before the evaluation corpus was generated.

**Frozen tool and harness:** frozen-sha256: `652f6a4585a8288856467ab20030778bbf69b02cf26c4aca7d5180256c1898c2`

This hash was amended from the original `eb877a0b471c3d482c28f077d49af03c36ce37c4a62523fe5cfca9d2c1c326bf` by A1 and A2 in §8. Both are changes to output parsing in `bench/run.mjs` only.

The hash is computed by `node bench/freeze.mjs` over `src/`, `bench/corpus.mjs`, `bench/run.mjs`, `bench/score.mjs`, `bench/policy.json` and `package.json`. `bench/run.mjs --set eval` refuses to run when the current tree does not match it.

## 1. Question

Should a release be shipped or blocked? The decision must account for the owner's asset model (server-only, public-by-design, private artifacts) and for content that cannot be inspected. Is Anti-REA substantially more accurate at that decision than current secret scanners used as CI gates, given the **same owner knowledge**?

This is *not* a test of which tool has the best secret detectors. Dedicated scanners are expected to beat Anti-REA on detector breadth, and the study is designed to show that too (H4).

## 2. Systems and configurations

All tools run fully offline. HTTP(S) proxies point at a dead local port, and TruffleHog runs with `--no-verification`, so no synthetic credential can reach a provider API.

| ID | System | Configuration | Owner knowledge |
|---|---|---|---|
| AR-0 | Anti-REA (frozen) | `assure` with `manifest.noknowledge.json` (one public asset; no private globs) | none |
| AR-1 | Anti-REA (frozen) | `assure` with `manifest.json` and `bench/policy.json` (default gates) | full asset model |
| AR-2 | Anti-REA (frozen) | AR-1 plus `--import trufflehog:<TH-D output>` | full + TruffleHog detectors |
| GL-D | gitleaks 8.30.1 | `gitleaks dir <release> --report-format json` | none |
| GL-T | gitleaks 8.30.1 | adds `--max-archive-depth 8 --max-decode-depth 5 --config gitleaks.toml` | equivalent (see below) |
| TH-D | trufflehog 3.99.8 | `trufflehog filesystem <release> --json --no-verification --no-update --fail` | none |
| TH-T | trufflehog 3.99.8 | adds `--config trufflehog.yaml --fail-on-scan-errors` | equivalent (see below) |
| DS-D | detect-secrets 1.5.0 | `detect-secrets scan --all-files --no-verify release` | none |

**Knowledge parity.** For every scenario the generator writes tuned baseline configs from the same facts as `manifest.json`:
- regex rules for the owner-declared server-only implementation markers;
- a rule for the owner's internal credential format;
- a path rule for `.map` files and a rule for inline source maps;
- an exact-value allowlist for declared public-by-design values. gitleaks supports this. TruffleHog has no value allowlist, which is a property of that tool.

The configs are published per scenario in the corpus for review.

**Decision rule (CI gate semantics).**
- Anti-REA: exit 2 = block, exit 0 = pass, any other exit = block (recorded as a tool error).
- Baselines: block if the tool reports ≥ 1 finding or exits non-zero. Otherwise pass.

## 3. Corpus

`node bench/corpus.mjs --set eval` uses seed `0x5eed2026` and 20 scenarios per family, so **N = 180**.

Each scenario is an Electron-style release:
- `resources/app.asar`;
- `resources/app.asar.unpacked/native/addon.node`, a 1 MiB slice of Homebrew's real `libnode` Mach-O plus its real header;
- `updates/plugin-2.1.0.zip`;
- a real `package-lock.json`;
- six real third-party files drawn from a pool of 172: TypeScript compiler libs, `@types/node`, `undici-types`, `@electron/asar`, `minimatch` and `glob`. None were written by the author.

Benign false-positive traps appear in every scenario: UUIDs, commit SHAs, integrity hashes, a base64 PNG data URI, and an external source-map URL.

| Family | Truth | Content |
|---|---|---|
| CLEAN | pass | background only |
| LEAK-DECLARED | block | one owner-declared server-only credential, drawn from {EC PEM (PKCS#8/SEC1), GitHub, Slack, Stripe live, AWS key pair, internal `corp-svc-…`}, in one of 7 wrappers: plain file, JS string in asar, zip, zip-in-asar, tar.gz, UTF-16LE in native binary, base64 in JSON |
| PUBLIC-DECLARED | pass | two declared public-by-design values (Google browser key, Stripe publishable key, Sentry DSN) |
| SERVER-IMPL | block | code containing the declared server-only markers, in asar, zip or tar.gz |
| PRIVATE-ARTIFACT | block | a `.map` file in the asar, a plain `.map` file, or an inline `data:` source map |
| UNDECLARED-LEAK | block | a real-format credential the owner did not declare. Each instance is either inside Anti-REA's detector set or outside it (GitLab, npm, SendGrid, Hugging Face, Shopify, DigitalOcean, Anthropic, OpenAI formats), with even odds |
| UNVERIFIABLE | block | a declared server-only credential inside `updates/legacy.tar.xz` |
| UNVERIFIABLE-CLEAN | pass | `updates/legacy.tar.xz` containing only real background code |
| EXAMPLE-DOCS | pass | publicly documented example credentials (AWS `…EXAMPLE` pair, Stripe's documentation test key) in a docs file |

All credentials are synthetic values in real formats. EC keys are derived from seeded scalars.

## 4. Metrics and analysis

- **Primary:** release-decision accuracy over N = 180, with an exact Clopper–Pearson 95% interval.
- **Paired comparison:** exact two-sided McNemar test on discordant scenarios, AR-1 vs. each baseline.
- **Secondary:**
  - false-block rate (truth = pass) and false-pass rate (truth = block);
  - per-family accuracy;
  - needle recall per wrapper;
  - spurious findings (findings not attributable to a planted needle);
  - tool errors;
  - median wall-clock time per scenario.

## 5. Hypotheses and decision criteria

- **H1 (primary, "substantially better").** For **every** baseline B in {GL-D, GL-T, TH-D, TH-T, DS-D}, AR-1's accuracy minus B's accuracy must be ≥ 15 percentage points, **and** the McNemar p-value must be < 0.01/5 = 0.002 (Bonferroni). If either condition fails for any baseline, H1 is not supported, and the claim "substantially better than current tools" is **not** made.
- **H2 (composition).** AR-2's accuracy must be ≥ AR-1's, **and** AR-2 must have fewer false passes than AR-1 on UNDECLARED-LEAK.
- **H3 (no silent pass).** AR-1 must have 0 false passes on UNVERIFIABLE.
- **H4 (pre-registered expected loss).** On UNDECLARED-LEAK needles outside Anti-REA's detectors, AR-1's recall is expected to be lower than TH-D's.
- **H5 (pre-registered expected loss).** On UNVERIFIABLE-CLEAN, AR-1 is expected to have more false blocks than TH-D. This is the cost of failing closed on content Anti-REA cannot decode.
- **Also expected:** AR-1 will miss base64-wrapped credentials (W7). Anti-REA documents that it does not decode base64.

`bench/score.mjs` evaluates these criteria mechanically.

## 6. Procedure

1. Install the baselines from their official releases. Verify the publishers' SHA-256 checksums for gitleaks and TruffleHog.
2. **Harness validation on the dev set only** (seed `0x5eed0001`, 2 per family): run all configurations and inspect each baseline's output parsing.
   - Fixes are allowed **only** to output parsing and invocation in `bench/run.mjs`. They must be listed in §8 with their diff, and this file's frozen hash must be amended *before* step 3.
   - No change to `src/`, `bench/corpus.mjs`, `bench/policy.json` or the hypotheses is allowed after this registration.
3. Generate the eval corpus, run all configurations **once**, and score. Report every result, including unfavourable ones.

## 7. Threats to validity

- **Author-designed corpus.** The family list reflects the product's claims, so aggregate accuracy depends on the family mix. That mix has no known real-world prevalence. Per-family results are therefore primary for interpretation, and families where baselines should win (UNDECLARED-LEAK outside, UNVERIFIABLE-CLEAN, base64) are included on purpose.
- **Synthetic needles.** Background bytes are real, but planted values are synthetic. Real leaks may be shaped differently.
- **Tuned configs written by the author**, who is not an expert in each tool. They are published for review. A better configuration might change the results.
- **Gate semantics.** Treating "any finding = block" is how these tools are commonly wired into CI. Vendors might recommend triage workflows instead.
- **Single platform** (macOS arm64) and single tool versions.
- **Dev-set exposure.** Before registration, the author ran AR-0 and AR-1 on the 18-scenario dev set to debug the harness. AR-1 scored 15/18. Its errors were one base64-wrapped credential and two clean `.tar.xz` false blocks, both already anticipated above. No tool change was made after observing them.

## 8. Amendments

Both amendments were made during step 2 (dev-set harness validation), before the eval corpus was generated. Nothing in `src/`, `bench/corpus.mjs`, `bench/policy.json`, `bench/score.mjs` or the hypotheses changed. The new frozen hash is `652f6a4585a8288856467ab20030778bbf69b02cf26c4aca7d5180256c1898c2`.

- **A1: TruffleHog custom-detector naming.**
  - TruffleHog 3.99.8 reports every custom detector as `DetectorName: "CustomRegex"`; the configured name is in `ExtraData.name`.
  - Before the fix, TH-T's correct marker and source-map hits were not attributed to their needles, and were counted as spurious. Decisions were unaffected.
  - Fix: use `ExtraData.name` when `DetectorName` is `CustomRegex`.
- **A2: `--only` re-runs duplicated rows.**
  - Re-running a single configuration appended a second set of rows instead of replacing the old ones.
  - Fix: re-running a configuration replaces its rows.
  - This does not affect a full run, which is how the eval set is run.

**Disclosure.** Validating the harness required running every configuration on the 18-scenario dev set, so the author has seen dev results for all tools: TH-T 18/18, GL-T 17/18, AR-2 16/18, AR-1 15/18, TH-D 15/18, AR-0 11/18, GL-D 11/18, DS-D 8/18. These point *against* H1. The hypotheses and thresholds were not changed in response.

**Tool behaviour that differs from the cited documentation.** The `gitleaks dir --help` of 8.30.1 reports `--max-decode-depth` default **5**, not the 0 stated in the README fetched for LANDSCAPE.md. So GL-D decodes base64 by default. The configurations are unchanged: GL-D is "defaults", whatever the defaults are.
