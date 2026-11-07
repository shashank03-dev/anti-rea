# Anti-REA evidence

How well Anti-REA works, measured. Every benchmark was pre-registered and frozen by hash before it was run, and run once. Misses, defects and unsupported hypotheses are reported alongside the wins.

- **Exposure report (`expose`), v7 benchmark.** Pre-registered (commit `986e2d7`) and run once on 240 real builds of disjoint Go, C and JS/Electron code, scored against an independent reference checker ([results](../bench/v7/RESULTS-eval.md), [protocol](../bench/v7/PREREGISTRATION.md)):
  - **96.6% accuracy** [94.8, 98.0] on 566 checks. That is the post-hoc figure; the registered one is 97.0% on 624 checks. A harness defect, disclosed in the results, built 29 Go library archives instead of executables.
  - **0 false positives** in 333 checks of hardened builds.
  - **100%** on native debug info, symbols, debug maps and dSYMs (67 Go executables across ELF/PE/Mach-O, plus C dylibs), inside zip, tar.gz and app.asar packaging.
  - **66/66** source maps found and graded correctly, and **43/43** `openDevTools()` calls.
  - Every miss is one predicted scope gap: an insecure `webPreferences` value passed through a variable (0/19).
  - It is **not** more accurate than a careful expert checklist built from llvm tools and regexes (p = 0.54, as predicted). It matches that checklist in one command, and adds attribution, grading and fixes.
- **Real-world robustness:** `expose` completed on every one of the 101 applications installed on the development machine, with no crash. The slowest took 12.6 s, and peak memory was 1.5 GB.
- **Correctness:** 164 tests, passing in CI on Linux, macOS and Windows with Node 22, 24 and 26 (a few that need POSIX file names or tools are skipped on Windows). A packaged-install smoke test runs in CI and before every publish.
  - Unit, pipeline and regression tests, plus the v0.8 exposure units, golden/redaction, fuzz (~10,000 seeded corruptions plus structure-preserving mutation of valid fixtures), review-regression and differential tests.
  - **Differential tests** against:
    - `@electron/asar`, Info-ZIP, `ditto`, bsdtar and Python `zipfile`;
    - xz(1), lzma(1), bzip2, lz4 and ar(1);
    - `hdiutil(1)` DMGs;
    - from v0.6, **`plutil(1)` and `codesign(1)`**.
- **Platform lane** (v0.6) on real apps, against `codesign`:
  - cdhashes agree on 145/145 Mach-O files;
  - **0 seal problems on 20 intact installed apps**;
  - **25/25 tamper cases agree** (copies of Ghostty, Loom and Figma).
- **False positives:** the rules were tuned and validated on 18.7 GB of real code: 55 apps, toolchains and packages in sets A–F ([CALIBRATION.md](research/CALIBRATION.md)).
  - On sets A–E, v0.6 produced **0 blocking structural or call-style leads**. The 1,719 blocking keyed leads are all real credentials shipped by design: WhatsApp's embedded proxy credentials and Adobe's OAuth client secrets.
  - **Every fresh validation set so far has found a false-lead class.** The newest, F (1.58 GB), had one: Objective-C `hf_` selectors in Home.app that matched the Hugging Face format. It was fixed afterwards, so F is tuning data now.
- **Comparison with current tools:** six pre-registered, sealed benchmarks, each run once ([results](research/BENCHMARK-RESULTS.md)).
  - **v6** (v0.6; N = 260, new background, 16 held-out formats never used before):

    | Config | Accuracy | p vs Anti-REA |
    |---|---|---|
    | **Anti-REA alone** | **91.5%** | — |
    | **Anti-REA + TruffleHog import** | **91.5%** | — |
    | Tuned TruffleHog | 81.2% | **0.0013** |
    | Tuned gitleaks | 75.0% | 3e-6 |
    | v0.4 on the same corpus | 81.5% | 3e-8 (26 : 0) |
    | v0.5 on the same corpus | 91.5% | identical decisions |

    - Anti-REA alone is **significantly better than every baseline** (H1b). This is the first study where AR-1 alone cleared that bar.
    - "Substantially better" (H1: Δ ≥ 15 points against every baseline) is **still not supported**. Against tuned TruffleHog the gap is 10.4 points.
    - **20 of Anti-REA's 22 errors** are clean releases containing an encrypted zip or DMG, blocked fail-closed by design. The other two:
      - a random Mistral key that looked word-like;
      - a Postmark UUID passed to a bare factory call, a predicted miss.
    - v0.6 and v0.5 decided all 260 identically. The v0.6 detector fixes were not exercised by v6's formats; the result shows v0.5's rules generalised.
  - **v6 platform sub-study** (N = 60 signed app bundles):
    - **Anti-REA 60/60.** `codesign --verify` scored 44/60, and a scripted `codesign` policy check 52/60.
    - Anti-REA agreed with `codesign` on every intact and tampered bundle.
    - The 8-scenario lead over the scripted check comes from Electron fuses and ASAR integrity, which `codesign` does not read. That lead is **by construction**.
  - **Earlier studies:**

    | Study | Anti-REA | Tuned TruffleHog | Result |
    |---|---|---|---|
    | v5 (v0.5) | 89.2% (AR-2: 91.2%) | 80.8% | p = 0.013 (AR-2: 0.0013) |
    | v4 (v0.4) | 85.0% | 81.7% | p = 0.35 |
    | v3 (v0.3) | 90.0% | 84.5% | p = 0.16 |
    | v2 (v0.2) | 86.0% | 89.5% | tie |
    | v1 (v0.1) | 84.4% | 93.9% | worse |

    Each study's losses drove the next version: [v0.2](research/V02-CHANGES.md), [v0.3](research/V03-CHANGES.md), [v0.4](research/V04-CHANGES.md), [v0.5](research/V05-CHANGES.md), [v0.6](research/V06-CHANGES.md).

## Reproduce the demo

```bash
npm install
```

```bash
npm test
```

```bash
npm run demo
```

```bash
npm run demo:fixed
```

`npm run demo` builds a **synthetic** Electron-style app with planted positive controls inside real nested containers. It returns **BLOCK** (exit code 2):

```
  ✗ [confirmedCriticalSecret] Declared server-only secret "license-signing-key" is present … @ …app.asar!/licensing/license-client.js:6
  ✗ [serverOnlyFoundInDistribution] Server-only implementation marker "scoreTransactionRiskV3" found … @ …risk-plugin-3.1.0.zip!/risk-plugin.js:10
  ✗ [reproducedPrivilegedEffect] Prohibited effect reproduced: bob@tenantB performed read on invoice:A-1001 in tenant tenantA
  ✗ [declaredPrivateArtifactShipped] Artifact declared private is present in the shipped bytes @ …app.asar!/renderer/app.js.map
  ! [warn] Unconfirmed lead: JSON Web Token (…app.asar!/config/dev-session.json:3)
```

`npm run demo:fixed` builds the remediated variant, which returns **PASS** (exit code 0).

## Benchmark (pre-registered v6; run once on 2026-11-07)

```bash
bench/install-baselines.sh
```

```bash
node bench/corpus.mjs --set eval --out bench/runs/eval/corpus
```

```bash
node bench/run.mjs --set eval
```

```bash
node bench/score.mjs --set eval
```

```bash
node bench/platform.mjs --set eval --gen --run --score
```

- The install script fetches the baselines into the gitignored `bench/.tools/`, verifying the publishers' checksums.
- **The corpus step** generates 260 scenarios across 10 families. They include a forced 4 × 5 × 4 grid of undeclared leaks (credential group × render style × repeat).
  - The background is real third-party bytes: git's `share/` tree, abseil's headers and a `libvpx` slice. The sha256 of each is recorded.
  - The **eval seeds are derived from the frozen code hash**, so they cannot be picked.
- **The platform step** (macOS) builds 60 ad-hoc-signed app bundles with `codesign`, tampers with some of them, and compares Anti-REA with `codesign`-based checks.
- `run.mjs` and `platform.mjs` refuse to run eval unless the code matches the hash in the pre-registration.
- `score.mjs` computes exact CIs and McNemar tests and evaluates the hypotheses mechanically. That includes v0.6 against the frozen v0.5 and v0.4 builds on the same corpus.

See [bench/PREREGISTRATION.md](../bench/PREREGISTRATION.md) for the families, held-out strata, hypotheses, predictions, dev-set disclosure and threats to validity. The v1–v5 studies are archived in [bench/v1/](../bench/v1/) through [bench/v5/](../bench/v5/).
