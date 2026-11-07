# Anti-REA — release assurance with hard gates

Anti-REA decides whether a release should **ship or be blocked**. It looks at the bytes actually being delivered. That includes the contents of nested files:
- `app.asar`;
- zip/jar/apk/ipa (stored, deflate, bzip2 and LZMA entries);
- tar, gzip, xz, lzma, bzip2, zstd, lz4 and ar/.deb;
- DMG (UDIF with HFS+);
- base64-, hex- and percent-encoded text inside any of them.

It weighs those bytes against an **owner-declared asset model**:

- **Server-only** secrets and implementations must not ship.
- **Public-by-design** values may ship.
- **Private artifacts** such as source maps and debug symbols must not ship.
- Content that **cannot be inspected** is a coverage gap, never a silent pass.

From v0.6 it can also check **platform hardening** against what the owner declares:
- macOS code signatures, every code page and bundle seal;
- hardened runtime, team and entitlements;
- Electron fuses and ASAR integrity.

From v0.7 it checks for **reverse-engineering aids** a release should not hand out:
- embedded DWARF, Mach-O debug maps (object-file build paths, source files, functions) and local symbol names in Mach-O and ELF code;
- PDB, dSYM and source-map files, recognised by content (a map with `sourcesContent` ships the original source);
- original source files, unminified or unmangled owner JavaScript;
- Electron `webPreferences` that switch isolation off, and `openDevTools()` calls.

It can verify **build provenance** (DSSE / in-toto / SLSA, with pinned keys) against the shipped bytes. And it can **sign its decision** as an in-toto attestation that a deploy step verifies.

From v0.8 it adds an **advisory exposure report** — the defensive mirror of a reverse-engineering (REA-class) tool. `anti-rea expose <path>` answers: *if someone ran a REA-class tool on my build, what would they recover, which of it can I avoid, and what do I change?* It covers Mach-O/ELF/PE, Electron, .NET, Unity IL2CPP, Android APK, Flutter, Go, Rust, PyInstaller, WebAssembly, ML models (GGUF/safetensors/TFLite), Godot and GPU kernels, grading each finding by a fixed rubric, separating your own code from vendored components, and redacting any secret it meets. It is standalone and **trips no gate** — the release decision is untouched. It ships as a CLI command, a GitHub Action and a zero-dependency MCP server.

Every conclusion is an evidence record with an explicit result state, coverage, budget and limitations. Hard gates decide the release; no score does.

It has zero runtime dependencies and needs Node ≥ 22 (Node 20 reached end-of-life in April 2026). This is the "measurement and evidence system" that the Anti-REA research recommends building first (§1, §14 stage 1).

> **Scope.** Anti-REA makes scoped statements about a declared release closure, declared assets and the lanes that ran. It never claims an application "cannot be reverse engineered" (research §3).

> **Versions.** The first public release is **0.1.0**. The "v0.1–v0.8" names in this README and in `docs/research/` are internal development milestones that came before it.

## For your release: quick start

Install it in the project that builds your app (Node ≥ 22):

```bash
npm install --save-dev anti-rea
```

**1. See what a reverse-engineering tool would recover.** No setup needed. Point it at what your build produces:

```bash
npx anti-rea expose dist/MyApp.app
```

It writes `anti-rea-exposure/exposure.md` and `exposure.json`: what is exposed, whether it is your code or a dependency's, and the exact toolchain setting that removes it (for example `strip -S`, or building without `sourcesContent`). Re-run after each fix.

**2. Gate the release.** Scaffold a manifest and policy from your build, then declare what must never ship:

```bash
npx anti-rea init dist
```

```bash
npx anti-rea fingerprint --file path/to/server-only-secret.pem
```

```bash
npx anti-rea assure --manifest anti-rea.manifest.json --policy anti-rea.policy.json --out anti-rea-report
```

`init` declares only the checks your build has something for, such as macOS signing, Electron fuses or Authenticode. `assure` exits **2 (block)** until each finding is fixed or covered by a named, expiring exception. It also blocks until you declare at least one asset. That is deliberate: a release cannot pass before its owner has said what must not ship.

**3. Let your coding agent drive the fixes.** Register the read-only MCP server once:

```bash
claude mcp add anti-rea -- npx -y -p anti-rea anti-rea-mcp
```

Then ask your agent, for example, *"Run expose_release on dist/ and fix every avoidable owner finding in our build config."* See [docs/AGENTS.md](docs/AGENTS.md) for the workflow and a snippet to paste into your repository's agent instructions.

**4. Keep it fixed in CI.** Add [examples/workflows/exposure.yml](examples/workflows/exposure.yml), which fails the build on a high-or-worse exposure, and run `assure` in your release job.

## Evidence status

- **Exposure report (`expose`), v7 benchmark.** Pre-registered (commit `a8d681b`) and run once on 240 real builds of disjoint Go, C and JS/Electron code, scored against an independent reference checker ([results](bench/v7/RESULTS-eval.md), [protocol](bench/v7/PREREGISTRATION.md)):
  - **96.6% accuracy** [94.8, 98.0] on 566 checks. That is the post-hoc figure; the registered one is 97.0% on 624 checks. A harness defect, disclosed in the results, built 29 Go library archives instead of executables.
  - **0 false positives** in 333 checks of hardened builds.
  - **100%** on native debug info, symbols, debug maps and dSYMs (67 Go executables across ELF/PE/Mach-O, plus C dylibs), inside zip, tar.gz and app.asar packaging.
  - **66/66** source maps found and graded correctly, and **43/43** `openDevTools()` calls.
  - Every miss is one predicted scope gap: an insecure `webPreferences` value passed through a variable (0/19).
  - It is **not** more accurate than a careful expert checklist built from llvm tools and regexes (p = 0.54, as predicted). It matches that checklist in one command, and adds attribution, grading and fixes.
- **Real-world robustness:** `expose` completed on every one of the 101 applications installed on the development machine, with no crash. The slowest took 12.6 s, and peak memory was 1.5 GB.
- **Correctness:** 164 tests on macOS. Linux (Node 22 and 24) was verified in a container. CI is configured for Linux, macOS and Windows on Node 22, 24 and 26; Windows has not been run yet.
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
- **False positives:** the rules were tuned and validated on 18.7 GB of real code: 55 apps, toolchains and packages in sets A–F ([CALIBRATION.md](docs/research/CALIBRATION.md)).
  - On sets A–E, v0.6 produced **0 blocking structural or call-style leads**. The 1,719 blocking keyed leads are all real credentials shipped by design: WhatsApp's embedded proxy credentials and Adobe's OAuth client secrets.
  - **Every fresh validation set so far has found a false-lead class.** The newest, F (1.58 GB), had one: Objective-C `hf_` selectors in Home.app that matched the Hugging Face format. It was fixed afterwards, so F is tuning data now.
- **Comparison with current tools:** six pre-registered, sealed benchmarks, each run once ([results](docs/research/BENCHMARK-RESULTS.md)).
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

    Each study's losses drove the next version: [v0.2](docs/research/V02-CHANGES.md), [v0.3](docs/research/V03-CHANGES.md), [v0.4](docs/research/V04-CHANGES.md), [v0.5](docs/research/V05-CHANGES.md), [v0.6](docs/research/V06-CHANGES.md).

## Quick start

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

## CLI

| Command | Purpose |
|---|---|
| `anti-rea assure --manifest m.json --policy p.json [--authz-results r.json] [--import <tool>:<file>]… [--out dir] [--json] [--now ISO]` | Full pipeline. Writes `report.json` and `report.md`. **Exit codes:** 0 = pass or pass-with-exceptions, 2 = block, 1 = error. `--out` may not be inside a release root. |
| `anti-rea assure … --sign-key key.pem` | Also writes `attestation.dsse.json`: a DSSE-signed in-toto Statement binding the decision, gates, policy and report digest to every shipped artifact's sha256. |
| `anti-rea verify-attestation --attestation a.json --public-key k.pub [--artifact f]… [--require-decision pass]` | Checks the signature, predicate type, subject coverage and decision. **Exit codes:** 0 = valid, 2 = invalid. |
| `anti-rea inspect --manifest m.json [--json]` | Facts with no policy applied: Mach-O signing (team, runtime, entitlements, bad pages), bundle seals, Electron fuses and ASAR integrity, PE Authenticode presence; and (v0.7) native debug info, debug maps and local symbols, debug files, source files, unminified JavaScript and Electron leads. |
| `anti-rea inventory --manifest m.json [--json]` | The release closure, including nested entries, with sha256 for each, plus a deterministic release ID. |
| `anti-rea expose (<path> \| --manifest m.json) [--out dir] [--json] [--fail-on <severity>] [--include-third-party]` | (v0.8) Advisory reverse-engineering exposure report. `<path>` may be a `.app`, `.apk`/`.ipa`/`.exe`, a directory or a file. Writes `exposure.json` + `exposure.md`; owner findings rank first. Trips no gate. **Exit codes:** 0 advisory, 2 if `--fail-on` is met by the maximum grade, 1 error. |
| `anti-rea mcp-config [--json]` | (v0.8) Prints registration snippets for the read-only `anti-rea-mcp` MCP server. |
| `anti-rea fingerprint --file secret.pem` or `--stdin` | Prints the canonical sha256 to put in the manifest. The secret is never printed. |
| `anti-rea authz-plan --manifest m.json [--out plan.json]` | Expands the declared authorization matrix into a test plan for **your own** harness. |
| `anti-rea stats zero-event --n 3000` / `stats min-trials --target 0.001` | Exact zero-event upper bound (research §11). Valid only for independent trials. |

**Combining with a dedicated scanner.**
- `--import gitleaks:report.json` takes the output of `gitleaks dir … --report-format json`, run without `--redact`.
- `--import trufflehog:results.jsonl` takes the output of `trufflehog filesystem … --json --no-verification`.

Anti-REA applies the asset model to the imported findings. Declared public values are not flagged, declared server-only values are confirmed, and anything else becomes a lead. Every imported secret is hashed on arrival and never stored in plaintext. The import file itself contains plaintext secrets, so delete it after the run.

## How it works

```
manifest (owner-declared assets, platform + provenance expectations) + policy (gates)
        │
inventory ──── walk roots; classify by magic bytes; expand zip/asar/tar/gzip/xz/bzip2/zstd/lz4/ar/DMG
        │      in memory (resource-limited); sha256 everything; release ID; symlinks recorded as notes;
        │      flag declared-private artifacts and source-map comments
exposure ───── chunked Latin-1 views (+ UTF-16LE for binaries): format, structural, keyed and call
        │      detectors + fingerprint sweep → CONFIRMED only on a declared-fingerprint match
placement ──── owner-declared server-only markers, searched as raw UTF-8/UTF-16LE bytes
authorization ─ owner-executed results vs. server-side ground truth (Anti-REA sends no traffic)
external ───── imported gitleaks/TruffleHog findings, mapped through the asset model
platform ───── Mach-O signatures (page hashes recomputed), bundle seals, entitlements, hardened
        │      runtime, team, Electron fuses, ASAR integrity, PE Authenticode presence   [when declared]
provenance ─── DSSE signatures (pinned keys), SLSA builder id, subject digests vs. shipped bytes [when declared]
        │
gates ──────── block / warn / owned + scoped + expiring exceptions → decision ──→ optional signed attestation
```

### Result states (research §9.1)

| Outcome | Meaning |
|---|---|
| `recovered` | The attacker objective succeeded, or the prohibited effect was reproduced. |
| `not-recovered-within-budget` | A valid attempt finished its budget without success. This is a scoped, right-censored observation. |
| `inconclusive` | Unsupported content, a missing input, or insufficient coverage. **A required lane in this state blocks.** |
| `not-applicable` | The test does not apply under the declared scope. A rationale is recorded. |

### Gates (research §10)

| Gate | Default | Trips when |
|---|---|---|
| `confirmedCriticalSecret` | block | A server-only secret's fingerprint is matched in the shipped bytes. |
| `serverOnlyFoundInDistribution` | block | An owner-declared server-only implementation marker is present. |
| `reproducedPrivilegedEffect` | block | An expected-deny authorization case was observed as allowed. |
| `declaredPrivateArtifactShipped` | block | An artifact matching `releaseClosure.private` ships, or a real inline source map exists. |
| `unconfirmedCredentialLead` | block | A **format-specific** credential matches no declared asset: one of 35 documented provider formats (private keys, AWS, GitHub, GitLab, Slack, Stripe live, npm, PyPI, OpenAI, Anthropic, …) or a non-generic scanner import. It blocks until triaged. |
| `unrecognizedTokenLead` | block | A `<prefix>_<random>` token from an unknown provider whose prefix marks it secret (`sk`, `secret`, `tkn`, `pat`, `key`, `api`, …). The shape filters and the secret-marker requirement were calibrated on 2.1 GB of real apps ([CALIBRATION.md](docs/research/CALIBRATION.md)). |
| `keyedCredentialLead` | block | A generated-looking value (random token, 32+ hex, or UUID) assigned to a key whose name ends in a credential noun: `…_API_KEY`, `apiKey`, `access_token`, `client_secret`, `password` and so on. It catches unprefixed credentials. Placeholders, templates, editor-theme scopes and base64-encoded prose are excluded. |
| `lowConfidenceCredentialLead` | warn | A JWT, an often-public key (Google), a test-mode key, or a password in a URL. |
| `platformHardeningViolation` | block | A declared platform expectation is violated: unsigned or ad hoc code where Developer ID is required, a modified code page, a broken bundle seal, no hardened runtime, the wrong team, a forbidden entitlement, an Electron fuse in the wrong state, an ASAR integrity mismatch, or a PE file without Authenticode. |
| `reverseEngineeringAidShipped` | block | (v0.7, when `reAids` is declared) embedded debug info, a debug map, local symbols beyond the allowance, a PDB/dSYM/source map, an original source file, JavaScript that fails the declared minification level, or an insecure Electron `webPreferences` value / `openDevTools()` call ships. Native counts agree with `dsymutil -s` and `llvm-objdump` ([V07-CHANGES.md](docs/research/V07-CHANGES.md)). |
| `provenanceMismatch` | block | A shipped artifact is not a subject of trusted build provenance or differs from the attested digest, or the provenance is unsigned, badly signed or from an unexpected builder. |
| `requiredLaneInconclusive` | block | A required lane did not run to a conclusion. |

There is no aggregate score. Research §10.1 gives a counterexample: a score of 82/100 can coexist with an exposed critical secret.

An exception needs an `owner`, `scope`, `rationale` and `expiry`. It can be narrowed to an `assetId` or a `lane`. Excepted findings stay in the report. An expired exception does not apply.

### Coverage and safety properties

- **No plaintext secrets.** The manifest holds sha256 fingerprints only, and the validator rejects anything else. Reports carry a redacted preview and a hash. Tests assert that serialized reports contain no secret material.
- **Canonical fingerprints.** A PEM key matches whether it ships as a `.pem` file or as a `\n`-escaped string literal.
- **Native binaries are scanned.** PE, ELF and Mach-O are read as raw bytes, as Latin-1 and as UTF-16LE. Installers whose payload is compressed (NSIS, Inno Setup, MSI, pkg) are opaque. So are formats this version cannot decode: 7z, RAR, squashfs, RPM, Cabinet, LZFSE- or APFS-based and encrypted DMGs, encrypted zip entries, zip methods other than stored/deflate/bzip2/LZMA, and xz filters other than delta and x86-BCJ. Opaque or corrupt content makes the content lanes inconclusive.
- **Zero-dependency decoders.** The xz/LZMA2, lzma, bzip2 and lz4 decoders are checked byte-for-byte against xz(1), lzma(1), bzip2, lz4(1), Python `zipfile` and bsdtar. All integrity checks are verified. 3,000 fuzzed corruptions were all rejected, and none decoded silently to wrong bytes ([V02-CHANGES.md](docs/research/V02-CHANGES.md)).
- **Encoded text is decoded.** Base64/base64url, hex and percent-encoding are decoded up to two layers, and only when the result is readable text. Findings record the decoding chain.
- **Read-only, in-memory expansion.** Nothing is extracted to disk. Entry size, total size, entry count and depth are limited to stop decompression bombs. On-disk files up to 2 GiB are read lazily and scanned in overlapping chunks.
- **Platform checks are validated against `codesign(1)`:**
  - cdhashes agree on 145/145 Mach-O files;
  - 0 seal problems on 20 intact installed apps;
  - 25/25 tamper cases agree.

  Certificate chains, notarization and revocation are **not** validated. Use `codesign`/`spctl` or `signtool` for chain trust. Bundle *structure* (for example a missing `Versions/Current` link) and extended attributes are not modelled ([V06-CHANGES.md](docs/research/V06-CHANGES.md)).
- **Provenance trust comes from pinned keys.** Sigstore certificate chains, Rekor inclusion and keyless identities are not verified.
- **Known gaps:**
  - the archive formats listed above;
  - encodings beyond two layers, encryption, and secrets assembled at runtime;
  - a credential with no recognised format, passed as a bare UUID to an unknown call, or to a method whose name carries no configuration verb (for example `api.setKey("…")`), is not detected;
  - unquoted `NAME=a.b` values: `.` reads as a member expression;
  - runtime instrumentation and behavioural-cloning lanes are not implemented. Use `--import` for detector breadth.

## Exposure (v0.8, advisory)

`anti-rea expose <path>` is the defensive mirror of a reverse-engineering tool. It is static, read-only,
in-memory, makes no network calls, and **trips no gate** — `assure` never runs it, so the release
decision is untouched by construction.

```bash
anti-rea expose /Applications/MyApp.app
anti-rea expose dist/app.apk --fail-on high        # exit 2 if the max grade is high or critical
npm run expose-demo                                # a synthetic release covering every format
```

- **Findings** are graded by a **fixed rubric** (attack surface → severity; [rubric.ts](src/analyzers/rubric.ts)); analyzers never invent a grade. `--fail-on` uses the **maximum** grade, never an average, so a critical can't be hidden.
- Each finding is attributed **owner vs third-party** (dependencies, vendored runtimes, engine libraries), and marked **avoidable** (a toolchain setting removes it) vs inherent (ObjC/Swift metadata, Go `pclntab`, IL2CPP `global-metadata.dat`).
- The report is **about the product**: a profile (platforms, frameworks, languages), findings by surface with your code first, a deduplicated hardening checklist, coverage with every opaque artifact named, and the REA → Anti-REA matrix.
- It never prints secret values. Go `-ldflags -X`, `KEY=…` pairs and model `__metadata__` are redacted; tests assert a planted secret never appears in the serialized report.
- Distribution: a CI step (`npx anti-rea@0.1.0 expose …`, or the composite **GitHub Action** `anti-rea/anti-rea@v0.1.0`; see [examples/workflows/exposure.yml](examples/workflows/exposure.yml)), a zero-dependency **MCP server** (`anti-rea mcp-config`; [docs/AGENTS.md](docs/AGENTS.md)), and the CLI.

Coverage and the honest gaps (Flutter/GPU detected-only; EVM/BEAM detected as roadmap stubs) are in [docs/REA-COVERAGE.md](docs/REA-COVERAGE.md); the design and the tuning-only calibration are in [docs/research/V08-CHANGES.md](docs/research/V08-CHANGES.md).

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

See [bench/PREREGISTRATION.md](bench/PREREGISTRATION.md) for the families, held-out strata, hypotheses, predictions, dev-set disclosure and threats to validity. The v1–v5 studies are archived in [bench/v1/](bench/v1/) through [bench/v5/](bench/v5/).

## Manifest and policy

Complete examples: [fixtures/demo-app/manifest.json](fixtures/demo-app/manifest.json) and [fixtures/demo-app/policy.json](fixtures/demo-app/policy.json).

- **`releaseClosure.roots`:** **every byte under these roots ships.** Roots may not overlap. There is deliberately no `exclude` option. Use `private` for things that must *not* ship; the tool checks that claim against the actual bytes.
- **`assets[]`:** each asset has an `id` and a `placement` (`server-only`, `sensitive-local` or `public-by-design`).
  - Optional fields: `fingerprints`, `markers` (≥ 4 characters each), `attacker { objective, success, budget }`, `owner`, `rationale`, `offlineRequired`, and `onConfirmedDistribution: "warn"`.
  - A fingerprint may belong to only one asset.
  - A server-only asset with neither markers nor fingerprints is an **unresolved gap**.
- **`authorization`:** principals, tenants, objects, operations and `defaultExpected`, plus explicit `cases`. Conflicting results for one case make the lane inconclusive.
- **`platform`** (v0.6):
  - `macos`: `requireSigned`, `requireDeveloperId`, `requireHardenedRuntime`, `teamId`, `forbiddenEntitlements`, `requireIntactSeal`;
  - `electron`: `fuses` (for example `{"RunAsNode": false}`) and `requireAsarIntegrity`;
  - `windows`: `requireAuthenticode`.

  An expectation with nothing to apply to is inconclusive.
- **`reAids`** (v0.7): `native` (`forbidDebugInfo`, `forbidDebugMap`, `maxLocalSymbols`, `exclude`), `debugFiles` (`exclude`), `sources` (`extensions`, `exclude`; `node_modules` trees excluded by default), `minified` (`include`, `exclude`, `level: "whitespace" | "identifiers"`) and `electron` (`forbidInsecureWebPreferences`, `forbidDevTools`, `include`, `exclude`). `{}` runs native, debugFiles and sources with defaults; any check can be `false`.
- **`provenance`** (v0.6): `statement` (a DSSE envelope, Sigstore bundle or in-toto Statement; JSON or JSONL), `publicKeys`, `builderId` and `subjects` (globs; default: every top-level file).

## Status against the research roadmap (§14)

| Stage | Status |
|---|---|
| 0 Research specification | ✅ encoded as types, validation and policy |
| 1 Release assurance foundation | ✅ this codebase, self-reviewed and differentially tested |
| 2 Platform adapters | ◐ macOS Mach-O / bundle-seal / entitlement semantics, Electron fuses and ASAR integrity, PE Authenticode *presence*; (v0.7) Mach-O and ELF symbol-table and debug-section facts; (v0.8, advisory exposure only) PE debug-directory / `DllCharacteristics`, ELF program-header hardening, DEX + APK signing block + binary-XML manifest, and the other exposure formats. The gated lanes are unchanged. |
| 3 Adversarial evaluation | ◐ Pre-registered release-gate benchmarks (v1–v6) and a static tamper sub-study against `codesign`. Runtime and cloning lanes are not implemented. |
| 4 Architecture, API, attestation | ◐ Authorization-matrix evaluation, DSSE/in-toto/SLSA provenance verification, signed decision attestations. |
| 5–6 Transformations, confidential execution | ✗ out of scope until stage-3 measurements justify them |

Byte identity (sha256) does **not** authenticate the build context. Declare `provenance` to check the shipped bytes against signed SLSA-style provenance (research §9.2).

## Layout

```
src/model/     result states, manifest, policy, evidence types
src/codecs/    zero-dependency xz/LZMA2, lzma, bzip2, lz4, UDIF/HFS+ (DMG), plist, Mach-O, ELF, PE, Android binary-XML (AXML) and symbol-table readers; CRCs
src/lanes/     containers, inventory, detectors, decode, exposure, placement, authorization, external, platform, provenance, aids, recovery (v0.8 exposure)
src/analyzers/ (v0.8) the exposure analyzers (native, electron, dotnet, unity, apk, flutter, go, rust, pyinstaller, wasm, models, godot, gpu, stubs), rubric, attribution, redaction
src/engine/    evaluate (pipeline), gate, report, stats, attest (signed decisions), exposure-report (v0.8)
src/mcp/       (v0.8) zero-dependency JSON-RPC-over-stdio MCP server (anti-rea-mcp)
src/pack/      deterministic asar/zip/tar writers (fixtures and tests)
test/          unit, pipeline, regression, differential and (v0.8) exposure/fuzz tests (node:test)
bench/         v6 pre-registration, corpus generator, runner, scorer, platform sub-study, baseline installer, calibration, minify classifier corpus, dsymutil differential; v1/–v5/ archived
docs/          AGENTS.md (v0.8 agent workflow), REA-COVERAGE.md (v0.8 coverage matrix), research/ (self-review, calibration, v0.2–v0.8 changes, benchmark results)
action.yml     (v0.8) composite GitHub Action; examples/workflows/exposure.yml
fixtures/demo-app/     synthetic app, build script, manifest, policy, authz results
fixtures/expose-demo/  (v0.8) multi-format synthetic release builder (every format, gitignored output)
```

Every secret in the fixtures and benchmark corpus is **synthetic** and is not used for anything.
