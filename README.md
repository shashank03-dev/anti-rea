# Anti-REA — release assurance with hard gates

Anti-REA decides whether a release should **ship or be blocked**. It looks at the bytes actually being delivered, including the contents of nested `app.asar`, zip/jar/apk/ipa (stored, deflate, bzip2 and LZMA entries), tar, gzip, xz, lzma, bzip2, zstd, lz4 and ar/.deb files, plus base64-, hex- and percent-encoded text inside them, and weighs them against an **owner-declared asset model**:

- **Server-only** secrets and implementations must not ship.
- **Public-by-design** values may ship.
- **Private artifacts** such as source maps and debug symbols must not ship.
- Content that **cannot be inspected** is a coverage gap, never a silent pass.

Every conclusion is an evidence record with an explicit result state, coverage, budget and limitations. Hard gates decide the release; no score does.

It has zero runtime dependencies and needs Node ≥ 20. This is the "measurement and evidence system" that the Anti-REA research recommends building first (§1, §14 stage 1).

> **Scope.** Anti-REA makes scoped statements about a declared release closure, declared assets and the lanes that ran. It never claims an application "cannot be reverse engineered" (research §3).

## Evidence status

- **Correctness:** 83 tests.
  - Unit, pipeline and regression tests.
  - **Differential tests** against `@electron/asar`, Info-ZIP, `ditto`, bsdtar, Python `zipfile`, xz(1), lzma(1), bzip2, lz4, ar(1) and, from v0.5, **`hdiutil(1)` DMGs**, on real third-party files.
  - DMG reading: UDZO, UDBZ, UDRO, UDCO and ULMO images with HFS+ volumes, including hard links, Unicode names and resource forks, come back byte-identical. Under 3,000 random corruptions there were 0 wrong outputs.
- **False positives:** the rules were tuned and validated on 17.1 GB of real code: 43 apps, toolchains and packages, in sets A, C, D and E ([CALIBRATION.md](docs/research/CALIBRATION.md)).
  - Final v0.5 result: **0 blocking structural or call-style leads.**
  - The blocking keyed leads (1,719) are all real credentials shipped by design: WhatsApp's embedded proxy credentials and Adobe's OAuth client secrets.
  - **Each held-out validation set has found false leads** (C, D and E), which were fixed afterwards, so all four sets are now tuning data.
  - Throughput on set A: 55.4 MB/s, up from v0.4's 48.2 MB/s.
- **Comparison with current tools:** five pre-registered, sealed benchmarks, each run once ([results](docs/research/BENCHMARK-RESULTS.md)).
  - **v5 (this version, v0.5; N = 260, new background, 16 held-out formats):**

    | Config | Accuracy | p |
    |---|---|---|
    | **Anti-REA + TruffleHog import (recommended)** | **91.2%** | 0.0013 vs tuned TruffleHog |
    | Anti-REA alone | **89.2%** | 0.013 vs tuned TruffleHog |
    | v0.4 on the same corpus | 80.8% | **5e-7** (22 : 0 against v0.5) |
    | Tuned TruffleHog | 80.8% | — |
    | Tuned gitleaks | 75.4% | 7e-5 |

    - The recommended configuration is significantly better than every baseline (H1c supported).
    - Anti-REA alone misses the pre-registered p < 0.01 bar against tuned TruffleHog (p = 0.013), so H1b is **not supported**.
    - "Substantially better" (H1, Δ ≥ 15 points) is **not supported.**
  - **20 of v0.5's 28 errors** are clean releases containing an encrypted zip or DMG, blocked fail-closed. TruffleHog passes all 40 such releases, including the 20 that hide a secret.
  - **The other 8** are held-out formats:
    - Klaviyo's private keys use a `pk_` prefix that looks public;
    - fal's `<uuid>:<hex>` pairs;
    - a bare-call UUID;
    - `AIRTABLE_PAT`.
  - **Earlier studies:**

    | Study | Anti-REA | Tuned TruffleHog | Result |
    |---|---|---|---|
    | v4 (v0.4) | 85.0% | 81.7% | p = 0.35 |
    | v3 (v0.3) | 90.0% | 84.5% | p = 0.16 |
    | v2 (v0.2) | 86.0% | 89.5% | tie |
    | v1 (v0.1) | 84.4% | 93.9% | worse |

    Each study's losses drove the next version: [v0.2](docs/research/V02-CHANGES.md), [v0.3](docs/research/V03-CHANGES.md), [v0.4](docs/research/V04-CHANGES.md), [v0.5](docs/research/V05-CHANGES.md).

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
| `anti-rea inventory --manifest m.json [--json]` | The release closure, including nested entries, with sha256 for each, plus a deterministic release ID. |
| `anti-rea fingerprint --file secret.pem` or `--stdin` | Prints the canonical sha256 to put in the manifest. The secret is never printed. |
| `anti-rea authz-plan --manifest m.json [--out plan.json]` | Expands the declared authorization matrix into a test plan for **your own** harness. |
| `anti-rea stats zero-event --n 3000` / `stats min-trials --target 0.001` | Exact zero-event upper bound (research §11). Valid only for independent trials. |

**Combining with a dedicated scanner.**
- `--import gitleaks:report.json` takes the output of `gitleaks dir … --report-format json`, run without `--redact`.
- `--import trufflehog:results.jsonl` takes the output of `trufflehog filesystem … --json --no-verification`.

Anti-REA applies the asset model to the imported findings. Declared public values are not flagged, declared server-only values are confirmed, and anything else becomes a lead. Every imported secret is hashed on arrival and never stored in plaintext. The import file itself contains plaintext secrets, so delete it after the run.

## How it works

```
manifest (owner-declared assets) + policy (gates)
        │
inventory ──── walk roots; classify by magic bytes; expand zip/asar/tar/gzip in memory (resource-limited);
        │      sha256 everything; release ID; flag declared-private artifacts and source-map comments
exposure ───── chunked Latin-1 views (+ UTF-16LE for binaries): 9 detectors + fingerprint sweep
        │      → CONFIRMED only on a declared-fingerprint match; otherwise a lead
placement ──── owner-declared server-only markers, searched as raw UTF-8/UTF-16LE bytes
authorization ─ owner-executed results vs. server-side ground truth (Anti-REA sends no traffic)
external ───── imported gitleaks/TruffleHog findings, mapped through the asset model
        │
gates ──────── block / warn / owned + scoped + expiring exceptions → decision
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
| `requiredLaneInconclusive` | block | A required lane did not run to a conclusion. |

There is no aggregate score. Research §10.1 gives a counterexample: a score of 82/100 can coexist with an exposed critical secret.

An exception needs an `owner`, `scope`, `rationale` and `expiry`. It can be narrowed to an `assetId` or a `lane`. Excepted findings stay in the report. An expired exception does not apply.

### Coverage and safety properties

- **No plaintext secrets.** The manifest holds sha256 fingerprints only, and the validator rejects anything else. Reports carry a redacted preview and a hash. Tests assert that serialized reports contain no secret material.
- **Canonical fingerprints.** A PEM key matches whether it ships as a `.pem` file or as a `\n`-escaped string literal.
- **Native binaries are scanned.** PE, ELF and Mach-O are read as raw bytes, as Latin-1 and as UTF-16LE. Installers whose payload is compressed (NSIS, Inno Setup, MSI, DMG, pkg) are opaque. So are formats this version cannot decode: 7z, RAR, squashfs, RPM, Cabinet, DMG, encrypted zip entries, zip methods other than stored/deflate/bzip2/LZMA, and xz filters other than delta and x86-BCJ. Opaque or corrupt content makes the content lanes inconclusive.
- **Zero-dependency decoders.** The xz/LZMA2, lzma, bzip2 and lz4 decoders are checked byte-for-byte against xz(1), lzma(1), bzip2, lz4(1), Python `zipfile` and bsdtar. All integrity checks are verified. 3,000 fuzzed corruptions were all rejected, and none decoded silently to wrong bytes ([V02-CHANGES.md](docs/research/V02-CHANGES.md)).
- **Encoded text is decoded.** Base64/base64url, hex and percent-encoding are decoded up to two layers, and only when the result is readable text. Findings record the decoding chain.
- **Read-only, in-memory expansion.** Nothing is extracted to disk. Entry size, total size, entry count and depth are limited to stop decompression bombs. On-disk files up to 2 GiB are read lazily and scanned in overlapping chunks.
- **Known gaps:**
  - the archive formats listed above;
  - encodings beyond two layers, encryption, and secrets assembled at runtime;
  - a credential with no recognised format that is **not** assigned to a credential-named key is not detected, for example `new Client("…")`;
  - the key-noun list is finite, so names like `SEGMENT_WRITE_KEY` are missed. Use `--import` for detector breadth.

## Benchmark (pre-registered v5; run once on 2026-11-07)

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

- The install script fetches the baselines into the gitignored `bench/.tools/`, verifying the publishers' checksums.
- The corpus step generates 260 scenarios across 10 families, including a forced 4 × 5 × 4 grid of undeclared leaks (credential group × render style × repeat). The background is real third-party bytes: Zen browser toolkit code, bash-completion scripts and a `libx265` slice, with the sha256 of each recorded. The **eval seed is derived from the frozen code hash**, so it cannot be picked.
- `run.mjs` refuses to run unless the code matches the hash in the pre-registration and the corpus seed matches that hash.
- `score.mjs` computes exact CIs and McNemar tests, and evaluates H1–H11 mechanically, including v0.5 against the frozen v0.4 build on the same corpus.

See [bench/PREREGISTRATION.md](bench/PREREGISTRATION.md) for the families, held-out strata, hypotheses, dev-set disclosure and threats to validity. The v1–v4 studies are archived in [bench/v1/](bench/v1/) through [bench/v4/](bench/v4/).

## Manifest and policy

Complete examples: [fixtures/demo-app/manifest.json](fixtures/demo-app/manifest.json) and [fixtures/demo-app/policy.json](fixtures/demo-app/policy.json).

- **`releaseClosure.roots`:** **every byte under these roots ships.** Roots may not overlap. There is deliberately no `exclude` option. Use `private` for things that must *not* ship; the tool checks that claim against the actual bytes.
- **`assets[]`:** each asset has an `id` and a `placement` (`server-only`, `sensitive-local` or `public-by-design`).
  - Optional fields: `fingerprints`, `markers` (≥ 4 characters each), `attacker { objective, success, budget }`, `owner`, `rationale`, `offlineRequired`, and `onConfirmedDistribution: "warn"`.
  - A fingerprint may belong to only one asset.
  - A server-only asset with neither markers nor fingerprints is an **unresolved gap**.
- **`authorization`:** principals, tenants, objects, operations and `defaultExpected`, plus explicit `cases`. Conflicting results for one case make the lane inconclusive.

## Status against the research roadmap (§14)

| Stage | Status |
|---|---|
| 0 Research specification | ✅ encoded as types, validation and policy |
| 1 Release assurance foundation | ✅ this codebase, self-reviewed and differentially tested |
| 2 Platform adapters | ◐ Generic containers and raw native-binary scanning only. No DEX, Mach-O or PE *semantics*. |
| 3 Adversarial evaluation | ◐ The release-gate benchmark is pre-registered. Runtime, cloning and tamper lanes are not implemented. |
| 4 Architecture, API, attestation | ◐ Authorization matrix evaluation only |
| 5–6 Transformations, confidential execution | ✗ out of scope until stage-3 measurements justify them |

Byte identity (sha256) does **not** authenticate the build context. Pair the tool with SLSA-style provenance for that (research §9.2).

## Layout

```
src/model/     result states, manifest, policy, evidence types
src/codecs/    zero-dependency xz/LZMA2, lzma, bzip2 and lz4 decoders, CRC32/CRC64/xxHash32
src/lanes/     containers, inventory, detectors, decode (base64/hex/percent), exposure, placement, authorization, external
src/engine/    evaluate (pipeline), gate, report, stats
src/pack/      deterministic asar/zip/tar writers (fixtures and tests)
test/          unit, pipeline, regression and differential tests (node:test)
bench/         v3 pre-registration, corpus generator, runner, scorer, baseline installer, calibration; v1/ and v2/ archived
docs/research/ self-review, tool landscape, calibration, v0.2–v0.5 changes, benchmark results
fixtures/demo-app/  synthetic app, build script, manifest, policy, authz results
```

Every secret in the fixtures and benchmark corpus is **synthetic** and is not used for anything.
