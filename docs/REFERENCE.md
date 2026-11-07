# Anti-REA reference

The full technical reference: what each lane checks, every gate, the manifest and policy format, and the known gaps. For the quick start, see the [README](../README.md); for the measurements, see [EVIDENCE.md](EVIDENCE.md).

## What it checks

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
| `unrecognizedTokenLead` | block | A `<prefix>_<random>` token from an unknown provider whose prefix marks it secret (`sk`, `secret`, `tkn`, `pat`, `key`, `api`, …). The shape filters and the secret-marker requirement were calibrated on 2.1 GB of real apps ([CALIBRATION.md](research/CALIBRATION.md)). |
| `keyedCredentialLead` | block | A generated-looking value (random token, 32+ hex, or UUID) assigned to a key whose name ends in a credential noun: `…_API_KEY`, `apiKey`, `access_token`, `client_secret`, `password` and so on. It catches unprefixed credentials. Placeholders, templates, editor-theme scopes and base64-encoded prose are excluded. |
| `lowConfidenceCredentialLead` | warn | A JWT, an often-public key (Google), a test-mode key, or a password in a URL. |
| `platformHardeningViolation` | block | A declared platform expectation is violated: unsigned or ad hoc code where Developer ID is required, a modified code page, a broken bundle seal, no hardened runtime, the wrong team, a forbidden entitlement, an Electron fuse in the wrong state, an ASAR integrity mismatch, or a PE file without Authenticode. |
| `reverseEngineeringAidShipped` | block | (v0.7, when `reAids` is declared) embedded debug info, a debug map, local symbols beyond the allowance, a PDB/dSYM/source map, an original source file, JavaScript that fails the declared minification level, or an insecure Electron `webPreferences` value / `openDevTools()` call ships. Native counts agree with `dsymutil -s` and `llvm-objdump` ([V07-CHANGES.md](research/V07-CHANGES.md)). |
| `provenanceMismatch` | block | A shipped artifact is not a subject of trusted build provenance or differs from the attested digest, or the provenance is unsigned, badly signed or from an unexpected builder. |
| `requiredLaneInconclusive` | block | A required lane did not run to a conclusion. |

There is no aggregate score. Research §10.1 gives a counterexample: a score of 82/100 can coexist with an exposed critical secret.

An exception needs an `owner`, `scope`, `rationale` and `expiry`. It can be narrowed to an `assetId` or a `lane`. Excepted findings stay in the report. An expired exception does not apply.

### Coverage and safety properties

- **No plaintext secrets.** The manifest holds sha256 fingerprints only, and the validator rejects anything else. Reports carry a redacted preview and a hash. Tests assert that serialized reports contain no secret material.
- **Canonical fingerprints.** A PEM key matches whether it ships as a `.pem` file or as a `\n`-escaped string literal.
- **Native binaries are scanned.** PE, ELF and Mach-O are read as raw bytes, as Latin-1 and as UTF-16LE. Installers whose payload is compressed (NSIS, Inno Setup, MSI, pkg) are opaque. So are formats this version cannot decode: 7z, RAR, squashfs, RPM, Cabinet, LZFSE- or APFS-based and encrypted DMGs, encrypted zip entries, zip methods other than stored/deflate/bzip2/LZMA, and xz filters other than delta and x86-BCJ. Opaque or corrupt content makes the content lanes inconclusive.
- **Zero-dependency decoders.** The xz/LZMA2, lzma, bzip2 and lz4 decoders are checked byte-for-byte against xz(1), lzma(1), bzip2, lz4(1), Python `zipfile` and bsdtar. All integrity checks are verified. 3,000 fuzzed corruptions were all rejected, and none decoded silently to wrong bytes ([V02-CHANGES.md](research/V02-CHANGES.md)).
- **Encoded text is decoded.** Base64/base64url, hex and percent-encoding are decoded up to two layers, and only when the result is readable text. Findings record the decoding chain.
- **Read-only, in-memory expansion.** Nothing is extracted to disk. Entry size, total size, entry count and depth are limited to stop decompression bombs. On-disk files up to 2 GiB are read lazily and scanned in overlapping chunks.
- **Platform checks are validated against `codesign(1)`:**
  - cdhashes agree on 145/145 Mach-O files;
  - 0 seal problems on 20 intact installed apps;
  - 25/25 tamper cases agree.

  Certificate chains, notarization and revocation are **not** validated. Use `codesign`/`spctl` or `signtool` for chain trust. Bundle *structure* (for example a missing `Versions/Current` link) and extended attributes are not modelled ([V06-CHANGES.md](research/V06-CHANGES.md)).
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

- **Findings** are graded by a **fixed rubric** (attack surface → severity; [rubric.ts](../src/analyzers/rubric.ts)); analyzers never invent a grade. `--fail-on` uses the **maximum** grade, never an average, so a critical can't be hidden.
- Each finding is attributed **owner vs third-party** (dependencies, vendored runtimes, engine libraries), and marked **avoidable** (a toolchain setting removes it) vs inherent (ObjC/Swift metadata, Go `pclntab`, IL2CPP `global-metadata.dat`).
- The report is **about the product**: a profile (platforms, frameworks, languages), findings by surface with your code first, a deduplicated hardening checklist, coverage with every opaque artifact named, and the REA → Anti-REA matrix.
- It never prints secret values. Go `-ldflags -X`, `KEY=…` pairs and model `__metadata__` are redacted; tests assert a planted secret never appears in the serialized report.
- Distribution: a CI step (`npx -p @anti-rea/cli@0.1.0 anti-rea expose …`, or the composite **GitHub Action** `shashank03-dev/anti-rea@v0.1.0`; see [examples/workflows/exposure.yml](../examples/workflows/exposure.yml)), a zero-dependency **MCP server** (`anti-rea mcp-config`; [docs/AGENTS.md](AGENTS.md)), and the CLI.

Coverage and the honest gaps (Flutter/GPU detected-only; EVM/BEAM detected as roadmap stubs) are in [docs/REA-COVERAGE.md](REA-COVERAGE.md); the design and the tuning-only calibration are in [docs/research/V08-CHANGES.md](research/V08-CHANGES.md).

## Manifest and policy

Complete examples: [fixtures/demo-app/manifest.json](../fixtures/demo-app/manifest.json) and [fixtures/demo-app/policy.json](../fixtures/demo-app/policy.json).

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
