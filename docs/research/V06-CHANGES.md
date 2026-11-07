# v0.6 changes

v0.6 does two things. It fixes the held-out misses that the v5 benchmark found, without touching the frozen v5 build. It also adds the stage-2/3 **platform lane** and the stage-4 **provenance lane and decision attestations** from the research roadmap (§14). Every new parser was checked against the platform's own tool before it was trusted.

## 1. Detector fixes for v5's misses

Of v0.5's eight held-out misses in the sealed v5 eval ([BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md)), these were fixed:

| Miss | Cause | Fix |
|---|---|---|
| Klaviyo private keys ×3 | `pk_` was treated as a public prefix | Only `pk_live_` and `pk_test_` (Stripe publishable) are public now; a bare `pk_` is not. |
| fal `<uuid>:<hex>` ×3 | Fixing the v0.5 single-case separator rule broke the UUID-plus-secret shape | `generatedValue` accepts a UUID joined to a random rest of at least 16 characters. |
| `AIRTABLE_PAT` ×1 | "PAT" was not a credential noun | `PAT` was added to `CRED_SEGMENT`. |
| Railway bare-call UUID ×1 | — | **Not fixed, on purpose.** A UUID passed to an unknown factory call is the UUID false-lead class that v0.5 calibration removed. |

An unquoted `NAME=pat….<hex>` is still not a lead, because outside quotes `.` reads as a member expression. That is a known trade-off for `.env`-style files.

A fourth change came from calibration set F, not from any benchmark. Apple's Home.app ships Objective-C selectors such as `hf_clearCached…` that matched the Hugging Face format `hf_[A-Za-z]{34}`. A body that is mostly CamelCase words with an English vowel share is now an identifier. That guard costs 0.6% recall on random tokens ([CALIBRATION.md](CALIBRATION.md), round 6).

These changes were made after v5 was scored. They are therefore not evidence about v5. They are tested in the v6 benchmark under new held-out providers, a new seed and a new background.

## 2. Symlinks are no longer coverage gaps

v0.5 recorded every symbolic link as unsupported content. That made the required inventory lane inconclusive, so **every real macOS app bundle blocked**: framework bundles always contain `Versions/Current` links. A link ships its path, not bytes. v0.6 records links as inventory notes, says whether each target is outside the release closure, and inspects targets inside the closure as themselves.

## 3. Platform lane (`manifest.platform`, gate `platformHardeningViolation`)

The lane uses three zero-dependency readers:

- **Property lists** (`src/codecs/plist.ts`): XML and binary `bplist00`. The XML and binary forms parse to identical values, and they match `plutil -extract`.
- **Mach-O code signatures** (`src/codecs/macho.ts`): thin and fat files, `LC_CODE_SIGNATURE`, the SuperBlob and every CodeDirectory. It reads the identifier, team ID, flags (ad hoc, linker-signed, hardened runtime), the cdhash, the special slots and the entitlements. **Every code page hash is recomputed** against the shipped bytes. Detached CodeDirectories (code-less bundles) are supported too.
- **Bundle seals**: `_CodeSignature/CodeResources` `files2`/`rules2`. The checker verifies:
  - the Info.plist and CodeResources special slots;
  - every sealed resource's SHA-256;
  - nested code against its sealed designated requirement (identifier and team), the same way `codesign` does it;
  - files that were added or deleted after signing, following `omit` rules and the implicit exclusions (`_CodeSignature/`, `_MASReceipt/`, legacy `Contents/CodeResources`).

Expectations the manifest can declare:

| Key | Checks |
|---|---|
| `macos.requireSigned` (default on) | Every Mach-O slice has a code signature. |
| `macos.requireDeveloperId` | The signature has a CMS blob; ad hoc and linker-signed code fail. |
| `macos.requireHardenedRuntime` | Each `MH_EXECUTE` slice has the runtime flag. |
| `macos.teamId` | Developer-signed code carries this TeamIdentifier. |
| `macos.forbiddenEntitlements` | Default: `get-task-allow`, `allow-dyld-environment-variables`, `disable-executable-page-protection`. |
| `macos.requireIntactSeal` (default on) | No bundle seal problems and no modified code pages. |
| `electron.fuses` | Required states, read from the fuse wire (sentinel `dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`, v1 layout), e.g. `{"RunAsNode": false, "OnlyLoadAppFromAsar": true}`. |
| `electron.requireAsarIntegrity` | Each shipped `.asar` in a macOS bundle matches its `ElectronAsarIntegrity` header hash. |
| `windows.requireAuthenticode` | Every PE file has a security directory. This checks presence only. |

If an expectation is declared but the release has nothing it can apply to (no Mach-O, or no fuse wire), the lane is **inconclusive**, not passed.

`anti-rea inspect --manifest m.json` prints these facts without evaluating any policy.

### Validation against `codesign(1)`

- **Mach-O:** cdhashes and signature presence agree with `codesign -dv` on 145/145 Mach-O files sampled from installed apps.
- **Intact apps** (`codesign --verify --deep --strict`, which passed on 20 installed apps and system apps: Ghostty, Loom, Figma, Postman, Claude, ChatGPT, VS Code, Tailscale, WhatsApp, Moonlight, Kai, Vercelify, iZip, Safari, iLovePDF, Vorssaint, Calculator, Mail, and others): **0 seal problems** on every one. Getting there took five fixes, each found on these apps:
  - code-less resource bundles;
  - `CFExecutableName` bundles with no `CFBundleExecutable` (Postman and VS Code helpers);
  - shallow (unversioned) frameworks;
  - `.docktileplugin` bundles;
  - nested code whose recorded cdhash is stale but whose requirement holds, which `codesign` accepts.

  These are fixes to the tool's model of Apple's format, made on installed apps. They were not tuned on any benchmark data.
- **Tamper differential** (copies of Ghostty, Loom and Figma; 25 cases): added resource, modified resource, modified main-executable page, modified Info.plist, modified nested framework, modified `app.asar` body and header, and deleted resource. **Anti-REA and `codesign` agree on 25/25.** Every tamper `codesign` rejects is reported, and the copies `codesign` accepts are clean. (Two Figma byte edits landed in unsigned padding; both tools accept them.)
- **Known disagreements:**
  - **Opera** fails `codesign` because a framework's `Versions/Current` link is missing (two leftover versions). Anti-REA records symlinks as notes and does not model bundle structure, so it reports no problem.
  - **Zen** fails `codesign --strict` on extended-attribute detritus. Inventory does not read extended attributes.
  - Neither tool's verdict here changes the bytes users run, but both gaps are listed in the lane's limitations.
- Certificate chains, notarization tickets and revocation are **not** validated. Use `codesign`/`spctl` or `signtool` for chain trust.

## 4. Provenance lane (`manifest.provenance`, gate `provenanceMismatch`)

Byte identity does not authenticate a build context (research §9.2). The lane reads:

- an in-toto Statement, bare or in a **DSSE envelope**;
- a Sigstore bundle's `dsseEnvelope`;
- JSON, a JSON array or JSON Lines.

It then:

- verifies DSSE signatures (PAE as specified) with Ed25519, ECDSA P-256 or RSA keys **pinned by the owner** (`publicKeys`);
- checks `builderId` against SLSA v1 `runDetails.builder.id` or v0.2 `builder.id`;
- requires every top-level shipped artifact, or the `subjects` globs, to be a subject of a *trusted* statement with the same SHA-256.

Every failure produces a finding:

- an unsigned statement while keys are pinned;
- a bad signature;
- the wrong builder;
- a digest mismatch ("shipped artifact differs from the attested build output");
- an uncovered artifact.

An unreadable provenance file makes the lane inconclusive.

Sigstore certificate chains, Rekor inclusion and keyless identities are **not** verified. Pin a key, or verify them with `cosign` or `gh attestation verify`.

## 5. Signed decision attestations

`anti-rea assure … --sign-key key.pem` also writes `attestation.dsse.json`, a DSSE-signed in-toto Statement:

- **subjects:** every top-level shipped artifact (path and sha256);
- **predicate** (`https://anti-rea.dev/attestation/release-decision/v1`): tool, release ID, decision, blocking reasons, per-gate results, required-lane status, manifest and policy digests, and the **sha256 of report.json**.

`anti-rea verify-attestation --attestation a.json --public-key k.pub [--artifact f]… [--require-decision pass]` checks the signature, the predicate type, subject coverage and the decision. A deploy step can therefore check, without re-running Anti-REA, that *this* decision was made about *these* bytes. Exit code 0 means valid; 2 means invalid.

## 6. Tests

`test/v06.test.ts` adds 13 tests:

- the detector fixes;
- the symlink regression;
- plist XML/binary/`plutil` agreement;
- Mach-O cdhash against `codesign` and page-tamper detection;
- platform-lane expectations on real ad-hoc-signed bundles built with `codesign`;
- a six-case seal differential against `codesign`;
- fuses, including the inconclusive case;
- ASAR integrity;
- provenance with three key types and every failure mode;
- Sigstore bundles and JSON Lines;
- attestations, including a forged payload;
- the set-F selector regression.

The tests that call `codesign`, `plutil` or `hdiutil` are skipped where those tools are missing.
