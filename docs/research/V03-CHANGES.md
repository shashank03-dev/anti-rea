# v0.3: what changed, and why

v0.2 tied the best tuned scanners on the pre-registered v2 benchmark ([BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md)). Its 28 errors and its noise had three causes:

1. **Unprefixed undeclared credentials only warned.** Twilio and Cloudflare tokens were 0/5 blocked.
2. **Unmarked prefixed tokens only warned.** Resend and Figma tokens were 0/3 blocked.
3. **217 spurious warnings**, from two warn-only rules.

A fourth cause, 20 false blocks, came from failing closed on formats Anti-REA could not read. For **lz4** that was a real decoder gap: the baselines read it. For **encrypted zip** it is a design choice.

v0.3 is evaluated on a **new** pre-registered benchmark (v3). It has a new seed, a new background corpus, and held-out credential formats that were used in neither v2 nor v0.3 development.

## 1. Keyed credentials (new gate `keyedCredentialLead`, default block)

A generated-looking value assigned to a key whose name ends in a credential noun is a blocking lead. This is how unprefixed credentials appear in code and config: `MAILCHIMP_API_KEY = "…"`, `{"apiKey": "…"}`, `client_secret: '…'`. It replaces the v0.2 `credential-assignment` warning, which matched editor-theme scopes and enum names.

Calibration (details in [CALIBRATION.md](CALIBRATION.md), round 3):
- 0 keyed leads on 2.1 GB of tuning data (set A), after one fix;
- 0 leads of any kind on a held-out 417 MB validation set (set B);
- recall 86–100% depending on value shape.

## 2. Noise removal

- `credential-assignment` (warn) was removed. On set A, 562 of its hits were all non-secrets.
- Unmarked prefixed tokens (warn) are no longer reported. On set A, 75 of 75 were non-secrets. A token with an unmarked prefix is still caught when assigned to a credential-named key (§1).
- Warnings on set A fell from 631 to 10.

## 3. Decoders

| Format | Implementation | Verified against |
|---|---|---|
| `.lz4` | `src/codecs/lz4.ts`. Implements the frame format with xxHash32 descriptor, block and content checksums (all verified), independent and linked blocks, uncompressed blocks, content size, skippable frames, concatenated frames and the legacy frame format. An external dictionary ID is rejected as a coverage gap. | `lz4` 1.10: default, `-9 --no-frame-crc`, `-BD -B4 --content-size`, `-BX -B5`, `-l` legacy, concatenated |
| zip method 12 (bzip2) | the v0.2 bzip2 decoder | Python `zipfile` `ZIP_BZIP2` |
| zip method 14 (LZMA) | rewritten to an LZMA_Alone header and decoded by the v0.2 LZMA core | Python `zipfile` `ZIP_LZMA` |

**Fuzzing:** 4,500 corruptions of lz4 frames, with 0 decoded to wrong bytes. A frame written with `--no-frame-crc` has no content checksum, so its corruption can only be caught structurally; that is a property of the format.

Still opaque: 7z, RAR, squashfs, RPM, Cabinet, DMG, MSI, xar/pkg, installers, encrypted zip entries, zip methods other than 0, 8, 12 and 14, and xz filters other than delta and x86-BCJ.

## 4. Verification

- 63 tests pass. New in v0.3: lz4 and zip-method differential tests, plus `test/v03.test.ts`.
- 36 of 36 lz4 and zip-method vectors decode byte-identically to the reference tools.
