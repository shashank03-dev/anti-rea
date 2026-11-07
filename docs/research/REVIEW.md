# Self-review and verification record (v0.1 → v0.2)

v0.1 passed its own 21 tests. That was weak evidence: every one of those tests was written by the same author as the code. This review re-read every module looking for failures on real releases. It then checked the container code against reference implementations.

## Defects found by code review

Each defect now has a regression test in `test/regressions.test.ts` (R1–R14) that fails on v0.1.

| # | Defect in v0.1 | Consequence on a real release | Fix |
|---|---|---|---|
| R1 | `.exe` classified as an opaque installer | Every Windows Electron release blocked, because `MyApp.exe` is always present | Classify by magic bytes. PE, ELF and Mach-O are scanned as raw bytes. Only real installers and undecodable formats are opaque: NSIS, Inno Setup, MSI/CFB, DMG, xar, 7z, rar, xz, bzip2, zstd, lz4, squashfs, ar, RPM, cab |
| R2 | 64 MiB per-file limit; whole files decoded to one string | Every real Electron app blocked (Electron Framework is ~170 MB). Strings above ~512 MiB crash V8 | 2 GiB on-disk limit; chunked text views with overlap; marker search on raw bytes; on-disk files read lazily |
| R3 | `markers: [""]` accepted | `indexOf("")` returns 0 forever: an **infinite loop** | Markers must be ≥ 4 characters |
| R4 | An asset counted as addressed if any of its records was not inconclusive | A server-only secret whose only meaningful lane (exposure) was inconclusive reported as addressed | Addressed means no inconclusive record |
| R5 | Unanchored `sourceMappingURL` regex | Bundler code that *builds* source-map comments as strings was flagged as an inline map: false block | Only real `//#` lines or `/*# */` blocks count. `data:` templates are ignored |
| R6 | PEM detector accepted any body ≥ 16 characters | Templates such as `${base64Key}` counted as private keys: false block once leads gate | The body must be ≥ 64 characters of base64 |
| R7 | UTF-16LE never scanned | Secrets and markers in Windows/.NET string tables were invisible | Binaries are also scanned as UTF-16LE at both alignments; findings record the encoding and byte offset |
| R8 | Fingerprint tokenizer limited to `[A-Za-z0-9_\-+/.~]` | Declared passwords containing `!@#$%&*:` were never confirmed | Second, broad printable-ASCII tokenizer, also split on `=`/`:`. ASCII-only, so binaries stay cheap |
| R9 | Undeclared high-confidence credentials only warned | A forgotten Slack or AWS token **shipped with a warning** | Split gates. `unconfirmedCredentialLead` (format-specific) blocks; `lowConfidenceCredentialLead` (entropy, JWT, often-public keys) warns. Documented example keys (AWS `…EXAMPLE`) are suppressed and counted |
| R10 | Duplicate authorization result IDs: last one won | Conflicting evidence silently resolved | Conflicting results are treated as errors, so the lane is inconclusive |
| R11 | Default report directory could sit inside a release root | The next scan included the report and the release ID changed | The CLI refuses an `--out` inside any root |
| R12 | Unreadable files and directories threw | The whole run crashed instead of recording a gap | They become unsupported items, so the lane is inconclusive |
| R13 | Zip reader assumed no prepended bytes; tar ignored pax headers | Self-extractor zips misparsed; long tar paths truncated | EOCD-relative offset correction; pax `path=` and GNU `L` long names supported |
| R14 | Overlapping roots and one secret under two placements accepted | Bytes counted twice; ambiguous placement | Both rejected at load time |

Also added:
- the `external` lane, which imports gitleaks or TruffleHog findings and applies the asset model to them; plaintext is hashed on arrival;
- byte-offset locations for binaries;
- release IDs that include unhashed items.

## Defects found only by differential testing

`test/differential.test.ts` compares Anti-REA's container code with reference implementations on real third-party content: the TypeScript compiler's `lib/`, 125 files of about 23 MB, plus long and Unicode paths.

| Reference | Direction | Result |
|---|---|---|
| `@electron/asar` 4.3.1 (Electron's official packer) | its output → our reader; our writer → its lister/extractor | identical bytes for every entry; unpacked entries reported |
| Info-ZIP `zip` (deflate and stored), macOS `ditto`, streaming `zip - -` (data descriptors) | their output → our reader | identical |
| `unzip -t`, Python `zipfile.testzip()` | our writer → them | **failed at first**: see below. Passes after the fix |
| bsdtar 3.5.3 (pax, gnutar, ustar) and `tar -z` | their output → our reader | identical |
| bsdtar | our writer → it | identical |

**Writer bug the unit tests could not catch.** The zip writer stored UTF-8 names under "version made by" host 0 (MS-DOS). That tells readers the names are in the OEM code page, so UnZip transcoded them into invalid bytes and failed. The fix declares host 3 (Unix) with standard file modes and sets general-purpose bit 11 (UTF-8 names), so both strict and lenient readers agree.

**Not a bug, but a behaviour now pinned by a test.** macOS bsdtar writes AppleDouble `._*` members for extended attributes; here those were `com.apple.provenance`. They are real shipped bytes, and the reader correctly surfaces them, even though `tar -tf` hides them.

## Performance on real bytes

The test release was 67 MB: Homebrew's 60 MB `libnode` Mach-O plus the 9 MB TypeScript compiler. It took **1.3 s wall-clock with 384 MB peak RSS** (M-series Mac, Node 26), including the UTF-16LE views and the fingerprint sweep. It produced zero leads, so there was no false-positive noise on a large real native binary.

## Statistics code

`bench/score.mjs` implements the exact Clopper–Pearson interval and the exact McNemar test. Both match reference values from R's `binom.test` and the exact binomial McNemar test:
- CP(7, 10) = [0.3475471, 0.9332605]
- CP(0, 30) upper = 0.1157033
- McNemar(10, 2) = 0.03857422
- McNemar(20, 0) = 1.9073e-06
