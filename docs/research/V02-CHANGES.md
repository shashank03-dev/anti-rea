# v0.2: what changed, and why

v0.1 lost the pre-registered v1 benchmark ([BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md)). 27 of its 28 errors came from two gaps:

1. It failed closed on `.tar.xz`, which it could not decode (20 errors).
2. Undeclared credentials in formats outside its 9 detectors only warned (7 errors).

The remaining error was a base64-wrapped secret. v0.2 addresses each of these. It is evaluated on a **new** pre-registered benchmark with a new seed and new families ([bench/PREREGISTRATION.md](../../bench/PREREGISTRATION.md)), never by re-scoring the v1 corpus.

## 1. Decoders: xz, lzma, bzip2, zstd, ar/.deb

| Format | Implementation | Verified against |
|---|---|---|
| `.xz` | `src/codecs/xz.ts`: LZMA2 plus the delta and x86-BCJ filters. Every field and integrity check of the .xz format 1.2.1 is validated: header, block and index CRC32, CRC64 and SHA-256 block checks, the index, footer and backward size, padding, and concatenated streams. | xz 5.x: presets 0/6/9e, check types none/crc32/crc64/sha256, `--x86`, `--delta`, multithreaded multi-block output, concatenated streams with padding; plus bsdtar `-J` |
| `.lzma` | `src/codecs/xz.ts` (LZMA_Alone) | `lzma(1)` |
| `.bz2` | `src/codecs/bzip2.ts`: Huffman, MTF and RLE2, inverse BWT, then RLE1. Block and stream CRCs are verified, and concatenated streams are supported. Bytes after the last stream become a scanned entry. | `bzip2 -1`/`-9`, bsdtar `-j`, concatenated streams |
| `.zst` | Node's built-in `zlib.zstdDecompressSync` (Node ≥ 22.15 or 23.8). On older Node it remains an explicit coverage gap. | bsdtar `--zstd` |
| `.deb` / `ar` | `src/lanes/containers.ts`: BSD `#1/` and GNU `//` long names. Symbol tables are skipped, and trailing bytes become a scanned entry. | macOS `ar(1)` |

**Robustness.** I fuzzed 1,500 random bit-flip and truncation corruptions of each of an xz and a bzip2 file. All 3,000 were rejected with a typed `DecodeError` or `LimitError`, and **0 decoded to wrong bytes**. Corrupt input becomes an `inconclusive` coverage gap, so it blocks; it is never read as "no secrets here". Output is capped at `maxEntryBytes`, as for gzip and zip.

Still opaque, and so still failing closed: 7z, RAR, lz4, squashfs, RPM, Cabinet, DMG, MSI, xar/pkg, NSIS/Inno installers, encrypted zip entries, and xz filters other than delta and x86 (ARM/ARM64/PowerPC/IA-64/SPARC/RISC-V BCJ).

## 2. Text-encoding decoding: base64, hex, percent

`src/lanes/decode.ts` decodes every base64 or base64url run of 20 or more characters, every even-length hex run of 32 or more, and every percent-encoded token with 3 or more escapes. It recurses up to 2 layers. A run is kept only if it decodes to valid UTF-8 that is at least 90% printable. Images, digests and random bytes therefore produce nothing. Findings record the decoding chain (`decoded: base64 > percent`) and point at the encoded run.

On the 2.1 GB calibration set this added **no spurious credential leads**, apart from one case: base64url digests. That is handled in §3, rule 4.

## 3. Detectors and gates

- **Named format detectors** grew from 6 to 35, each a prefix or structure documented by its provider. They include the 8 formats v0.1 missed in v1 (GitLab, npm, SendGrid, Hugging Face, Shopify, DigitalOcean, Anthropic and OpenAI). *This is fitting to what v1 exposed*, which is why the v2 benchmark has a separate **held-out** stratum of formats with no named detector.
- **The structural rule** is new. It catches `<lowercase-prefix>_<random>` tokens from providers Anti-REA does not know.
  - It **blocks** (new gate `unrecognizedTokenLead`, default block) only when the prefix marks the token as secret: `sk`, `secret`, `tkn`, `pat`, `key`, `api`, `auth` and similar.
  - Otherwise it **warns** (`prefixed-token` on `lowConfidenceCredentialLead`).
  - The split, and the shape filters, come from calibration on real apps. A first version would have falsely blocked 4 of 7 real releases, on public SDK keys and on identifiers. See [CALIBRATION.md](CALIBRATION.md).
- **Heuristics** cover JWTs, Google keys, credential-named assignments, test-mode keys (`sk_test_`) and passwords embedded in URLs. They still only warn, and they no longer re-report a span that a specific detector already explained.
- **Documented examples:** the Stripe API-reference test keys and the Azure Storage Emulator key were added.

## 4. Bugs found while building v0.2

| Bug | Found by | Fix and test |
|---|---|---|
| The percent-decoding regex was quadratic: 4.9 s per 4 MB of binary, more than 10 minutes per real app | the calibration run's wall time | linear scanner; `v02.test.ts` "decoding is linear" |
| The heuristic `credential-assignment` claimed spans before the structural rule, so `GROQ_KEY = "gsk_…"` only warned | unit test | detector order is format, then structural, then heuristic; `v02.test.ts` |
| After the reorder, Stripe `sk_test_` keys tripped the structural rule | unit test | `<x>_test_` prefixes are test-mode and warn only; `v02.test.ts` |
| A test assumed macOS `ar rc` keeps non-object members. It silently drops them. | differential test | the test uses `ar -S -q`. The reader was correct. |
| `.lzma` with an unknown size was rejected as "Infinity exceeds limit" | codec differential run | the limit check is skipped for unknown size |

## 5. Verification

- 57 tests pass: unit, pipeline and regression tests, differential tests against xz(1), bzip2, lzma, bsdtar (xz/bz2/lzma/zstd), ar and Info-ZIP, plus `v02.test.ts`.
- Codec differential: 58/58 test vectors decode byte-identically to the reference tools.
- Calibration: 0 blocking structural leads on 7 real releases totalling 2.1 GB, at about 66 MB/s.
