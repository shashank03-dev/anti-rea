# Anti-REA v0.5 changes

v0.5 targets every loss the v4 benchmark diagnosed, plus the format that dominates macOS releases. It contains:
- a reader for DMG disk images;
- fixes for the generated-value test;
- broader detection of credentials passed in calls;
- more credential-name forms;
- false-lead guards from calibration;
- faster regexes.

The tests are in `test/v05.test.ts`, which brings the suite to 83 tests, all passing.

## 1. DMG disk images are read, not skipped

v0.1–v0.4 treated every `.dmg` as an opaque coverage gap. That made the required lanes inconclusive and blocked every DMG release, clean or not.

**There was also a latent bug.** UDBZ and ULMO images were misclassified as bzip2 or xz streams, because the data fork starts with that magic number. Only the first chunk was decoded, and the rest was treated as trailing bytes.

**`src/codecs/udif.ts`** (zero dependencies):
- **Structure:** it reads the koly trailer and the XML plist's `blkx` tables, then decodes each partition's chunks.
- **Chunk types:** zero-fill, raw, ADC (UDCO), zlib (UDZO), bzip2 (UDBZ) and xz (ULMO).
- **Checksums:** each table's CRC32 is verified. It covers every chunk except "ignore" runs, a detail established empirically against hdiutil images.
- **Explicit coverage gaps:** LZFSE (ULFO), segmented images and unknown chunk types.

**`src/codecs/hfsplus.ts`** (zero dependencies):
- **Reading:** it walks the catalog B-tree leaf chain and reads data forks, including extents stored in the extents-overflow B-tree.
- **Hard links:** they are resolved to their `iNode` files and reported under the link's real path.
- **Names:** HFS+ stores names as NFD; paths are reported as NFC.
- **Extra entries:** resource forks, the extended-attributes B-tree, and every non-zero unallocated block are reported as their own entries, so leftover bytes in a DMG are still inspected.
- **Explicit gaps:** HFS+-compressed (decmpfs) files and APFS volumes.
- **Opaque:** encrypted DMGs (`encrcdsa`) are classified as opaque.

**Measured against `hdiutil(1)`:**

| Test | Result |
|---|---|
| UDZO, UDBZ, UDRO, UDCO and ULMO | byte-identical on 32/32 files |
| Rich image (2,000 files, real Figma app resources, a hard link, Unicode names, a resource fork) | 2,012/2,012 identical |
| A copy of iZip.app | 263/263 identical |
| The 223 MB Claude app resources | 9/9 identical, read in 0.41 s |
| Fuzzing, 3,000 random corruptions of UDZO and UDRO images | 2,966 failed to decode, 34 still decoded to identical bytes, **0 wrong content**, 0 crashes |

## 2. The generated-value test (v4's main miss)

v0.4 rejected every value that wasn't mixed-case, unless it was pure hex of 32+ digits. That covers lowercase-only keys (`csk-<lowercase>`), prefix + hex (`fc-<hex>`, `lsv2_sk_<hex>_<hex>`), short hex secrets and uppercase base32 seeds. Changes:
- **Single-case branch:** 20+ characters with letter–digit alternation, an entropy floor and, for non-hex values, a vowel-share limit. Random letters are about 19% vowels; words are 30–40%.
- **Compound values are judged by their random body:** the longest separator-delimited segment, with a short prefix allowed.
  - Covers `fc-<hex>`, `lsv2_sk_<hex>_<hex>`, `sk-lf-<uuid>` and `app.key:secret`.
  - A short readable prefix no longer counts against the body. This was v4 dev miss S034, `tvly-<random>`.
- **`.` and `:` are allowed in quoted values.** Unquoted, they are member expressions.
- **Always rejected:** URLs, test-mode keys (`sk_test_…`), and separated values whose words would otherwise merge (`x86_64-apple-darwin23.4.0-clang`).
- **Identifier rejection:** snake_case and kebab-case identifiers with several word segments (`EC_KEY_get0_private_key`).

**Acceptance on random values,** 4,000 trials per shape:

| Shape | Acceptance |
|---|---|
| 16-char base62 | 82.5% |
| 24-char base62 | 90.8% |
| 32-char base62 | 95.4% |
| 40-char base62 | 97.0% |
| 40-char url-safe | 97.8% |
| 75-char base64 | 99.5% |
| 20-digit hex | 94.0% |
| 32-digit hex | 100% |
| 20-char lowercase alnum | 83.5% |
| 32-char lowercase alnum | 95.8% |
| 48-char lowercase alnum | 98.3% |
| 32-char base32 | 90.8% |
| `csk-<48>` | 98.5% |
| `fc-<hex>` | 100% |
| `lsv2_sk_…` | 100% |
| `sk-lf-<uuid>` | 100% |
| `app.key:secret` | 99.4% |

**Known gap:** `<uuid>:<hex>` compounds (for example `KEY_ID:KEY_SECRET` pairs) are rejected. Neither half is at least half the value, and separated single-case values are not merged.

## 3. Calls

| v0.4 | v0.5 |
|---|---|
| Credential-named functions (`setApiKey("…")`) | unchanged; getters and validators excluded (`get…`, `verify…`, `check…`, `revoke…`) |
| Constructors only with a Client/Api/SDK suffix | **any constructor** (`new Resend("…")`, `new Ably.Realtime("…")`), except classes that take arbitrary strings (`Error`, `RegExp`, `URL`, `Date`, `Blob`, `Worker`…) |
| — | **configuration methods:** `.init` `.initialize` `.configure` `.config` `.setup` `.connect` `.login` `.signIn` `.authenticate` `.authorize` `.auth` `.use` `.start` `.register` `.load` `.create` `.createClient` |
| — | **assigned factory calls:** `const s = Stripe("…")`, `client = resend("…")`, `=> createClient("…")`. A UUID passed this way is treated as an identifier, and callees named for data (`…FromHex`, `parse…`, `decode…`, `fail`, `hash`, `uuid`) or all-caps (SQL, macros) are excluded |

## 4. Credential names

- **CONSTANT_CASE names with a credential segment anywhere**, not only a trailing `_KEY`: `MJ_APIKEY_PRIVATE`, `API_KEY_PROD`, `STRIPE_SECRET_LIVE`.
  - Names whose last segment says the value is not the secret are excluded (`…_KEY_ID`, `…_TOKEN_URL`, `…_SECRET_NAME`, `…_HEADER`, `…_HASH`).
  - So are names marked public (`…_PUBLIC_KEY`, `…_SITE_KEY`, `…_ANON_KEY`).
- **Tried and dropped:** the bare key `key` (`{"key": "…"}`). On calibration set A it matched 155 content hashes and signing-metadata public keys, with no credentials among them.

## 5. Structural rule

- **Strong markers in more places:** the marker may be the second segment (`lsv2_sk_<hex>_<hex>`), and the random body may be single-case (`csk-<lowercase>`). `esecret` is a strong marker.
- **Fix for a v0.2 bug:** the marker `[a-z]*sk` matched English words ending in "sk". On validation set E that produced 690 false leads in mingw-w64's GCC binaries (`hf3_mask_roundP7rtx_…`). Now up to three letters may precede "sk", and common words (mask, task, desk, disk, risk, ask, flask…) are not markers.
- **Repetition check:** repeated-pattern bodies (`S0_S0_S0_S0`) are rejected.

## 6. Speed

The keyed and credential-call regexes are now anchored on their noun, instead of a 40-character lazy name prefix tried at every identifier character. The configuration-call regex is anchored on `.verb(`.

On 53.8 MB of ChatGPT's minified JS, keyed detection dropped from 329 to 90 ms and credential-call detection from 170 to 64 ms. Overall throughput is in [CALIBRATION.md](CALIBRATION.md), round 5.

## 7. Version

`package.json` and `src/version.ts` are at 0.5.0.
