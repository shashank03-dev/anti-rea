# Calibrating the v0.2 detectors on real application code

**Purpose:** set the false-positive behaviour of the new detectors *before* the v2 benchmark is frozen, using real code that is **not** part of the benchmark corpus.

**Corpus:** 7 real releases, 2.1 GB in total.
- The shipped `app.asar` and `app.asar.unpacked` of five Electron apps installed on the author's machine: Claude, ChatGPT, Codex Web GPT, Figma and Postman.
- Homebrew's `npm` and `pnpm` packages.

The benchmark's background bytes come from this repository's `node_modules` and Homebrew's `libnode`, and none of them were scanned during calibration. The tool used is [bench/calibration/calibrate.mjs](../../bench/calibration/calibrate.mjs). It prints only redacted witnesses, never values.

## Round 1: structural rule as first written. Rejected.

The first version blocked on any `<lowercase-or-UPPERCASE prefix>_<random ≥ 20>` token whose body had mixed case and digits.

| Release | Blocking structural leads |
|---|---|
| Claude | 14 |
| Postman | 43 |
| ChatGPT | 22 |
| pnpm | 2 |
| Figma, Codex Web GPT, npm | 0 |

**4 of 7 real releases would have been falsely blocked.** Inspecting the matches, with values shown only in shape:

| Shape found | Where | Why it is not a secret |
|---|---|---|
| `TLS_DH_anon_WITH_…`, `N12_GLOBAL__N_1…`, `PFNS_5Value…`, `ss11_StringGuts…` | native addons (OpenSSL tables, C++ and Swift mangled symbols) | identifiers |
| `err33_<32 hex>LL…` | Swift symbol hashes | hash |
| `useandom-26T198340PX75pxJACKVERY…` | the nanoid URL alphabet, in 4 bundles | constant |
| `diff-<64 hex>` | a GitHub diff anchor (SHA-256) in pnpm | hash |
| `cr_nj2Z…` (43 characters) | base64url SHA-256 root hashes in a Chrome-extension `verified_contents.json`, found after base64 decoding | hash |
| `client-<random>`, `env_<random>`, `app_<random>`, `connector_<random>` | ChatGPT and Postman bundles: SDK client keys and public resource identifiers | **random but public by design** |

The last row is the important finding. Shape alone cannot separate a public identifier from a secret: both are a prefix followed by randomness. Real issuers show which is which **in the prefix**: Stripe `sk_`/`pk_`, Statsig `secret-`/`client-`, Supabase `sb_secret_`/`sb_publishable_`.

## Round 2: rule as shipped in v0.2

Changes, each motivated by a row above:
1. Only lowercase prefixes are accepted. This removes the mangled-symbol and cipher-suite names.
2. A body containing 16 or more consecutive same-case hex characters is rejected, and pure-hex bodies are rejected entirely. Hex is indistinguishable from a digest.
3. Bodies are rejected when word-shaped runs make up more than 45% of their characters (`[A-Z]{4,}` or `[A-Z]?[a-z]{4,}`). Measured on 5,000 uniformly random 32–56 character alphanumeric bodies, the 97th percentile is 0.43. snake_case and camelCase identifiers measured 0.48–0.61.
4. A whole token whose length is an unpadded base64url digest length (22, 27, 43, 64 or 86) is rejected.
5. **The rule blocks only when the prefix marks the token as secret.** The marker set is `sk`/`…sk`, `secret`, `sec`, `key`, `token`, `tkn`, `tok`, `pat`, `pw`, `pass`, `priv`, `api`, `auth`, `svc`, `srv`, `server`, `admin`, `root` and `master`. Gate: `unrecognizedTokenLead`, which blocks by default.
6. Any other prefixed random token is a `prefixed-token` lead on the warn-only `lowConfidenceCredentialLead` gate.

| Release | Size | Time | Blocking structural leads | Warn-only `prefixed-token` |
|---|---|---|---|---|
| Figma | 23 MB | 0.4 s | 0 | 3 |
| Codex Web GPT | 41 MB | 0.7 s | 0 | 0 |
| Claude | 223 MB | 4.3 s | 0 | 4 |
| Postman | 319 MB | 5.4 s | 0 | 52 |
| ChatGPT | 1,451 MB | 21.8 s | 0 | 10 |
| npm | 12 MB | 0.6 s | 0 | 0 |
| pnpm | 37 MB | 1.3 s | 0 | 0 |

**Zero blocking structural leads on 7 of 7 real releases.** Throughput was about 66 MB/s, base64/hex/percent decoding included.

**Recall cost:** on uniformly random bodies, recall is 94–98% for secret-marked prefixes, which block. It is about 96% for unmarked prefixes, which only warn. A token whose prefix carries no secret marker, such as Replicate's `r8_` or Fly's `fo1_`, therefore **ships with a warning**. That is a known, pre-registered loss (bench/PREREGISTRATION.md, H7).

## Other findings from the calibration set

- **Format detectors.** There were 5 hits:
  - a PEM private key inside a Claude JS chunk;
  - PEM keys inside two Postman native addons, plus a `server.key` file;
  - one Azure storage key in ChatGPT.

  The Azure key is the **Azure Storage Emulator development key** that Microsoft publishes, so it was added to the documented-examples list. The PEM keys are real format matches; whether they are live is unknown and was not investigated. Any secret scanner would flag them, and they are reported here only as counts.
- **Base64 decoding** produced no spurious credential leads on 2.1 GB, apart from the digest case fixed in rule 4.
- **Performance regression found and fixed.** The first percent-decoding regex backtracked quadratically on long runs in native binaries: 4.9 s per 4 MB, and more than 10 minutes on the Claude bundle. The replacement is linear (13 ms per 4 MB) and has a regression test (`test/v02.test.ts`, "decoding is linear on long runs").

## Round 3 (v0.3): keyed credentials, noise removal, and a held-out validation set

**Problem, from the v2 benchmark.**
- Undeclared credentials **without** a distinctive prefix only warned (0/5 blocked).
- Warn-only rules produced 217 spurious warnings.

On calibration set A (the same 7 releases), the two v0.2 warn-only rules accounted for **631 warnings**:
- `credential-assignment`: 562;
- unmarked `prefixed-token`: 69.

**What they actually matched**, inspected by shape (values masked):

| v0.2 rule | Dominant matches | Credentials among them |
|---|---|---|
| `credential-assignment` | editor-theme scopes (`{token:"markup.bold.markdown"}`, hundreds in Postman and ChatGPT), enum names (`…_AUTH_PROVIDER_ONEPASSWORD="BROWSER_…"`), regex fragments, `?token=` concatenations | none found |
| `prefixed-token` (unmarked) | OpenSSL snake_case identifiers in native addons (`…_to_PrivateKeyInfo_der_encode`), public SDK and resource IDs (`client-…`, `app_…`, `connector_…`) | none (75/75 non-secret) |

**Changes in v0.3:**
1. `credential-assignment` was removed. It is replaced by **`keyed-credential`**, a new gate `keyedCredentialLead` that blocks by default. It needs both of the following:
   - a key whose name **ends** in a credential noun: `…api_key`, `apiKey`, `…_token`, `access_token`, `client_secret`, `password`, `private_key` and others;
   - a **generated-looking** value: hex of 32 or more characters (optionally with a `-usNN` datacentre suffix), a UUID, or a 16+ character token with mixed case and digits, word-run fraction ≤ 0.45 and entropy ≥ 3.5.

   It rejects placeholders (`your…`, `example`, `xxxx`, `${…}`) and values that base64-decode to readable prose.
2. An unmarked prefixed token no longer produces any lead by itself. It is still caught when assigned to a credential-named key.

**Calibration set A** (tuning, 7 releases, 2.1 GB):
- `keyed-credential` produced 1 hit: `password: '<base64 of "not my real password">'` in npm's `@npmcli/arborist` README.
- The base64-prose rule (rule 1 above) was added for it. **After the fix: 0 keyed leads.**
- Warnings fell from 631 to 10. All 10 are JWTs in Postman.

**Validation set B: held out, run once after tuning.** It covers Visual Studio Code's core (`out/`, `node_modules`, `node_modules.asar` and `.unpacked`, `bin/`) and Homebrew OpenSSL 4's `libcrypto`, `libssl` and `ossl-modules`: 6,610 items, 417 MB.

**Result on B: 0 leads of any kind**, blocking or warn-only.

**Recall of `keyed-credential`** on generated values under four key styles (1,000 trials each):

| Value shape | Recall |
|---|---|
| 32-hex | 99.9% |
| UUID | 100% |
| Mailchimp-style hex plus suffix | 99.9% |
| 40-char base64 | 97.9% |
| 40-char URL-safe | 97.6% |
| 24-char base62 | 94.9% |
| 16-char base62 | 85.9% |

**Known limit:** a credential that has no recognised format and is **not** assigned to a credential-named key is not detected. An example is `new Client("…")`. The v3 benchmark measures this as the "call" render style.

## Round 4 (v0.4): call-style detection, `*_KEY` names, and two more validation sets

The v0.4 detectors are described in [V04-CHANGES.md](V04-CHANGES.md). The procedure:
1. tune on set A;
2. validate once on a new set C;
3. after fixes, validate once on a new set D.

None of these sets overlaps the v4 benchmark background (Zen's `omni.ja`, Zig std, ffmpeg).

**Set A** (tuning: the same 7 releases, 2.1 GB):
- First pass: 1 new keyed lead, `sdkKey: "client-…"` (a public Statsig client key).
- Fix: values whose prefix marks them public are not leads.
- After: back to the v0.3 baseline. There are no keyed, call or structural leads; the 4 PEM blocks and 10 JWTs are unchanged.

**Set C** (validation, first and only clean pass), 1.8 GB:
- Contents: Go 1.27 standard library source and 9 apps (Opera, Loom, Kai, Moonlight, Vorssaint, Mister Horse Product Manager, Ghostty, Vercelify, iZip).
- Blocking leads from the keyed and structural rules:

  | Release | Leads | What they were |
  |---|---|---|
  | Go | 32 keyed | all crypto test vectors under key names (`PrivateKey`, `shared_secret`, `exporter_secret`) in `ecdh_test.go` and `hpke-pq.json` |
  | Loom | 2 structural | BoringSSL symbol names in a native binary |

  Both rules already existed in v0.3, so v0.3 would have flagged these too. None came from a v0.4 addition.
- **Fixes:** keyed leads in test-fixture paths warn instead of blocking, and snake_case symbols are rejected. After the fixes, C has 0 blocking keyed or structural leads.
- The remaining format leads are true format matches, not investigated:
  - 2 Google OAuth client secrets (`GOCSPX-`) in Opera's framework;
  - 3 PEM keys in Go's test data.

**Set D** (validation after the C fixes), 4.8 GB:
- Contents: WhatsApp, Tailscale, iLovePDF, Pages, Numbers and Keynote (Creator Studio editions), and the Homebrew `gh`, `docker`, `supabase` and `bun` packages.
- Results:
  - **WhatsApp: 1,689 keyed leads**, all inside hex-encoded JSON in `Assets.car`. The keys are `sshPassword` (771), `webServerSecret` (572) and `inproxySessionRootObfuscationSecret` (190). They appear to be embedded proxy-server entries: **real credentials, shipped to every user by design**. The detector is right that they are credentials. An owner would declare them public-by-design, so they are reported here as true leads, not false positives. They would also have been flagged by v0.3.
  - **Tailscale: 1 keyed lead**, a CamelCase identifier under `udp6PWD`. This is a false positive, fixed after D by the CamelCase guard.
  - **Supabase CLI: 1 structural lead**, the published local-dev `sb_secret_` key. It is a documented example, added to the examples list after D.
  - **`gh`: 1 `github-token` format lead.** This is a format detector unchanged since v0.1, and the lead was not investigated.
- **After the fixes,** D shows only WhatsApp's 1,689 true leads, the `gh` format lead, the PEM blocks and warn-only heuristics. **Because the fixes came after D, D is now tuning data too.** The v4 benchmark background is the next unseen data.

## Round 5 (v0.5): broader call and value rules, tuned on A, C and D, validated once on a new set E

The rules are described in [V05-CHANGES.md](V05-CHANGES.md). Sets A, C and D (about 9.4 GB) were all already tuning data. **Set E** (7.6 GB, never scanned before) was the one-time validation set:
- Adobe After Effects 2024, including Creative Cloud JavaScript extensions;
- `/Applications/Utilities`;
- the mingw-w64 toolchain;
- 13 Homebrew tools: cloudflared, restic, lima, colima, uv, icu4c, sqlite, shellcheck, lld, svt-av1, x264, bats-core and rsync.

**Tuning, round 1** (A, C, D). The new rules produced false leads:

| Rule | Leads | What they were |
|---|---|---|
| bare `key` | 155 | content hashes under `{key:"<hex>"}` in Claude's bundles; public keys in TUF/sigstore metadata |
| bare calls | 45 blocking | UUIDs in C# `[Guid("…")]` and SQL `VALUES ('…')`; Go hex constants (`bigFromHex("…")`); error strings (`fail("EC_KEY_…")`) |
| keyed | 4 | unquoted member expressions (`sharedSecret = nacl.box…`) |

**Fixes:**
- the bare `key` rule was dropped;
- positional UUIDs are treated as identifiers;
- bare calls count only when their result is assigned;
- callees named for data handling are excluded;
- `.` and `:` are allowed only inside quotes;
- snake_case identifier values are rejected.

**Tuning, round 2** (A, C, D): the only blocking keyed, call or structural leads are WhatsApp's 1,689 embedded proxy credentials, which are true leads. Go's test vectors stay warn-only.

**Validation on E** (single clean pass), **failed:**

| Release | Leads | Assessment |
|---|---|---|
| mingw-w64 | **690 structural** | false: GCC symbols such as `hf3_mask_roundP7rtx_defS0_S0_…`. The marker `[a-z]*sk` had matched the word "mask" since **v0.2**. |
| After Effects | 28 keyed | true: OAuth client secrets (`clientSecret`, `CLIENT_SECRET`, `typekitClientSecret`) for Adobe's services, shipped in its apps |
| Utilities | 2 keyed | true: the same kind of client secret |
| After Effects | 1 keyed | ambiguous: a `gtoken=` URL parameter, counted within the 28 above |

**Fixes after E:**
- common words ending in "sk" are not markers, and at most three letters may precede "sk";
- repeated-pattern bodies are rejected.

After these fixes mingw-w64 has 0 leads. **E is therefore tuning data now.**

**Final run of the frozen v0.5 rules** over A, C, D and E (43 targets, 17.1 GB):

| Gate | Leads | Composition |
|---|---|---|
| Blocking keyed | 1,719 | 1,689 WhatsApp proxy credentials and 30 Adobe OAuth client secrets: real credentials shipped by design |
| Blocking structural or call | **0** | — |
| Format (unchanged rules) | 13 | 10 PEM blocks, 2 Google OAuth client secrets, 1 GitHub token |
| Warn-only | 59 | 34 Go test vectors, 11 JWTs, 9 URL passwords, 5 Google API keys |

**Throughput,** on the same set A bytes: v0.4 ran at 48.2 MB/s and **v0.5 at 55.4 MB/s**, despite the extra rules, because the hot regexes are now anchored. Across all 17.1 GB it averaged 31.5 MB/s; that figure includes After Effects' 6.1 GB of binaries.

## Round 6 (v0.6): A–E re-run, then a new validation set F

v0.6 changed three content rules for v5's misses ([V06-CHANGES.md](V06-CHANGES.md) §1):
- `pk_` is no longer public;
- a UUID plus a random rest is generated;
- `PAT` is a credential noun.

**Re-run on A–E** (43 targets, 17.1 GB, all tuning data): **identical to v0.5's final run.**

| Gate | Leads | Composition |
|---|---|---|
| Blocking keyed | 1,719 | the same WhatsApp proxy credentials and Adobe client secrets |
| Blocking structural or call | 0 | — |
| Format | 13 | unchanged |
| Warn-only | 59 | unchanged |

The three new rules produced **no new lead on 17.1 GB of real code.**

**Validation on F** (single clean pass; 12 targets, 1.58 GB, never scanned before):
- `/System/Applications`, all 51 of them;
- Homebrew openssl@4, gettext, ncurses, pcre2, aria2, libssh2, docker-compose, docker-buildx, sdl3, highway and simdjson.

**F failed:**

| Release | Leads | Assessment |
|---|---|---|
| Home.app (and its widget) | **1 blocking format lead** (`huggingface-token`) | **false.** Objective-C selectors from Apple's HomeFoundation category prefix (`hf_clearCached…`, `hf_currentUserSupported…`) contain 34-letter runs matching `hf_[A-Za-z]{34}`. That rule is unchanged since v0.1. There were 8 distinct matching strings. |
| aria2 | 1 warn-only URL password | documentation example |

There were 0 keyed, structural or call leads on F.

**Fix after F:** the Hugging Face format rule rejects a body whose CamelCase-word coverage is ≥ 0.7 **and** whose vowel share is ≥ 0.28. English identifiers are about 38% vowels; random letters about 19%.

| Measure | Result |
|---|---|
| Selectors rejected | all 8 |
| Random 34-letter bodies rejected (wrongly) | 0.62%, measured on 400,000 |
| Hugging Face recall on random tokens after the fix | 99.4% |

A grid of thresholds was tried on these 8 strings, so the guard is fitted to one app's selectors. **F is therefore tuning data now.** The v6 benchmark background (git `share/`, abseil, libvpx) is the next unseen data.

After the fix, `/System/Applications` has 0 leads.

**Throughput** across A–E was 31.7 MB/s (v0.5: 31.5 MB/s). F ran at 20.3 MB/s, dominated by `/System/Applications`' many small Mach-O files. Both runs shared the machine with other jobs.

**Pattern across rounds:** every fresh validation set so far (C, D, E, F) has found at least one false-lead class. The classes are getting smaller: 690 leads in E, 1 in F. They have also moved from the new rules to an old format rule. A new kind of release should still be expected to produce some false leads. Triage them with scoped, expiring exceptions.
