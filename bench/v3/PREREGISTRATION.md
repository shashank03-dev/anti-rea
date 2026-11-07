# Pre-registration v3: Anti-REA v0.3 vs. current secret scanners as release gates

**Registered:** 2026-11-06. The eval corpus had not been generated, and no tool had been run on it, at registration time.

Earlier studies, archived:
- [bench/v1/](../v1/): v0.1, H1 not supported. Tuned TruffleHog was significantly better.
- [bench/v2/](../v2/): v0.2, H1 not supported. Statistically tied with tuned TruffleHog and gitleaks.

**Frozen tool and harness:** frozen-sha256: `363c69c654472e16fb8daf65f1a5695b557809dbd5d0a4f0f9b6c6c8d7e7f6ee`

`node bench/freeze.mjs` computes the hash over `src/`, `bench/freeze.mjs`, `bench/corpus.mjs`, `bench/run.mjs`, `bench/score.mjs`, `bench/policy.json`, `bench/policy.open.json` and `package.json`.

**Eval seed:** the first 32 bits of the frozen hash, `0x363c69c6`. `bench/run.mjs --set eval` refuses to run if the tree does not match the hash, or if the corpus seed was not derived from it.

## 1. Question

**Primary.** Given the same owner knowledge, is Anti-REA substantially better than current secret scanners at the ship/block decision? This is unchanged from v1 and v2.

**Secondary.** Do the v0.3 changes generalise to data and credential formats that were not used to develop them? The changes are the keyed-credential detector, noise removal, lz4 support, and zip bzip2/LZMA support ([docs/research/V03-CHANGES.md](../../docs/research/V03-CHANGES.md)).

## 2. Systems

The tool versions and configurations are the same as v2: gitleaks 8.30.1, TruffleHog 3.99.8, detect-secrets 1.5.0. The configurations are AR-0, AR-1 (primary), AR-1o (secondary), AR-2, GL-D, GL-T, TH-D, TH-T and DS-D. Everything runs fully offline, and the decision rule is the same as v2.

## 3. Corpus (v3)

There are 10 families × 20 scenarios = **N = 200**. The family list is v2's, with these changes.

**New background.** The v1 and v2 background (this repo's `node_modules` plus `libnode`) was exposed by the v2 run, so v3 uses real bytes that were **never scanned during v0.3 development**:
- Visual Studio Code's built-in extensions (`.js`, `.cjs`, `.mjs` and `.json` files of 2 KB to 1.5 MB);
- LLVM 22.1.8's Python sources;
- the native addon is a 1 MiB slice of Homebrew's `libLLVM.dylib`, plus its Mach-O header.

The pool holds 489 files. `index.json` records the sha256 of every pool file and of the native source.

VS Code's *core* (`out/`, `node_modules`) was validation set B in calibration; the extensions directory was not scanned.

**Wrappers:**
- LEAK-DECLARED gains W14 lz4 and W15 zip-with-bzip2 entries (14 wrappers in total).
- COMPRESSED-CLEAN draws 2 of {xz, bz2, zst, deb, lz4, zip-bzip2}.
- UNVERIFIABLE and UNVERIFIABLE-CLEAN now use formats Anti-REA v0.3 genuinely cannot read:
  - an **encrypted zip** (ZipCrypto);
  - a compressed **DMG** (`hdiutil -format UDZO`).

**UNDECLARED-LEAK.** Each scenario draws one of 4 strata, and **one of 3 render styles**, both uniformly. The strata:
- **INSIDE**: formats v0.1 detected.
- **NAMED**: v1's outside formats, which got named detectors in v0.2.
- **HELDOUT-PREFIXED (new set):** Pinecone `pcsk_`, Supabase `sb_secret_`, ElevenLabs `sk_` + hex, xAI `xai-`, Perplexity `pplx-`, Tavily `tvly-`, Netlify `nfp_`, Neon `napi_`.
- **HELDOUT-UNPREFIXED (new set):** Mistral, Cohere, Deepgram (hex), Postmark (UUID), Segment write key.

None of the held-out formats was used in v2 or in v0.3 development.

The render styles:
- **env**: a provider-named constant or env var, such as `XAI_API_KEY = "…"`;
- **config**: `{"provider": "…", "apiKey": "…"}`;
- **call**: `new XAIClient("…")`, with **no credential-named key**.

## 4. Metrics

The metrics are the same as v2: exact Clopper–Pearson intervals, exact McNemar tests, per-family and per-stratum breakdowns, spurious findings, and median time.

## 5. Hypotheses (scored mechanically by `bench/score.mjs`)

- **H1 (primary).** For every baseline, Δ ≥ 15 points **and** McNemar p < 0.002.
- **H1b.** For every baseline, Δ > 0 **and** p < 0.01.
- **H2.** AR-2's accuracy ≥ AR-1's, **and** AR-2 has strictly fewer UNDECLARED-LEAK false passes.
- **H3.** AR-1 has 0 false passes on UNVERIFIABLE.
- **H4 (keyed detector generalises).** On held-out unprefixed formats in env or config style, AR-1 blocks at least 80%. Call style is a **predicted loss**; it is reported, not scored.
- **H5 (expected loss).** On UNVERIFIABLE-CLEAN, AR-1 has more false blocks than TH-D.
- **H6 (decoders).** AR-1 is correct on at least 95% of COMPRESSED-CLEAN, **and** every LEAK-DECLARED scenario via W7–W12, W14 or W15 is blocked with its needle found.
- **H7 (held-out prefixed).** Secret-marked held-out prefixes (Pinecone, Supabase secret, ElevenLabs) are blocked at least 80% of the time.
- **H8 (noise).** AR-1 has at most 20 spurious findings in total. v0.2 had 217 on v2.
- **H9 (undeclared leaks).** AR-1's correct decisions on UNDECLARED-LEAK are at least TH-T's.

**Author's predictions, written before the eval run:**
- H1: **not supported**. UNVERIFIABLE-CLEAN false blocks are again by design.
- H1b: uncertain.
- H3, H6 and H8: supported.
- H4: **at risk** (see the dev disclosure in §8).
- H5: confirmed.
- H7: at risk. ElevenLabs' hex body is rejected by the structural rule, so in call style it is expected to ship.
- H9: uncertain.

## 6. Procedure

Same as v2:
1. Harness validation on dev only (seed `0x5eed0003`, 4 per family).
2. Changes allowed only to harness parsing and invocation, and to the baseline configs' fairness. **No `src/` change in response to dev results.**
3. Freeze. Then generate the eval corpus and run everything once.

## 7. Threats to validity

- **The author designed both the corpus and the tool.**
  - Families that exercise new decoders favour Anti-REA.
  - The held-out formats and render styles were chosen by the author, who knows how the keyed detector works. The **call** style exists to measure the case it cannot handle.
  - **Per-family and per-stratum results are primary for interpretation.**
- **Background from installed applications.** The bytes depend on the VS Code and LLVM builds on this machine; the sha256 list makes them auditable. They are not redistributable here.
- **Strata sizes are small.** About 5 scenarios per UNDECLARED stratum, and about 1–2 per stratum × style cell. H4 and H7 may be not evaluable or noisy.
- **The tuned baseline configs were written by the author** (see amendment A1).
- **v2's tuned configs** used the unanchored inline-source-map regex that A1 fixes. On v2's background this produced no observed false blocks in PRIVATE-ARTIFACT, but it may have cost GL-T and TH-T false blocks elsewhere. v2's results stand as run.

## 8. Amendments and dev-set disclosure

- **A1: baseline config fairness** (`bench/corpus.mjs`).
  - The tuned gitleaks and TruffleHog rules for inline source maps matched `sourceMappingURL=data:application/json…` anywhere. On the new background, that flagged css-loader code that *builds* such a comment as a string, a false positive of the author's config. This was observed on dev in 2 clean scenarios.
  - Both rules are now anchored to a real `//# sourceMappingURL=data:` comment line, as Anti-REA's own rule is.
  - This makes the baselines stronger. Only GL-T and TH-T were re-run on dev after the fix.
- **A2: scorer label** (`bench/score.mjs`). H9's text hard-coded "/20"; it now prints the actual count. The verdict logic is unchanged.

**Dev-set disclosure** (N = 40, after A1):
- AR-1 34/40, AR-1o 34/40;
- AR-2 33/40;
- GL-T 33/40, TH-T 33/40;
- AR-0 26/40;
- TH-D 24/40;
- GL-D 19/40, DS-D 19/40.

On dev:
- H1 and H1b were not supported;
- H3, H6 and H8 held (AR-1 had **0** spurious findings);
- H5 was confirmed;
- H7 was not evaluable;
- H4 and H9 were not supported.

**Observed on dev and deliberately not fixed** (it would change `src/` in response to dev results): `keyed-credential`'s key-noun list has no `write_key`. A Segment `SEGMENT_WRITE_KEY = "…"` in env style therefore shipped (1 dev scenario). The eval will likely contain more Segment env/config scenarios, which would count against H4 and H9. A v0.4 fix would add `write[_.-]?key` and, more generally, accept `<provider>_KEY` names with a generated value. That fix must be tested in a new pre-registration.
