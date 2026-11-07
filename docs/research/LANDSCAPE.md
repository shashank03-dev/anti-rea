# Current tools: verified capabilities (as of 2026-11-06)

Facts below come from each project's own README or release metadata, fetched on 2026-11-06. Where the installed binary contradicted its README, the binary wins and the correction is noted. "Not documented" means it was not found in those sources; it does **not** mean "not supported". The benchmark measures behaviour instead of relying on documentation.

| Tool | Version | Archives | Decoding | Owner customisation | Gate semantics |
|---|---|---|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 (2026-03-21) | `--max-archive-depth`, **default 0 = off**. Formats come from mholt's `archives` package. Inner paths are joined with `!` | `--max-decode-depth`: base64 (≥ 16 chars), hex (≥ 32), percent. **Correction:** the README says the default is 0 (off), but the 8.30.1 binary's `--help` reports **default 5**, and in practice it decoded base64 with no flags set | Custom `[[rules]]` with `regex` and/or `path`. Allowlists by `regexes`, `stopwords` or `paths`. `[extend] useDefault` | Exit code (default 1) when leaks are found |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | 3.99.8 (2026-11-02) | Archive handlers on by default, with `--archive-max-size`, `--archive-max-depth` and `--archive-timeout` | The README doesn't list decoders. Truffle Security's [blog](https://trufflesecurity.com/blog/secret-scanning-encoded-and-archived-data) and package docs name UTF-8, UTF-16, Base64 and escaped Unicode | Custom regex detectors via `--config` (alpha). `--include-detectors` / `--exclude-detectors`. **No value allowlist documented** | `--fail` exits 183 on results. `--fail-on-scan-errors` exits non-zero on scan errors. Live verification on by default (`--no-verification` turns it off) |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | 1.5.0 (2024-05-06) | not documented | not documented | Plugins and baseline files | Baseline/audit workflow |
| `@yigitguldal/unrea` (npm) | 0.4.0 (2026-10-25) | Third-party listing describes unpacking `app.asar` to a temp dir; flags `.map`/`.env` files and Electron fuses | — | — | **Not executed**: a single-author package that this review did not vet |
| [Electronegativity](https://github.com/doyensec/electronegativity) | — | Scans `.asar` | — | — | A misconfiguration scanner, not a secret scanner (from search results; not verified further) |

Commercial mobile protectors (Guardsquare, PreEmptive) advertise obfuscation, attestation and monitoring. The research document already treats that as advertised overlap only; it says nothing about effectiveness.

## What the documentation does *not* show any of these tools doing

These are differentiation **hypotheses** for the benchmark to test, not established facts:

1. **Classify a found value against an owner asset model without plaintext in the config.**
   - gitleaks can allowlist a public value, but only by putting the value itself in a regex. It cannot say "this exact secret is server-only" without the same.
   - Anti-REA matches canonical sha256 fingerprints.
2. **Treat content it could not inspect as a gate signal.**
   - TruffleHog's `--fail-on-scan-errors` is the closest analogue. It covers *errors*, not "this format is not supported".
   - Whether formats such as `.tar.xz` are decoded is measured, not assumed.
3. **Expand Electron `app.asar`.** Not documented for gitleaks or TruffleHog. asar data is uncompressed, so a raw-bytes scan may still find plaintext inside it; the benchmark measures this.
4. **Ship/block on server-only *implementations* and private artifacts**, beyond credentials. Possible in gitleaks with custom rules, which the tuned baseline (GL-T) receives.
5. **Evaluate server-side authorization results.** Out of scope for secret scanners; not part of the head-to-head.

## Where the current tools are expected to be better

These are pre-registered as H4/H5 and the base64 expectation:
- **Detector breadth.** gitleaks and TruffleHog cover hundreds of provider formats. Anti-REA has 9 detectors.
- **Decoding.** Base64 and UTF-16 decoders, with base64 on by default in both gitleaks 8.30.1 and TruffleHog. Anti-REA decodes neither base64 nor percent-encoding.
- **Archive formats.** The libraries behind these tools handle formats Anti-REA marks opaque (xz, bzip2, 7z…). Anti-REA fails closed on them, which costs false blocks on clean releases.

## Behaviour measured in the v2 benchmark (not from documentation)

Observed with gitleaks 8.30.1 and TruffleHog 3.99.8 on the v2 corpus, using the configurations in bench/PREREGISTRATION.md:

| Content | gitleaks (tuned) | TruffleHog (tuned) | Anti-REA v0.2 |
|---|---|---|---|
| `.tar.xz`, `.tar.zst` | read | read | read |
| `.tar.lz4` | read (15/15 leaks found) | read (15/15) | **not read**: fails closed |
| `.deb` (ar + data.tar.xz) | **not read** (0/2) | **not read** (0/2) | read (2/2) |
| encrypted zip entry | logs "could not read file", **exits 0** | skips silently, **exits 0** | reports a coverage gap and blocks |
| UTF-16LE string in a native binary | not found (0/2) | not found (0/2) | found (2/2) |
| zip inside `app.asar` | not found | not found | found |
| unprefixed provider tokens (Twilio, Cloudflare) | found 4/5 | found 2/5 | warns only (0/5 blocked) |

## Additional behaviour measured in the v3 benchmark

| Content | gitleaks (tuned) | TruffleHog (tuned) | Anti-REA v0.3 |
|---|---|---|---|
| `.tar.lz4`, zip entries compressed with bzip2 | read | read | read |
| compressed DMG (UDZO) | not read; passes | not read; passes | not read; **blocks** (coverage gap) |
| encrypted zip | not read; passes | not read; passes | not read; **blocks** |
| held-out provider tokens in `{"apiKey": "…"}` / `PROVIDER_API_KEY = "…"` | 20/20 of undeclared leaks blocked (generic-api-key rule) | 12/20 | 20/20 |
| examples from documentation (`…EXAMPLE`, Stripe docs test key) | 9/20 passed | 20/20 passed | 20/20 passed |
