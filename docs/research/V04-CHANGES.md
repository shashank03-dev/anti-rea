# Anti-REA v0.4 changes

v0.4 targets the two open items left by the v3 benchmark:
- **the untested "call" blind spot:** credentials passed to code, such as `new Client("…")`, rather than assigned to a key;
- **the disclosed `SEGMENT_WRITE_KEY` gap.**

All changes are in `src/lanes/detectors.ts` and `src/lanes/exposure.ts`, with tests in `test/v04.test.ts`. That brings the suite to 70 tests, all passing.

## Detection

| Change | Detector id | Gate |
|---|---|---|
| More key nouns: `write_key`, `sdk_key`, `admin_key`, `credential(s)` | `keyed-credential` | `keyedCredentialLead` (blocks) |
| Any CONSTANT_CASE name ending in `_KEY` (`SEGMENT_WRITE_KEY`, `DD_APP_KEY`, `ALGOLIA_ADMIN_KEY`). Case-sensitive, so camelCase `cacheKey` is excluded | `keyed-constant-credential` | `keyedCredentialLead` |
| A generated value passed as the first argument of a function whose name ends in a credential noun (`setApiKey("…")`, `setAccessToken("…")`, `withToken("…")`). Getters and validators (`get…`, `verify…`, `parse…`) are excluded | `credential-call-argument` | `keyedCredentialLead` |
| A generated value passed to an API client constructor: `new [ns.]…(Client\|Api\|API\|SDK\|Sdk)("…")`, including plain `new Client("…")` | `client-constructor-argument` | `keyedCredentialLead` |
| A hex body behind a **strong** secret-marker prefix (`sk_<hex>`, `sk-or-v1-<hex>`). Unmarked `<prefix>_<hex>` tokens are still treated as digests | `prefixed-secret-token` | `unrecognizedTokenLead` |

**Not detected, by design:**
- a bare factory call with an unknown-format value (`Stripe("…")`, `connect("…")`): there is no credential signal;
- a constructor whose class name carries no client suffix (`new Perplexity("…")`);
- values containing `.` or `:` (`app.key:secret`).

## False-lead guards (each found on real code, with values never printed)

| Guard | Found on | Example (shape only) |
|---|---|---|
| A value whose own prefix marks it public (`client-`, `pk_`, `pub_`, `publishable_`) is never a keyed lead | set A, ChatGPT | `sdkKey: "client-…"` (Statsig client key) |
| Keyed leads in test fixtures (`testdata/`, `test(s)/`, `__tests__/`, `fixtures/`, `_test.go`, `*.test.*`, `*.spec.*`) **warn** instead of blocking | set C, Go source | 32 crypto test vectors such as `PrivateKey: "<hex>"` |
| Structural tokens that are snake_case runs (≥5 segments, ≥2 all-lowercase words) are identifiers | set C, Loom | BoringSSL/Swift symbols in a native binary |
| Values in which a 4-character sequence repeats 3+ times are patterns | set D (see note) | — |
| Values made mostly (≥60%) of `[A-Z][a-z]{2,}` words are CamelCase identifiers | set D, Tailscale | `udp6PWD=<11 capitalised words>` |
| Supabase CLI local-development default keys added to the documented examples | set D, Supabase CLI | `sb_secret_N7UND0…` (published in Supabase docs) |

**Note:** the repetition guard was added for the Tailscale value but did not catch it; the CamelCase guard did. The repetition guard was kept because it is cheap and sound.

## Measured recall cost on random values (5,000 trials each)

**`generatedValue`:**

| Value | Recall |
|---|---|
| 16-char base62 | 81.6% |
| 24-char base62 | 91.0% |
| 32-char base62 | 94.7% |
| 40-char base62 | 97.2% |
| 75-char base64 | 99.7% |

**Structural rule:**

| Token shape | Recall |
|---|---|
| `sb_secret_<31>` | 85.9% |
| `pcsk_` | 99.5% |
| `gsk_` | 98.7% |
| `sk_<hex48>` | 100% |
| `sk-or-v1-<hex64>` | 100% |

The snake_case guard alone rejects under 1.2% of random URL-safe bodies.

## Version

`package.json` and `src/version.ts` are at 0.4.0.
