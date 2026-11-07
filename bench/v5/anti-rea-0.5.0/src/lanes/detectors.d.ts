import type { Confidence, Severity } from "../model/result.js";
import type { SecretWitness } from "../model/evidence.js";
/**
 * Credential detectors. Every hit is a LEAD, not a confirmed exposure.
 * Confirmation requires the canonical value to match an owner-declared
 * fingerprint (doc §11: "scanner negatives remain limited by detector
 * coverage"; and a public provider key is not automatically a private
 * credential, §6.1).
 *
 * Three kinds, each mapped to its own gate:
 *  - "format": a documented provider format with a distinctive prefix or
 *    structure → `unconfirmedCredentialLead` (blocks by default).
 *  - "structural": a prefixed, high-entropy token whose provider is NOT
 *    recognised but whose prefix marks it secret (`gsk_`, `secret_`, `…_tkn_`)
 *    → `unrecognizedTokenLead` (blocks by default).
 *  - "keyed": a generated-looking value assigned to a key whose name ends in a
 *    credential noun (`TWILIO_AUTH_TOKEN = "…"`, `"apiKey": "…"`). This is how
 *    unprefixed credentials appear in code → `keyedCredentialLead` (blocks by default).
 *  - "heuristic": JWTs, often-public keys, test-mode keys and passwords in URLs
 *    → `lowConfidenceCredentialLead` (warns by default).
 *
 * Formats come from each provider's public documentation of its token format.
 * For breadth beyond this list, import a dedicated scanner (`--import`).
 */
export type DetectorKind = "format" | "structural" | "keyed" | "heuristic";
export interface Candidate {
    readonly detector: string;
    readonly title: string;
    readonly kind: DetectorKind;
    readonly severity: Severity;
    readonly confidence: Confidence;
    readonly value: string;
    readonly index: number;
}
/**
 * Is a credential-named value generated (a credential) rather than a word, path, enum or template?
 * Calibration showed credential-named keys mostly hold editor-theme scopes (`token:
 * "markup.bold.markdown"`) and enum names; those are excluded.
 *
 * v0.5 also judges compound values by their random BODY: `fc-<hex>`, `lsv2_sk_<hex>_<hex>`,
 * `sk-lf-<uuid>`, `app.key:secret`. A short readable prefix no longer counts against the
 * randomness of the rest (v4 dev miss S034: `tvly-<random>` failed the word-run test because of `tvly`).
 */
export declare function generatedValue(v: string): boolean;
/** For profiling and tests: each detector's id and pattern, in run order. */
export declare function detectorPatterns(): [string, RegExp][];
export declare function detectorIds(): string[];
export declare function runDetectors(text: string): Candidate[];
export declare function isKnownExample(c: Pick<Candidate, "detector" | "value">): boolean;
/**
 * Canonical form used for fingerprints. PEM blocks reduce to their base64 body
 * (headers, whitespace and literal `\n` / `\r` escapes removed) so the same key
 * matches whether shipped as a file or embedded in a source string.
 */
export declare function canonicalSecret(value: string): string;
export declare function fingerprintOf(value: string): string;
/** Redacted preview — never enough to reconstruct the secret. */
export declare function witnessOf(value: string): SecretWitness;
export declare function tokens(text: string): Generator<{
    value: string;
    index: number;
}>;
