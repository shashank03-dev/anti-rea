import type { AttackObjective, Placement } from "./result.js";
/**
 * Owner-declared asset manifest (research doc §6).
 *
 * Classification is a business decision, proposed by tooling but CONFIRMED by an
 * owner. Names such as `fraudScore` are leads, not proof of value or sensitivity.
 */
export interface SecretFingerprint {
    /** Only sha256 is supported, so plaintext never enters the manifest. */
    readonly type: "sha256";
    /**
     * Lowercase hex sha256 of the CANONICAL form of the secret (compute it with
     * `anti-rea fingerprint`). For PEM keys the canonical form is the base64 body
     * with headers, whitespace and `\n` escapes removed, so the same key matches
     * whether it ships as a .pem file or inside a JS string literal.
     */
    readonly value: string;
    readonly note?: string;
}
export interface AttackerSpec {
    readonly objective: AttackObjective;
    /** Human description of what counts as success for this asset. */
    readonly success: string;
    /**
     * Attack budget (time / queries / compute). The doc requires this be specified
     * BEFORE evaluation for budgeted-resistance assets; the string is recorded verbatim
     * as evidence of that pre-registration.
     */
    readonly budget?: string;
}
export interface AssetDecl {
    readonly id: string;
    readonly description?: string;
    readonly owner?: string;
    readonly placement: Placement;
    readonly rationale?: string;
    /** Online/offline constraint, recorded because it changes the achievable guarantee. */
    readonly offlineRequired?: boolean;
    /**
     * For server-only / sensitive-local *implementations*: literal marker strings
     * (symbol names, resource names, unique literals) whose presence in the
     * distribution is evidence the implementation is locally present.
     * These are leads, not proof of semantic value (see doc §6.2).
     */
    readonly markers?: readonly string[];
    /** For secret assets: fingerprints of forbidden values (sha256 only). */
    readonly fingerprints?: readonly SecretFingerprint[];
    readonly attacker?: AttackerSpec;
    /** Per-asset override of the policy default for a confirmed distribution finding. */
    readonly onConfirmedDistribution?: "block" | "warn";
}
export interface ReleaseClosureDecl {
    /**
     * Directories (relative to the manifest file) that make up the delivered
     * application. EVERY byte under these roots is treated as shipped, including
     * the contents of supported nested containers (zip/jar/apk/ipa, asar, tar, gzip).
     */
    readonly roots: readonly string[];
    /**
     * Globs for artifacts the owner declares PRIVATE (must not ship) — typically
     * source maps and debug symbols kept for support under access control. The tool
     * does not trust the declaration: any matching artifact found in the shipped
     * bytes trips the `declaredPrivateArtifactShipped` gate.
     */
    readonly private?: readonly string[];
}
export interface AuthorizationCase {
    readonly id?: string;
    readonly principal: string;
    readonly tenant: string;
    readonly object: string;
    readonly operation: string;
    /** The server-enforced ground truth for this (principal × tenant × object × operation). */
    readonly expected: "allow" | "deny";
}
export interface AuthorizationDecl {
    readonly target?: string;
    readonly principals?: readonly string[];
    readonly tenants?: readonly string[];
    readonly objects?: readonly string[];
    readonly operations?: readonly string[];
    /** Explicit cases override the cartesian expansion of the dimensions above. */
    readonly cases?: readonly AuthorizationCase[];
    /** Default expected verdict for generated cases when not otherwise specified. */
    readonly defaultExpected?: "allow" | "deny";
}
export interface Manifest {
    readonly schema: "anti-rea/manifest/v1";
    readonly application: {
        readonly name: string;
        readonly version: string;
    };
    readonly releaseClosure: ReleaseClosureDecl;
    readonly assets: readonly AssetDecl[];
    readonly authorization?: AuthorizationDecl;
}
