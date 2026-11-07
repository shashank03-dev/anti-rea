/**
 * Release policy with HARD GATES (research doc §10).
 *
 * The central correction from the research: an aggregate score cannot be the
 * release authority. A weighted score can look healthy while a critical secret
 * is exposed. Gates are evaluated first; no summary can offset a tripped gate.
 * This engine deliberately produces NO aggregate score.
 */
export type GateId = "confirmedCriticalSecret" | "serverOnlyFoundInDistribution" | "reproducedPrivilegedEffect" | "declaredPrivateArtifactShipped" | "unconfirmedCredentialLead" | "unrecognizedTokenLead" | "keyedCredentialLead" | "lowConfidenceCredentialLead" | "requiredLaneInconclusive";
export type GateAction = "block" | "warn";
export interface PolicyException {
    readonly gate: GateId;
    /** Optional narrowing to one asset id. */
    readonly assetId?: string;
    /** Optional narrowing to one lane (used with requiredLaneInconclusive). */
    readonly lane?: string;
    readonly owner: string;
    readonly scope: string;
    readonly rationale: string;
    /** ISO date (YYYY-MM-DD), inclusive. An expired exception does not apply. */
    readonly expiry: string;
}
export interface Policy {
    readonly schema: "anti-rea/policy/v1";
    readonly releaseScope: string;
    /** Lanes that MUST run to a conclusion for a release decision to be valid. */
    readonly requiredLanes: readonly string[];
    /** Action per gate. Defaults are merged in by validatePolicy. */
    readonly gates: Partial<Record<GateId, GateAction>>;
    readonly exceptions?: readonly PolicyException[];
}
/**
 * Defaults fail closed on anything specific: an undeclared private key or
 * provider token blocks until an owner triages it (declares it public-by-design,
 * removes it, or records an exception). So does a `<prefix>_<random>` token of
 * an unrecognised provider: that shape is the modern credential convention, and
 * its false-positive rate was measured on real application code before this
 * default was set (docs/research/CALIBRATION.md). Generic entropy hits only
 * warn, because blocking on them would make the gate unusable on real code.
 */
export declare const DEFAULT_GATES: Record<GateId, GateAction>;
export declare const ALL_GATES: readonly GateId[];
export declare const KNOWN_LANES: readonly ["inventory", "exposure", "placement", "authorization", "external"];
export type LaneId = (typeof KNOWN_LANES)[number];
