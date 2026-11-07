/**
 * Release policy with HARD GATES (research doc §10).
 *
 * The central correction from the research: an aggregate score cannot be the
 * release authority. A weighted score can look healthy while a critical secret
 * is exposed. Gates are evaluated first; no summary can offset a tripped gate.
 * This engine deliberately produces NO aggregate score.
 */

export type GateId =
  | "confirmedCriticalSecret" // a forbidden server-only credential confirmed (by fingerprint) in the covered distribution
  | "serverOnlyFoundInDistribution" // owner-declared markers of a server-only implementation present locally
  | "reproducedPrivilegedEffect" // an unauthorized privileged effect reproduced (authorization lane)
  | "declaredPrivateArtifactShipped" // an artifact declared private (e.g. source maps, symbols) is in the shipped bytes
  | "unconfirmedCredentialLead" // a HIGH-confidence, format-specific credential not matched to any declared asset
  | "unrecognizedTokenLead" // a prefixed, high-entropy token of an unrecognised provider, not matched to any declared asset
  | "keyedCredentialLead" // a generated value assigned to a credential-named key, not matched to any declared asset
  | "lowConfidenceCredentialLead" // a medium/low-confidence credential-shaped value (generic entropy, JWT, often-public keys)
  | "requiredLaneInconclusive"; // a mandatory lane could not run to a conclusion

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
export const DEFAULT_GATES: Record<GateId, GateAction> = {
  confirmedCriticalSecret: "block",
  serverOnlyFoundInDistribution: "block",
  reproducedPrivilegedEffect: "block",
  declaredPrivateArtifactShipped: "block",
  unconfirmedCredentialLead: "block",
  unrecognizedTokenLead: "block",
  keyedCredentialLead: "block",
  lowConfidenceCredentialLead: "warn",
  requiredLaneInconclusive: "block",
};

export const ALL_GATES: readonly GateId[] = [
  "confirmedCriticalSecret",
  "serverOnlyFoundInDistribution",
  "reproducedPrivilegedEffect",
  "declaredPrivateArtifactShipped",
  "unconfirmedCredentialLead",
  "unrecognizedTokenLead",
  "keyedCredentialLead",
  "lowConfidenceCredentialLead",
  "requiredLaneInconclusive",
];

export const KNOWN_LANES = ["inventory", "exposure", "placement", "authorization", "external"] as const;
export type LaneId = (typeof KNOWN_LANES)[number];
