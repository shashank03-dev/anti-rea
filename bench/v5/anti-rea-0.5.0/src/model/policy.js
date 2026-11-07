/**
 * Release policy with HARD GATES (research doc §10).
 *
 * The central correction from the research: an aggregate score cannot be the
 * release authority. A weighted score can look healthy while a critical secret
 * is exposed. Gates are evaluated first; no summary can offset a tripped gate.
 * This engine deliberately produces NO aggregate score.
 */
/**
 * Defaults fail closed on anything specific: an undeclared private key or
 * provider token blocks until an owner triages it (declares it public-by-design,
 * removes it, or records an exception). So does a `<prefix>_<random>` token of
 * an unrecognised provider: that shape is the modern credential convention, and
 * its false-positive rate was measured on real application code before this
 * default was set (docs/research/CALIBRATION.md). Generic entropy hits only
 * warn, because blocking on them would make the gate unusable on real code.
 */
export const DEFAULT_GATES = {
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
export const ALL_GATES = [
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
export const KNOWN_LANES = ["inventory", "exposure", "placement", "authorization", "external"];
