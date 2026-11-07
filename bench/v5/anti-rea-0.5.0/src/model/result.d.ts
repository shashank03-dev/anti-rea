/**
 * Result states for an evaluation lane (research doc §9.1).
 *
 * The distinction between these states is load-bearing: a budget expiring after
 * a valid attempt ("not-recovered-within-budget") is NOT the same as a tool
 * failing before it did the required work ("inconclusive"). A required lane can
 * never silently pass.
 */
export type Outcome = "recovered" | "not-recovered-within-budget" | "inconclusive" | "not-applicable";
export declare const OUTCOMES: readonly Outcome[];
/** Confidence in a single finding, kept separate from the lane outcome. */
export type Confidence = "confirmed" | "high" | "medium" | "low";
/** Severity of a finding, independent of whether it blocks (policy decides that). */
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Placement = "server-only" | "sensitive-local" | "public-by-design";
export type AttackObjective = "secret-extraction" | "implementation-recovery" | "behavioral-cloning" | "authorization-bypass" | "tampering-or-redistribution" | "legitimate-client-abuse";
/**
 * Whether an outcome counts as a lane having "run to a conclusion". Inconclusive
 * is the only state that represents missing coverage.
 */
export declare function laneProducedCoverage(outcome: Outcome): boolean;
