/**
 * Result states for an evaluation lane (research doc §9.1).
 *
 * The distinction between these states is load-bearing: a budget expiring after
 * a valid attempt ("not-recovered-within-budget") is NOT the same as a tool
 * failing before it did the required work ("inconclusive"). A required lane can
 * never silently pass.
 */
export type Outcome =
  | "recovered" // the defined attacker objective succeeded / a prohibited effect was reproduced
  | "not-recovered-within-budget" // a valid attempt completed its declared budget without success
  | "inconclusive" // tool unavailable, unsupported content, crash, invalid evidence, or insufficient coverage
  | "not-applicable"; // the test does not apply under the declared asset/platform scope

export const OUTCOMES: readonly Outcome[] = [
  "recovered",
  "not-recovered-within-budget",
  "inconclusive",
  "not-applicable",
] as const;

/** Confidence in a single finding, kept separate from the lane outcome. */
export type Confidence = "confirmed" | "high" | "medium" | "low";

/** Severity of a finding, independent of whether it blocks (policy decides that). */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Placement = "server-only" | "sensitive-local" | "public-by-design";

export type AttackObjective =
  | "secret-extraction"
  | "implementation-recovery"
  | "behavioral-cloning"
  | "authorization-bypass"
  | "tampering-or-redistribution"
  | "legitimate-client-abuse";

/**
 * Whether an outcome counts as a lane having "run to a conclusion". Inconclusive
 * is the only state that represents missing coverage.
 */
export function laneProducedCoverage(outcome: Outcome): boolean {
  return outcome !== "inconclusive";
}
