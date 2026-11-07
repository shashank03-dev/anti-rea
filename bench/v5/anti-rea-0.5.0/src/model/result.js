export const OUTCOMES = [
    "recovered",
    "not-recovered-within-budget",
    "inconclusive",
    "not-applicable",
];
/**
 * Whether an outcome counts as a lane having "run to a conclusion". Inconclusive
 * is the only state that represents missing coverage.
 */
export function laneProducedCoverage(outcome) {
    return outcome !== "inconclusive";
}
