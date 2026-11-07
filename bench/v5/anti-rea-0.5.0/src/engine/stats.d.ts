/**
 * Zero-event confidence bounds (doc §11, "Statistical interpretation").
 *
 * For zero observed events in n independent Bernoulli trials with equal event
 * probability, the exact one-sided upper bound at confidence c solves
 * (1 − p)^n = 1 − c, i.e. p_upper = 1 − (1 − c)^(1/n).
 *
 * Valid ONLY for independent trials (e.g. sampled false-denial studies). It must
 * not be applied to correlated attack attempts and presented as a "probability
 * of security".
 */
export declare function zeroEventUpperBound(n: number, confidence?: number): number;
/** Minimum n such that the zero-event upper bound is strictly below `target`. */
export declare function minTrialsForBound(target: number, confidence?: number): number;
