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
export function zeroEventUpperBound(n, confidence = 0.95) {
    if (!Number.isInteger(n) || n < 1)
        throw new RangeError("n must be a positive integer");
    if (!(confidence > 0 && confidence < 1))
        throw new RangeError("confidence must be in (0, 1)");
    return 1 - Math.pow(1 - confidence, 1 / n);
}
/** Minimum n such that the zero-event upper bound is strictly below `target`. */
export function minTrialsForBound(target, confidence = 0.95) {
    if (!(target > 0 && target < 1))
        throw new RangeError("target must be in (0, 1)");
    // (1 - target)^n < 1 - c  ⇔  n > ln(1 - c) / ln(1 - target)
    let n = Math.ceil(Math.log(1 - confidence) / Math.log(1 - target));
    while (zeroEventUpperBound(n, confidence) >= target)
        n++;
    while (n > 1 && zeroEventUpperBound(n - 1, confidence) < target)
        n--;
    return n;
}
