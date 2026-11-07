/** Shannon entropy in bits/character over the characters present in the string. */
export function shannonEntropy(s) {
    if (s.length === 0)
        return 0;
    const counts = new Map();
    for (const ch of s)
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let h = 0;
    for (const c of counts.values()) {
        const p = c / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}
/** Heuristic: looks like an opaque high-entropy token rather than prose/code. */
export function looksHighEntropy(s, minLen = 20, minBits = 3.5) {
    if (s.length < minLen)
        return false;
    // Reject obvious non-secrets: pure words, repeated chars, dotted paths.
    if (/^[a-z]+$/i.test(s))
        return false;
    if (/^(.)\1+$/.test(s))
        return false;
    return shannonEntropy(s) >= minBits;
}
