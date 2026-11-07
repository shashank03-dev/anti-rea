/** Shannon entropy in bits/character over the characters present in the string. */
export declare function shannonEntropy(s: string): number;
/** Heuristic: looks like an opaque high-entropy token rather than prose/code. */
export declare function looksHighEntropy(s: string, minLen?: number, minBits?: number): boolean;
