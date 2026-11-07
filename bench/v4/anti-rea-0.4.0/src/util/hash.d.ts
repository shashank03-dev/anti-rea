export declare function sha256Hex(data: Buffer | string): string;
/**
 * Deterministic release identity: sha256 over the sorted (path, sha256, bytes)
 * triples of the inventory. Items that could not be hashed (unreadable,
 * symlinks, oversized) are included by path, so a release whose unknown
 * content changes shape also changes identity. Byte identity only (doc §9.2 —
 * authenticating build *context* additionally requires provenance).
 */
export declare function releaseId(entries: readonly {
    path: string;
    sha256: string;
    bytes: number;
}[]): string;
