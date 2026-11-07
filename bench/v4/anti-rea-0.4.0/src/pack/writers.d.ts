/**
 * Minimal container WRITERS, used to build fixtures and tests that exercise the
 * readers with real nested formats. Deterministic output (fixed timestamps).
 */
export interface PackFile {
    readonly path: string;
    readonly data: Buffer;
}
/** Electron ASAR: [u32 4][u32 headerPickleSize][u32 payload][u32 strLen][json][pad] + file data. */
export declare function writeAsar(files: readonly PackFile[]): Buffer;
/** ZIP (deflate by default, stored with {store:true}). DOS time fixed to 1980-01-01. */
export declare function writeZip(files: readonly PackFile[], opts?: {
    store?: boolean;
}): Buffer;
/** ustar tar archive. */
export declare function writeTar(files: readonly PackFile[]): Buffer;
