export declare const ZSTD_SUPPORTED: boolean;
/**
 * Read-only, in-memory expansion of common delivery containers so the release
 * closure covers nested bytes (doc §6.3). Nothing is ever written to disk, so
 * entry names like `../x` cannot escape anywhere.
 *
 * Resource limits guard against decompression bombs (doc §9.3). Anything that
 * cannot be expanded is returned as an explicit unsupported reason — never
 * silently skipped.
 */
export interface Limits {
    /** Largest on-disk file that is read at all. */
    readonly maxFileBytes: number;
    /** Largest single decompressed container entry. */
    readonly maxEntryBytes: number;
    readonly maxTotalExpandedBytes: number;
    readonly maxDepth: number;
    readonly maxEntries: number;
    /** Content lanes decode bytes to text in chunks of this size (strings in V8 are capped near 512 MiB). */
    readonly scanChunkBytes: number;
    /** Overlap between chunks; must exceed the longest bounded match (PEM blocks are capped at 16 KiB). */
    readonly scanOverlapBytes: number;
}
export declare const DEFAULT_LIMITS: Limits;
export interface ContainerEntry {
    readonly name: string;
    readonly data: Buffer | null;
    /** Set when data is null: why this entry could not be read. */
    readonly reason?: string;
}
export type ContainerKind = "zip" | "asar" | "tar" | "gzip" | "xz" | "lzma" | "bzip2" | "zstd" | "lz4" | "ar" | "dmg";
export type Expansion = {
    readonly ok: true;
    readonly kind: ContainerKind;
    readonly entries: ContainerEntry[];
    readonly notes: string[];
} | {
    readonly ok: false;
    readonly kind: ContainerKind;
    readonly reason: string;
};
export type Classification = {
    readonly type: "plain";
    readonly note?: string;
} | {
    readonly type: "container";
    readonly kind: ContainerKind;
} | {
    readonly type: "opaque";
    readonly format: string;
};
/**
 * Classify by magic bytes first, then by extension. Native executables
 * (PE / ELF / Mach-O) are PLAIN: their bytes are scanned directly. Only formats
 * whose payload is compressed or encoded in a way this version cannot decode
 * are opaque — and opaque content is reported as a coverage gap.
 */
export declare function classify(name: string, buf: Buffer): Classification;
export declare function expand(kind: ContainerKind, name: string, buf: Buffer, limits: Limits): Expansion;
export declare function isTar(buf: Buffer): boolean;
