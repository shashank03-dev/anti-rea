/**
 * Zero-dependency LZ4 frame decoder (LZ4 Frame Format 1.6.x, lz4.org).
 *
 * Supports independent and linked blocks, uncompressed blocks, content size,
 * block and content checksums (xxHash32, verified), skippable frames,
 * concatenated frames and the legacy frame format. Dictionary IDs are
 * rejected: the dictionary is not shipped with the data, so the content
 * cannot be reconstructed. That makes it a coverage gap, never a guess.
 */
export declare const LZ4_MAGIC = 407708164;
export declare function xxh32(b: Uint8Array, start?: number, end?: number, seed?: number): number;
export declare function looksLikeLz4(buf: Uint8Array): boolean;
export declare function lz4Decompress(src: Uint8Array, maxOutput: number): Buffer;
