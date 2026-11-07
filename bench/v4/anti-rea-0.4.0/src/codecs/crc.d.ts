/**
 * Checksums used by the container decoders. Implemented here (not via
 * `zlib.crc32`) so the package keeps working on Node 20, which lacks it.
 */
/** CRC-32 (IEEE 802.3, reflected), as used by zip, gzip and xz. */
export declare function crc32(buf: Uint8Array, start?: number, end?: number): number;
/** CRC-32 with the same polynomial but MSB-first and unreflected, as used by bzip2. */
export declare function crc32be(buf: Uint8Array, start?: number, end?: number): number;
/** CRC-64/XZ. Returns the 8 little-endian bytes as stored in an xz block check. */
export declare function crc64(buf: Uint8Array, start?: number, end?: number): Buffer;
