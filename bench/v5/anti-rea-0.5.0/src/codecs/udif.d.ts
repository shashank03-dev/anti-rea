/**
 * Zero-dependency reader for Apple UDIF disk images (.dmg), the container
 * `hdiutil` and electron-builder produce.
 *
 * Layout: a 512-byte "koly" trailer points at an XML property list whose
 * `blkx` array holds one "mish" block table per partition. Each table maps
 * runs of 512-byte sectors to chunks in the data fork: zero-fill, raw, ADC
 * (UDCO), zlib (UDZO), bzip2 (UDBZ) or xz (ULMO). LZFSE chunks (ULFO) are
 * rejected as a coverage gap, never guessed. Each table's CRC32 (over every
 * chunk except "ignore" runs) is verified, so corrupted data is never reported
 * as content.
 */
export declare class UnsupportedImage extends Error {
}
export interface Partition {
    readonly name: string;
    readonly data: Buffer;
}
export declare function looksLikeUdif(buf: Buffer): boolean;
/** Encrypted images (hdiutil -encryption) start with this header; their content is unreadable without the passphrase. */
export declare function looksLikeEncryptedDmg(buf: Buffer): boolean;
/** Apple Data Compression (UDCO chunks): a small LZ77 variant. */
export declare function adcDecompress(src: Buffer, outLen: number): Buffer;
/** Decode every partition of a UDIF image. `maxBytes` bounds the sum of partition sizes. */
export declare function readUdif(buf: Buffer, maxBytes: number): Partition[];
