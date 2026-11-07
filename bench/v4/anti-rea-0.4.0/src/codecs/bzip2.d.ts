import { DecodeError, LimitError } from "./xz.js";
export declare function looksLikeBzip2(buf: Uint8Array): boolean;
/**
 * Decompress a .bz2 file. Bytes after the last stream are returned as
 * `trailing` so the caller can still inspect them, instead of dropping them.
 */
export declare function bzip2Decompress(src: Uint8Array, maxOutput: number): {
    data: Buffer;
    trailing: Buffer | null;
};
export { DecodeError, LimitError };
