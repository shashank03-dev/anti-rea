/**
 * Zero-dependency decoders for the .xz container (LZMA2, with the delta and
 * x86-BCJ filters) and the legacy .lzma ("LZMA_Alone") format.
 *
 * Written against the published format documents: "The .xz File Format"
 * version 1.2.1 (tukaani.org) and the LZMA SDK's description of the
 * LZMA / LZMA2 bitstreams. Every structural field is validated, and so is every
 * integrity check xz defines (CRC32, CRC64 and SHA-256 block checks, the index
 * and the stream footer). A decoder that silently accepts damaged input would
 * report "nothing found" for bytes it never really read.
 *
 * Output is capped at `maxOutput` bytes. Exceeding it throws `LimitError`,
 * which the caller reports as an expansion-limit coverage gap.
 */
export declare class DecodeError extends Error {
}
export declare class LimitError extends Error {
}
export declare class Out {
    readonly limit: number;
    buf: Uint8Array;
    pos: number;
    constructor(initial: number, limit: number);
    ensure(n: number): void;
    result(): Buffer;
}
declare class RangeDecoder {
    range: number;
    code: number;
    ip: number;
    end: number;
    src: Uint8Array;
    init(src: Uint8Array, ip: number, end: number): void;
    normalize(): void;
    bit(p: Uint16Array, i: number): number;
    tree(p: Uint16Array, base: number, bits: number): number;
    reverse(p: Uint16Array, base: number, bits: number): number;
    direct(bits: number): number;
}
declare class LenDecoder {
    readonly choice: Uint16Array<ArrayBuffer>;
    readonly low: Uint16Array<ArrayBuffer>;
    readonly mid: Uint16Array<ArrayBuffer>;
    readonly high: Uint16Array<ArrayBuffer>;
    reset(): void;
    decode(rc: RangeDecoder, posState: number): number;
}
export declare class LzmaDecoder {
    lc: number;
    lp: number;
    pb: number;
    state: number;
    rep0: number;
    rep1: number;
    rep2: number;
    rep3: number;
    /** Output index at the last dictionary reset; matches may not reach before it. */
    dictStart: number;
    literal: Uint16Array<ArrayBuffer>;
    readonly isMatch: Uint16Array<ArrayBuffer>;
    readonly isRep: Uint16Array<ArrayBuffer>;
    readonly isRepG0: Uint16Array<ArrayBuffer>;
    readonly isRepG1: Uint16Array<ArrayBuffer>;
    readonly isRepG2: Uint16Array<ArrayBuffer>;
    readonly isRep0Long: Uint16Array<ArrayBuffer>;
    readonly posSlot: Uint16Array<ArrayBuffer>;
    readonly posSpecial: Uint16Array<ArrayBuffer>;
    readonly align: Uint16Array<ArrayBuffer>;
    readonly len: LenDecoder;
    readonly repLen: LenDecoder;
    readonly rc: RangeDecoder;
    setProps(byte: number, lzma2: boolean): void;
    resetState(): void;
    /**
     * Decode until `out.pos === stop` or, if `allowEndMarker`, an end-of-payload
     * marker. Returns true when the end marker was seen.
     */
    run(out: Out, stop: number, allowEndMarker: boolean): boolean;
    private distance;
}
/** Decode an LZMA2 stream starting at `ip`. Returns the input offset just past its end marker. */
export declare function decodeLzma2(src: Uint8Array, ip: number, out: Out): number;
/** Plausible LZMA_Alone header: valid properties byte and a sane dictionary size. */
export declare function looksLikeLzmaAlone(buf: Uint8Array): boolean;
export declare function lzmaAloneDecompress(src: Uint8Array, maxOutput: number): Buffer;
export declare const XZ_MAGIC: readonly [253, 55, 122, 88, 90, 0];
/** Decompress a complete .xz file (one or more concatenated streams, with stream padding). */
export declare function xzDecompress(src: Uint8Array, maxOutput: number): Buffer;
export {};
