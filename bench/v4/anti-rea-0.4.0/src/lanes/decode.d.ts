/**
 * Decoding of text-level encodings that hide credentials from pattern
 * matching: base64 (standard and URL-safe), hex, and percent-encoding.
 *
 * A run is decoded only if the result is valid UTF-8 that is mostly
 * printable. Random bytes, images and hashes decode to binary noise and are
 * dropped, so this adds candidates without adding noise. Decoding recurses
 * (base64 of percent-encoded text, and so on) up to `maxDepth` layers.
 */
export type Encoding = "base64" | "hex" | "percent";
export interface DecodedSpan {
    /** Decoded text. */
    readonly text: string;
    /** Character index of the encoded run in the text it was found in (outermost layer). */
    readonly index: number;
    /** Outermost encoding first. */
    readonly chain: readonly Encoding[];
}
export interface DecodeOptions {
    readonly maxDepth: number;
    /** Encoded runs longer than this are skipped (large data URIs are images, not secrets). */
    readonly maxRunChars: number;
    /** Stop after this many decoded spans per text (bounds work on pathological input). */
    readonly maxSpans: number;
}
export declare const DEFAULT_DECODE: DecodeOptions;
export declare function decodeLayers(text: string, opts?: DecodeOptions): DecodedSpan[];
