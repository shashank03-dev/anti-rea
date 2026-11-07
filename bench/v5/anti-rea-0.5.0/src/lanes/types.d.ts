import type { ArtifactRef } from "../model/evidence.js";
import type { Limits } from "./containers.js";
/**
 * Where an item's bytes live. On-disk files are re-read on demand so a large
 * release is never held in memory all at once; container entries are views of
 * their (already loaded) container.
 */
export type ItemSource = {
    readonly kind: "disk";
    readonly abs: string;
} | {
    readonly kind: "mem";
    readonly buf: Buffer;
};
/** One shipped artifact: a file on disk or an entry inside a supported container. */
export interface InventoryItem {
    readonly ref: ArtifactRef;
    /** null for expanded containers (their entries are separate items) and for unsupported content. */
    readonly source: ItemSource | null;
    readonly kind: "file" | "container" | "entry";
    /** Virtual path of the enclosing container, if any. */
    readonly parent?: string;
    readonly depth: number;
    readonly supported: boolean;
    readonly unsupportedReason?: string;
    /** Coverage caveat that does not make the item unsupported (e.g. native binary scanned raw). */
    readonly note?: string;
}
export interface Inventory {
    readonly releaseId: string;
    readonly items: readonly InventoryItem[];
    readonly notes: readonly string[];
    readonly limits: Limits;
}
export declare function readItem(item: InventoryItem): Buffer | null;
/** Items whose bytes the content lanes can actually inspect. */
export declare function scannable(inv: Inventory): InventoryItem[];
export declare function unsupported(inv: Inventory): InventoryItem[];
/**
 * Content-lane coverage. Successfully expanded containers are excluded from the
 * denominator because their entries are what get inspected; so
 * considered = supported + unsupported.
 */
export declare function contentCoverage(inv: Inventory, notes?: string[]): {
    notes?: string[] | undefined;
    artifactsConsidered: number;
    artifactsSupported: number;
    artifactsUnsupported: number;
};
/** 1-based line and column of a character offset in a string. */
export declare function lineCol(text: string, index: number): {
    line: number;
    column: number;
};
/** 1-based line of a byte offset (counts 0x0A bytes before it). */
export declare function lineAt(buf: Buffer, offset: number): number;
/** NUL bytes in the first 64 KiB indicate binary content (UTF-16 strings, native code, images). */
export declare function isBinary(buf: Buffer): boolean;
export interface TextView {
    readonly text: string;
    /** Byte offset of text[0]. */
    readonly base: number;
    /** Bytes per character in this view. */
    readonly stride: 1 | 2;
    readonly encoding: "latin1" | "utf16le";
    /** Matches starting at or beyond this byte offset belong to the next view (overlap dedupe). */
    readonly ownEnd: number;
}
/**
 * Chunked text views of a buffer: Latin-1 (byte-exact, covers ASCII/UTF-8
 * secrets) and, for binaries, UTF-16LE at both byte alignments (Windows / .NET
 * string tables). Chunks overlap so bounded matches are never split.
 */
export declare function textViews(buf: Buffer, limits: Pick<Limits, "scanChunkBytes" | "scanOverlapBytes">): Generator<TextView>;
