import { readFileSync } from "node:fs";
import type { ArtifactRef } from "../model/evidence.js";
import type { Limits } from "./containers.js";

/**
 * Where an item's bytes live. On-disk files are re-read on demand so a large
 * release is never held in memory all at once; container entries are views of
 * their (already loaded) container.
 */
export type ItemSource = { readonly kind: "disk"; readonly abs: string } | { readonly kind: "mem"; readonly buf: Buffer };

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
  /**
   * v0.6: the raw bytes of an EXPANDED container (whose `source` is null because its entries are the
   * scanned items). Used by the platform lane for ASAR-integrity and bundle-seal checks; never scanned.
   */
  readonly raw?: ItemSource;
}

export interface Inventory {
  readonly releaseId: string;
  readonly items: readonly InventoryItem[];
  readonly notes: readonly string[];
  readonly limits: Limits;
}

/** Raw bytes of any item: a scannable file/entry, or an expanded container. */
export function readRaw(item: InventoryItem): Buffer | null {
  const src = item.source ?? item.raw;
  if (!src) return null;
  return src.kind === "mem" ? src.buf : readFileSync(src.abs);
}

export function readItem(item: InventoryItem): Buffer | null {
  if (!item.source) return null;
  return item.source.kind === "mem" ? item.source.buf : readFileSync(item.source.abs);
}

/** Items whose bytes the content lanes can actually inspect. */
export function scannable(inv: Inventory): InventoryItem[] {
  return inv.items.filter((i) => i.supported && i.source !== null);
}

export function unsupported(inv: Inventory): InventoryItem[] {
  return inv.items.filter((i) => !i.supported);
}

/**
 * Content-lane coverage. Successfully expanded containers are excluded from the
 * denominator because their entries are what get inspected; so
 * considered = supported + unsupported.
 */
export function contentCoverage(inv: Inventory, notes?: string[]) {
  const sup = scannable(inv).length;
  const unsup = unsupported(inv).length;
  const caveats = inv.items.filter((i) => i.note).map((i) => `${i.ref.path}: ${i.note}`);
  const all = [...(notes ?? []), ...caveats];
  return {
    artifactsConsidered: sup + unsup,
    artifactsSupported: sup,
    artifactsUnsupported: unsup,
    ...(all.length > 0 ? { notes: all } : {}),
  };
}

/** 1-based line and column of a character offset in a string. */
export function lineCol(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let last = -1;
  for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) {
    line++;
    last = i;
  }
  return { line, column: index - last };
}

/** 1-based line of a byte offset (counts 0x0A bytes before it). */
export function lineAt(buf: Buffer, offset: number): number {
  let line = 1;
  for (let i = buf.indexOf(10, 0); i !== -1 && i < offset; i = buf.indexOf(10, i + 1)) line++;
  return line;
}

/** NUL bytes in the first 64 KiB indicate binary content (UTF-16 strings, native code, images). */
export function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 64 * 1024);
  let zeros = 0;
  for (let i = 0; i < n; i++) if (buf[i] === 0) zeros++;
  return zeros >= Math.max(4, n * 0.002);
}

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
export function* textViews(buf: Buffer, limits: Pick<Limits, "scanChunkBytes" | "scanOverlapBytes">): Generator<TextView> {
  const chunk = Math.max(2, limits.scanChunkBytes - (limits.scanChunkBytes % 2));
  const overlap = Math.max(0, limits.scanOverlapBytes);
  for (let start = 0; ; start += chunk) {
    const end = Math.min(buf.length, start + chunk + overlap);
    const last = end >= buf.length;
    yield { text: buf.toString("latin1", start, end), base: start, stride: 1, encoding: "latin1", ownEnd: last ? Infinity : start + chunk };
    if (last) break;
  }
  if (!isBinary(buf)) return;
  for (const align of [0, 1]) {
    for (let start = align; start + 1 < buf.length; start += chunk) {
      let end = Math.min(buf.length, start + chunk + overlap);
      if ((end - start) % 2 === 1) end--;
      const last = end + 1 >= buf.length;
      yield { text: buf.toString("utf16le", start, end), base: start, stride: 2, encoding: "utf16le", ownEnd: last ? Infinity : start + chunk };
      if (last) break;
    }
  }
}
