import { DecodeError, LimitError, Out } from "./xz.js";

/**
 * Zero-dependency LZ4 frame decoder (LZ4 Frame Format 1.6.x, lz4.org).
 *
 * Supports independent and linked blocks, uncompressed blocks, content size,
 * block and content checksums (xxHash32, verified), skippable frames,
 * concatenated frames and the legacy frame format. Dictionary IDs are
 * rejected: the dictionary is not shipped with the data, so the content
 * cannot be reconstructed. That makes it a coverage gap, never a guess.
 */

export const LZ4_MAGIC = 0x184d2204;
const LZ4_LEGACY_MAGIC = 0x184c2102;

// ------------------------------------------------------------------ xxHash32

const P1 = 2654435761;
const P2 = 2246822519;
const P3 = 3266489917;
const P4 = 668265263;
const P5 = 374761393;

const rotl = (x: number, r: number) => ((x << r) | (x >>> (32 - r))) >>> 0;
const mul = (a: number, b: number) => Math.imul(a, b) >>> 0;
const u32 = (b: Uint8Array, i: number) => (b[i]! | (b[i + 1]! << 8) | (b[i + 2]! << 16) | (b[i + 3]! << 24)) >>> 0;

export function xxh32(b: Uint8Array, start = 0, end = b.length, seed = 0): number {
  let p = start;
  const len = end - start;
  let h: number;
  if (len >= 16) {
    let v1 = (seed + P1 + P2) >>> 0;
    let v2 = (seed + P2) >>> 0;
    let v3 = seed >>> 0;
    let v4 = (seed - P1) >>> 0;
    const limit = end - 16;
    while (p <= limit) {
      v1 = mul(rotl((v1 + mul(u32(b, p), P2)) >>> 0, 13), P1);
      v2 = mul(rotl((v2 + mul(u32(b, p + 4), P2)) >>> 0, 13), P1);
      v3 = mul(rotl((v3 + mul(u32(b, p + 8), P2)) >>> 0, 13), P1);
      v4 = mul(rotl((v4 + mul(u32(b, p + 12), P2)) >>> 0, 13), P1);
      p += 16;
    }
    h = (rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)) >>> 0;
  } else {
    h = (seed + P5) >>> 0;
  }
  h = (h + len) >>> 0;
  while (p + 4 <= end) {
    h = mul(rotl((h + mul(u32(b, p), P3)) >>> 0, 17), P4);
    p += 4;
  }
  while (p < end) {
    h = mul(rotl((h + mul(b[p]!, P5)) >>> 0, 11), P1);
    p++;
  }
  h = mul(h ^ (h >>> 15), P2);
  h = mul(h ^ (h >>> 13), P3);
  return (h ^ (h >>> 16)) >>> 0;
}

// ------------------------------------------------------------------ block

/** Decode one LZ4 block (src[ip..end)) into out. Matches may reach into earlier output (linked blocks). */
function decodeBlock(src: Uint8Array, ip: number, end: number, out: Out, windowStart: number): void {
  while (ip < end) {
    const token = src[ip++]!;
    let lit = token >>> 4;
    if (lit === 15) {
      let b: number;
      do {
        if (ip >= end) throw new DecodeError("lz4 literal length truncated");
        b = src[ip++]!;
        lit += b;
      } while (b === 255);
    }
    if (ip + lit > end) throw new DecodeError("lz4 literals truncated");
    out.ensure(lit);
    out.buf.set(src.subarray(ip, ip + lit), out.pos);
    out.pos += lit;
    ip += lit;
    if (ip >= end) return; // the last sequence has literals only
    if (ip + 2 > end) throw new DecodeError("lz4 match offset truncated");
    const offset = src[ip]! | (src[ip + 1]! << 8);
    ip += 2;
    if (offset === 0 || out.pos - offset < windowStart) throw new DecodeError("lz4 match offset out of range");
    let len = token & 15;
    if (len === 15) {
      let b: number;
      do {
        if (ip >= end) throw new DecodeError("lz4 match length truncated");
        b = src[ip++]!;
        len += b;
      } while (b === 255);
    }
    len += 4;
    out.ensure(len);
    const buf = out.buf;
    let s = out.pos - offset;
    for (let k = 0; k < len; k++) buf[out.pos++] = buf[s++]!;
  }
}

// ------------------------------------------------------------------ frames

export function looksLikeLz4(buf: Uint8Array): boolean {
  return buf.length >= 7 && (u32(buf, 0) === LZ4_MAGIC || u32(buf, 0) === LZ4_LEGACY_MAGIC);
}

export function lz4Decompress(src: Uint8Array, maxOutput: number): Buffer {
  const out = new Out(src.length * 3, maxOutput);
  let ip = 0;
  let frames = 0;
  while (ip < src.length) {
    if (ip + 4 > src.length) throw new DecodeError("trailing bytes after lz4 frame");
    const magic = u32(src, ip);
    if (magic >>> 4 === 0x184d2a5) {
      // skippable frame
      if (ip + 8 > src.length) throw new DecodeError("lz4 skippable frame truncated");
      ip += 8 + u32(src, ip + 4);
      continue;
    }
    if (magic === LZ4_LEGACY_MAGIC) {
      ip += 4;
      while (ip + 4 <= src.length) {
        const size = u32(src, ip);
        if (size === LZ4_MAGIC || size === LZ4_LEGACY_MAGIC || size >>> 4 === 0x184d2a5) break; // next frame
        ip += 4;
        if (ip + size > src.length) throw new DecodeError("lz4 legacy block truncated");
        decodeBlock(src, ip, ip + size, out, out.pos);
        ip += size;
      }
      frames++;
      continue;
    }
    if (magic !== LZ4_MAGIC) throw new DecodeError(frames === 0 ? "not an lz4 frame" : "trailing bytes after lz4 frame");
    const descStart = ip + 4;
    if (descStart + 3 > src.length) throw new DecodeError("lz4 frame descriptor truncated");
    const flg = src[descStart]!;
    const bd = src[descStart + 1]!;
    if (flg >>> 6 !== 1) throw new DecodeError("unsupported lz4 frame version");
    if (flg & 0x02 || bd & 0x8f) throw new DecodeError("reserved lz4 frame bits set");
    const independent = (flg & 0x20) !== 0;
    const blockChecksum = (flg & 0x10) !== 0;
    const hasSize = (flg & 0x08) !== 0;
    const contentChecksum = (flg & 0x04) !== 0;
    if (flg & 0x01) throw new DecodeError("lz4 frame needs an external dictionary (not shipped with the data)");
    const maxBlock = [0, 0, 0, 0, 64 << 10, 256 << 10, 1 << 20, 4 << 20][(bd >>> 4) & 7]!;
    if (maxBlock === 0) throw new DecodeError("invalid lz4 block maximum size");
    let p = descStart + 2;
    let contentSize = -1;
    if (hasSize) {
      if (p + 8 > src.length) throw new DecodeError("lz4 frame descriptor truncated");
      contentSize = u32(src, p) + u32(src, p + 4) * 2 ** 32;
      if (contentSize > maxOutput) throw new LimitError(`declared size ${contentSize} exceeds limit of ${maxOutput} bytes`);
      p += 8;
    }
    if (((xxh32(src, descStart, p) >>> 8) & 0xff) !== src[p]) throw new DecodeError("lz4 frame descriptor checksum mismatch");
    ip = p + 1;
    const frameStart = out.pos;
    for (;;) {
      if (ip + 4 > src.length) throw new DecodeError("lz4 frame truncated");
      const word = u32(src, ip);
      ip += 4;
      if (word === 0) break; // end mark
      const raw = (word & 0x80000000) !== 0;
      const size = word & 0x7fffffff;
      if (size > maxBlock) throw new DecodeError("lz4 block exceeds the declared maximum size");
      if (ip + size + (blockChecksum ? 4 : 0) > src.length) throw new DecodeError("lz4 block truncated");
      if (blockChecksum && xxh32(src, ip, ip + size) !== u32(src, ip + size)) throw new DecodeError("lz4 block checksum mismatch");
      const blockStart = out.pos;
      if (raw) {
        out.ensure(size);
        out.buf.set(src.subarray(ip, ip + size), out.pos);
        out.pos += size;
      } else {
        decodeBlock(src, ip, ip + size, out, independent ? blockStart : frameStart);
      }
      if (out.pos - blockStart > maxBlock) throw new DecodeError("lz4 block decodes past the declared maximum size");
      ip += size + (blockChecksum ? 4 : 0);
    }
    if (contentSize >= 0 && out.pos - frameStart !== contentSize) throw new DecodeError("lz4 content size mismatch");
    if (contentChecksum) {
      if (ip + 4 > src.length) throw new DecodeError("lz4 content checksum truncated");
      if (xxh32(out.buf, frameStart, out.pos) !== u32(src, ip)) throw new DecodeError("lz4 content checksum mismatch");
      ip += 4;
    }
    frames++;
  }
  return out.result();
}
