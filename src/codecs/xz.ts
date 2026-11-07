import { createHash } from "node:crypto";
import { crc32, crc64 } from "./crc.js";

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

export class DecodeError extends Error {}
export class LimitError extends Error {}

// ------------------------------------------------------------------ growable output

export class Out {
  buf: Uint8Array;
  pos = 0;
  constructor(
    initial: number,
    readonly limit: number,
  ) {
    this.buf = new Uint8Array(Math.max(4096, Math.min(initial, limit)));
  }
  ensure(n: number): void {
    const need = this.pos + n;
    if (need <= this.buf.length) return;
    if (need > this.limit) throw new LimitError(`decompressed size exceeds limit of ${this.limit} bytes`);
    let cap = this.buf.length * 2;
    while (cap < need) cap *= 2;
    const next = new Uint8Array(Math.min(cap, this.limit));
    next.set(this.buf.subarray(0, this.pos));
    this.buf = next;
  }
  result(): Buffer {
    return Buffer.from(this.buf.buffer, this.buf.byteOffset, this.pos);
  }
}

// ------------------------------------------------------------------ range decoder

class RangeDecoder {
  range = 0;
  code = 0;
  ip = 0;
  end = 0;
  src: Uint8Array = new Uint8Array(0);

  init(src: Uint8Array, ip: number, end: number): void {
    if (end - ip < 5 || src[ip] !== 0) throw new DecodeError("invalid range-coder start");
    this.src = src;
    this.end = end;
    this.range = 0xffffffff;
    this.code = 0;
    this.ip = ip + 1;
    for (let i = 0; i < 4; i++) this.code = ((this.code << 8) | src[this.ip++]!) >>> 0;
    if (this.code === this.range) throw new DecodeError("invalid range-coder start");
  }

  normalize(): void {
    if (this.range < 0x1000000) {
      if (this.ip >= this.end) throw new DecodeError("compressed data truncated");
      this.range = (this.range << 8) >>> 0;
      this.code = ((this.code << 8) | this.src[this.ip++]!) >>> 0;
    }
  }

  bit(p: Uint16Array, i: number): number {
    this.normalize();
    const prob = p[i]!;
    const bound = (this.range >>> 11) * prob;
    if (this.code < bound) {
      this.range = bound;
      p[i] = prob + ((2048 - prob) >>> 5);
      return 0;
    }
    this.range -= bound;
    this.code -= bound;
    p[i] = prob - (prob >>> 5);
    return 1;
  }

  tree(p: Uint16Array, base: number, bits: number): number {
    let m = 1;
    for (let i = 0; i < bits; i++) m = (m << 1) | this.bit(p, base + m);
    return m - (1 << bits);
  }

  reverse(p: Uint16Array, base: number, bits: number): number {
    let m = 1;
    let sym = 0;
    for (let i = 0; i < bits; i++) {
      const b = this.bit(p, base + m);
      m = (m << 1) | b;
      sym |= b << i;
    }
    return sym;
  }

  direct(bits: number): number {
    let res = 0;
    for (let i = 0; i < bits; i++) {
      this.normalize();
      this.range = this.range >>> 1;
      let b = 0;
      if (this.code >= this.range) {
        this.code -= this.range;
        b = 1;
      }
      res = res * 2 + b;
    }
    return res;
  }
}

// ------------------------------------------------------------------ LZMA core

const STATES = 12;
const POS_STATES_MAX = 16;
const END_POS_MODEL_INDEX = 14;
const FULL_DISTANCES = 128;
const MATCH_LEN_MIN = 2;

class LenDecoder {
  readonly choice = new Uint16Array(2);
  readonly low = new Uint16Array(POS_STATES_MAX << 3);
  readonly mid = new Uint16Array(POS_STATES_MAX << 3);
  readonly high = new Uint16Array(256);
  reset(): void {
    this.choice.fill(1024);
    this.low.fill(1024);
    this.mid.fill(1024);
    this.high.fill(1024);
  }
  decode(rc: RangeDecoder, posState: number): number {
    if (rc.bit(this.choice, 0) === 0) return rc.tree(this.low, posState << 3, 3);
    if (rc.bit(this.choice, 1) === 0) return 8 + rc.tree(this.mid, posState << 3, 3);
    return 16 + rc.tree(this.high, 0, 8);
  }
}

export class LzmaDecoder {
  lc = 0;
  lp = 0;
  pb = 0;
  state = 0;
  rep0 = 0;
  rep1 = 0;
  rep2 = 0;
  rep3 = 0;
  /** Output index at the last dictionary reset; matches may not reach before it. */
  dictStart = 0;
  literal = new Uint16Array(0x300);
  readonly isMatch = new Uint16Array(STATES << 4);
  readonly isRep = new Uint16Array(STATES);
  readonly isRepG0 = new Uint16Array(STATES);
  readonly isRepG1 = new Uint16Array(STATES);
  readonly isRepG2 = new Uint16Array(STATES);
  readonly isRep0Long = new Uint16Array(STATES << 4);
  readonly posSlot = new Uint16Array(4 << 6);
  readonly posSpecial = new Uint16Array(FULL_DISTANCES - END_POS_MODEL_INDEX);
  readonly align = new Uint16Array(16);
  readonly len = new LenDecoder();
  readonly repLen = new LenDecoder();
  readonly rc = new RangeDecoder();

  setProps(byte: number, lzma2: boolean): void {
    if (byte >= 9 * 5 * 5) throw new DecodeError("invalid LZMA properties");
    this.lc = byte % 9;
    const rest = Math.floor(byte / 9);
    this.lp = rest % 5;
    this.pb = Math.floor(rest / 5);
    if (lzma2 && this.lc + this.lp > 4) throw new DecodeError("invalid LZMA2 properties (lc + lp > 4)");
    const need = 0x300 << (this.lc + this.lp);
    if (this.literal.length !== need) this.literal = new Uint16Array(need);
  }

  resetState(): void {
    this.state = 0;
    this.rep0 = this.rep1 = this.rep2 = this.rep3 = 0;
    this.literal.fill(1024);
    this.isMatch.fill(1024);
    this.isRep.fill(1024);
    this.isRepG0.fill(1024);
    this.isRepG1.fill(1024);
    this.isRepG2.fill(1024);
    this.isRep0Long.fill(1024);
    this.posSlot.fill(1024);
    this.posSpecial.fill(1024);
    this.align.fill(1024);
    this.len.reset();
    this.repLen.reset();
  }

  /**
   * Decode until `out.pos === stop` or, if `allowEndMarker`, an end-of-payload
   * marker. Returns true when the end marker was seen.
   */
  run(out: Out, stop: number, allowEndMarker: boolean): boolean {
    const rc = this.rc;
    const pbMask = (1 << this.pb) - 1;
    const lpMask = (1 << this.lp) - 1;
    const lc = this.lc;
    while (out.pos < stop) {
      const rel = out.pos - this.dictStart;
      const posState = rel & pbMask;
      const state = this.state;
      if (rc.bit(this.isMatch, (state << 4) + posState) === 0) {
        // literal
        const prev = rel > 0 ? out.buf[out.pos - 1]! : 0;
        const base = 0x300 * (((rel & lpMask) << lc) + (prev >>> (8 - lc)));
        let sym = 1;
        if (state >= 7) {
          if (this.rep0 >= rel) throw new DecodeError("match distance exceeds decoded data");
          let matchByte = out.buf[out.pos - this.rep0 - 1]! << 1;
          let offset = 0x100;
          while (sym < 0x100) {
            const matchBit = matchByte & offset;
            matchByte <<= 1;
            if (rc.bit(this.literal, base + offset + matchBit + sym) === 1) {
              sym = (sym << 1) | 1;
              offset &= matchBit;
            } else {
              sym <<= 1;
              offset &= ~matchBit;
            }
          }
        } else {
          while (sym < 0x100) sym = (sym << 1) | rc.bit(this.literal, base + sym);
        }
        out.ensure(1);
        out.buf[out.pos++] = sym & 0xff;
        this.state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
        continue;
      }

      let len: number;
      if (rc.bit(this.isRep, state) === 0) {
        // simple match
        this.rep3 = this.rep2;
        this.rep2 = this.rep1;
        this.rep1 = this.rep0;
        len = this.len.decode(rc, posState);
        this.state = state < 7 ? 7 : 10;
        const dist = this.distance(len);
        if (dist === 0xffffffff) {
          if (!allowEndMarker) throw new DecodeError("unexpected end-of-payload marker");
          return true;
        }
        this.rep0 = dist;
      } else {
        if (rc.bit(this.isRepG0, state) === 0) {
          if (rc.bit(this.isRep0Long, (state << 4) + posState) === 0) {
            // short rep: one byte at distance rep0
            if (this.rep0 >= rel) throw new DecodeError("match distance exceeds decoded data");
            this.state = state < 7 ? 9 : 11;
            out.ensure(1);
            out.buf[out.pos] = out.buf[out.pos - this.rep0 - 1]!;
            out.pos++;
            continue;
          }
        } else {
          let dist: number;
          if (rc.bit(this.isRepG1, state) === 0) {
            dist = this.rep1;
          } else {
            if (rc.bit(this.isRepG2, state) === 0) {
              dist = this.rep2;
            } else {
              dist = this.rep3;
              this.rep3 = this.rep2;
            }
            this.rep2 = this.rep1;
          }
          this.rep1 = this.rep0;
          this.rep0 = dist;
        }
        len = this.repLen.decode(rc, posState);
        this.state = state < 7 ? 8 : 11;
      }

      const n = len + MATCH_LEN_MIN;
      if (this.rep0 >= out.pos - this.dictStart) throw new DecodeError("match distance exceeds decoded data");
      if (out.pos + n > stop) throw new DecodeError("match extends past the end of the chunk");
      out.ensure(n);
      const buf = out.buf;
      let src = out.pos - this.rep0 - 1;
      for (let k = 0; k < n; k++) buf[out.pos++] = buf[src++]!;
    }
    return false;
  }

  private distance(len: number): number {
    const rc = this.rc;
    const lenState = len < 4 ? len : 3;
    const slot = rc.tree(this.posSlot, lenState << 6, 6);
    if (slot < 4) return slot;
    const direct = (slot >>> 1) - 1;
    let dist = (2 | (slot & 1)) * 2 ** direct;
    if (slot < END_POS_MODEL_INDEX) {
      dist += rc.reverse(this.posSpecial, dist - slot - 1, direct);
    } else {
      dist += rc.direct(direct - 4) * 16;
      dist += rc.reverse(this.align, 0, 4);
    }
    return dist;
  }
}

// ------------------------------------------------------------------ LZMA2

/** Decode an LZMA2 stream starting at `ip`. Returns the input offset just past its end marker. */
export function decodeLzma2(src: Uint8Array, ip: number, out: Out): number {
  const d = new LzmaDecoder();
  d.dictStart = out.pos;
  let needDictReset = true;
  let needProps = true;
  for (;;) {
    if (ip >= src.length) throw new DecodeError("LZMA2 data truncated");
    const control = src[ip++]!;
    if (control === 0x00) return ip;

    if (control >= 0xe0 || control === 0x01) {
      needProps = true;
      needDictReset = false;
      d.dictStart = out.pos;
    } else if (needDictReset) {
      throw new DecodeError("LZMA2 stream does not begin with a dictionary reset");
    }

    if (control < 0x80) {
      if (control > 0x02) throw new DecodeError(`invalid LZMA2 control byte 0x${control.toString(16)}`);
      if (ip + 2 > src.length) throw new DecodeError("LZMA2 data truncated");
      const size = ((src[ip]! << 8) | src[ip + 1]!) + 1;
      ip += 2;
      if (ip + size > src.length) throw new DecodeError("LZMA2 data truncated");
      out.ensure(size);
      out.buf.set(src.subarray(ip, ip + size), out.pos);
      out.pos += size;
      ip += size;
      continue;
    }

    if (ip + 4 > src.length) throw new DecodeError("LZMA2 data truncated");
    const unpacked = (control & 0x1f) * 65536 + ((src[ip]! << 8) | src[ip + 1]!) + 1;
    const packed = ((src[ip + 2]! << 8) | src[ip + 3]!) + 1;
    ip += 4;
    if (control >= 0xc0) {
      if (ip >= src.length) throw new DecodeError("LZMA2 data truncated");
      d.setProps(src[ip++]!, true);
      needProps = false;
      d.resetState();
    } else if (needProps) {
      throw new DecodeError("LZMA2 chunk lacks required properties");
    } else if (control >= 0xa0) {
      d.resetState();
    }
    if (ip + packed > src.length) throw new DecodeError("LZMA2 data truncated");
    d.rc.init(src, ip, ip + packed);
    d.run(out, out.pos + unpacked, false);
    d.rc.normalize();
    if (d.rc.ip !== ip + packed || d.rc.code !== 0) throw new DecodeError("LZMA2 chunk size mismatch");
    ip += packed;
  }
}

// ------------------------------------------------------------------ .lzma (LZMA_Alone)

/** Plausible LZMA_Alone header: valid properties byte and a sane dictionary size. */
export function looksLikeLzmaAlone(buf: Uint8Array): boolean {
  if (buf.length < 18 || buf[0]! >= 225) return false;
  const dict = (buf[1]! | (buf[2]! << 8) | (buf[3]! << 16) | (buf[4]! << 24)) >>> 0;
  return dict >= 4096 && dict <= 0x60000000 && buf[13] === 0;
}

export function lzmaAloneDecompress(src: Uint8Array, maxOutput: number): Buffer {
  if (src.length < 13) throw new DecodeError("truncated .lzma header");
  const d = new LzmaDecoder();
  d.setProps(src[0]!, false);
  d.resetState();
  const lo = (src[5]! | (src[6]! << 8) | (src[7]! << 16) | (src[8]! << 24)) >>> 0;
  const hi = (src[9]! | (src[10]! << 8) | (src[11]! << 16) | (src[12]! << 24)) >>> 0;
  const unknown = lo === 0xffffffff && hi === 0xffffffff;
  const size = unknown ? Infinity : hi * 2 ** 32 + lo;
  if (!unknown && size > maxOutput) throw new LimitError(`declared size ${size} exceeds limit of ${maxOutput} bytes`);
  const out = new Out(unknown ? src.length * 4 : size, maxOutput);
  d.rc.init(src, 13, src.length);
  const ended = d.run(out, unknown ? Number.MAX_SAFE_INTEGER : size, true);
  if (unknown && !ended) throw new DecodeError(".lzma stream has no end marker");
  return out.result();
}

// ------------------------------------------------------------------ filters

function deltaDecode(buf: Uint8Array, distance: number): void {
  for (let i = distance; i < buf.length; i++) buf[i] = (buf[i]! + buf[i - distance]!) & 0xff;
}

/** x86 branch/call/jump converter, decoder direction (the BCJ filter in xz). */
function x86Decode(buf: Uint8Array, startOffset: number): void {
  const allowed = [true, true, true, false, true, false, false, false];
  const bitNum = [0, 1, 2, 2, 3, 3, 3, 3];
  const msb = (b: number) => b === 0x00 || b === 0xff;
  if (buf.length <= 4) return;
  const size = buf.length - 4;
  let prevPos = -1;
  let prevMask = 0;
  let i = 0;
  for (; i < size; i++) {
    if ((buf[i]! & 0xfe) !== 0xe8) continue;
    const gap = i - prevPos;
    if (gap > 3) {
      prevMask = 0;
    } else {
      prevMask = (prevMask << (gap - 1)) & 7;
      if (prevMask !== 0) {
        const b = buf[i + 4 - bitNum[prevMask]!]!;
        if (!allowed[prevMask] || msb(b)) {
          prevPos = i;
          prevMask = (prevMask << 1) | 1;
          continue;
        }
      }
    }
    prevPos = i;
    if (msb(buf[i + 4]!)) {
      let src = (buf[i + 1]! | (buf[i + 2]! << 8) | (buf[i + 3]! << 16) | (buf[i + 4]! << 24)) >>> 0;
      let dest: number;
      for (;;) {
        dest = (src - (startOffset + i + 5)) >>> 0;
        if (prevMask === 0) break;
        const j = bitNum[prevMask]! * 8;
        const b = (dest >>> (24 - j)) & 0xff;
        if (!msb(b)) break;
        src = (dest ^ (2 ** (32 - j) - 1)) >>> 0;
      }
      dest &= 0x01ffffff;
      dest = (dest | (0 - (dest & 0x01000000))) >>> 0;
      buf[i + 1] = dest & 0xff;
      buf[i + 2] = (dest >>> 8) & 0xff;
      buf[i + 3] = (dest >>> 16) & 0xff;
      buf[i + 4] = (dest >>> 24) & 0xff;
      i += 4;
    } else {
      prevMask = (prevMask << 1) | 1;
    }
  }
}

// ------------------------------------------------------------------ .xz container

export const XZ_MAGIC = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] as const;

const FILTER_LZMA2 = 0x21;
const FILTER_DELTA = 0x03;
const FILTER_X86 = 0x04;
const FILTER_NAMES: Record<number, string> = { 0x04: "x86 BCJ", 0x05: "PowerPC BCJ", 0x06: "IA-64 BCJ", 0x07: "ARM BCJ", 0x08: "ARM-Thumb BCJ", 0x09: "SPARC BCJ", 0x0a: "ARM64 BCJ", 0x0b: "RISC-V BCJ" };

function le32(b: Uint8Array, at: number): number {
  return (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16) | (b[at + 3]! << 24)) >>> 0;
}

function checkSize(type: number): number {
  return type === 0 ? 0 : 4 << Math.floor((type - 1) / 3);
}

class Reader {
  constructor(
    readonly b: Uint8Array,
    public p: number,
    readonly end: number,
  ) {}
  byte(): number {
    if (this.p >= this.end) throw new DecodeError("xz structure truncated");
    return this.b[this.p++]!;
  }
  varint(): number {
    let v = 0;
    for (let i = 0; i < 9; i++) {
      const x = this.byte();
      v += (x & 0x7f) * 2 ** (7 * i);
      if ((x & 0x80) === 0) {
        if (x === 0 && i > 0) throw new DecodeError("non-minimal xz integer encoding");
        return v;
      }
    }
    throw new DecodeError("xz integer too long");
  }
}

interface Filter {
  readonly id: number;
  readonly props: Uint8Array;
}

/** Decompress a complete .xz file (one or more concatenated streams, with stream padding). */
export function xzDecompress(src: Uint8Array, maxOutput: number): Buffer {
  const parts: Buffer[] = [];
  let total = 0;
  let ip = 0;
  let streams = 0;
  while (ip < src.length) {
    if (streams > 0) {
      // Stream padding: null bytes in multiples of four.
      const padStart = ip;
      while (ip < src.length && src[ip] === 0) ip++;
      if ((ip - padStart) % 4 !== 0) throw new DecodeError("invalid xz stream padding");
      if (ip >= src.length) break;
    }
    for (let i = 0; i < 6; i++) if (src[ip + i] !== XZ_MAGIC[i]) throw new DecodeError(streams === 0 ? "not an xz stream" : "trailing bytes after xz stream");
    if (ip + 12 > src.length) throw new DecodeError("xz stream header truncated");
    const flags0 = src[ip + 6]!;
    const flags1 = src[ip + 7]!;
    if (flags0 !== 0 || (flags1 & 0xf0) !== 0) throw new DecodeError("unsupported xz stream flags");
    if (crc32(src, ip + 6, ip + 8) !== le32(src, ip + 8)) throw new DecodeError("xz stream header CRC mismatch");
    const check = flags1 & 0x0f;
    const csize = checkSize(check);
    ip += 12;

    const records: { unpadded: number; uncompressed: number }[] = [];
    for (;;) {
      if (ip >= src.length) throw new DecodeError("xz stream truncated");
      const sizeByte = src[ip]!;
      if (sizeByte === 0) break; // index indicator
      const blockStart = ip;
      const hsize = (sizeByte + 1) * 4;
      if (ip + hsize > src.length) throw new DecodeError("xz block header truncated");
      if (crc32(src, ip, ip + hsize - 4) !== le32(src, ip + hsize - 4)) throw new DecodeError("xz block header CRC mismatch");
      const r = new Reader(src, ip + 1, ip + hsize - 4);
      const bflags = r.byte();
      if (bflags & 0x3c) throw new DecodeError("unsupported xz block flags");
      const nFilters = (bflags & 0x03) + 1;
      const compSize = bflags & 0x40 ? r.varint() : undefined;
      const uncompSize = bflags & 0x80 ? r.varint() : undefined;
      const filters: Filter[] = [];
      for (let f = 0; f < nFilters; f++) {
        const id = r.varint();
        const psize = r.varint();
        if (r.p + psize > r.end) throw new DecodeError("xz filter properties truncated");
        filters.push({ id, props: src.subarray(r.p, r.p + psize) });
        r.p += psize;
      }
      for (let k = r.p; k < ip + hsize - 4; k++) if (src[k] !== 0) throw new DecodeError("xz block header padding is not zero");

      const last = filters[filters.length - 1]!;
      if (last.id !== FILTER_LZMA2) throw new DecodeError(`unsupported xz filter chain (last filter 0x${last.id.toString(16)})`);
      for (const f of filters.slice(0, -1)) {
        if (f.id === FILTER_LZMA2) throw new DecodeError("LZMA2 may only be the last xz filter");
        if (f.id !== FILTER_DELTA && f.id !== FILTER_X86)
          throw new DecodeError(`unsupported xz filter: ${FILTER_NAMES[f.id] ?? `0x${f.id.toString(16)}`}`);
      }
      if (uncompSize !== undefined && total + uncompSize > maxOutput) throw new LimitError(`decompressed size exceeds limit of ${maxOutput} bytes`);

      const dataStart = ip + hsize;
      const out = new Out(uncompSize ?? (src.length - dataStart) * 4, maxOutput - total);
      const dataEnd = decodeLzma2(src, dataStart, out);
      if (compSize !== undefined && dataEnd - dataStart !== compSize) throw new DecodeError("xz block compressed size mismatch");
      if (uncompSize !== undefined && out.pos !== uncompSize) throw new DecodeError("xz block uncompressed size mismatch");
      const data = out.buf.subarray(0, out.pos);
      for (let f = filters.length - 2; f >= 0; f--) {
        const flt = filters[f]!;
        if (flt.id === FILTER_DELTA) {
          if (flt.props.length !== 1) throw new DecodeError("invalid delta filter properties");
          deltaDecode(data, flt.props[0]! + 1);
        } else {
          if (flt.props.length !== 0 && flt.props.length !== 4) throw new DecodeError("invalid BCJ filter properties");
          x86Decode(data, flt.props.length === 4 ? le32(flt.props, 0) : 0);
        }
      }

      ip = dataEnd;
      while ((ip - blockStart) % 4 !== 0) {
        if (src[ip] !== 0) throw new DecodeError("xz block padding is not zero");
        ip++;
      }
      if (ip + csize > src.length) throw new DecodeError("xz block check truncated");
      const stored = src.subarray(ip, ip + csize);
      if (check === 0x01) {
        if (crc32(data) !== le32(stored, 0)) throw new DecodeError("xz block CRC32 mismatch");
      } else if (check === 0x04) {
        if (!crc64(data).equals(stored)) throw new DecodeError("xz block CRC64 mismatch");
      } else if (check === 0x0a) {
        if (!createHash("sha256").update(data).digest().equals(stored)) throw new DecodeError("xz block SHA-256 mismatch");
      } else if (check !== 0x00) {
        // Reserved check IDs: the data decoded and every structural check passed, but integrity is unverified.
        throw new DecodeError(`unsupported xz check type ${check}`);
      }
      ip += csize;
      records.push({ unpadded: hsize + (dataEnd - dataStart) + csize, uncompressed: out.pos });
      total += out.pos;
      parts.push(out.result());
    }

    // Index
    const indexStart = ip;
    const r = new Reader(src, ip + 1, src.length);
    const count = r.varint();
    if (count !== records.length) throw new DecodeError("xz index record count mismatch");
    for (const rec of records) {
      if (r.varint() !== rec.unpadded || r.varint() !== rec.uncompressed) throw new DecodeError("xz index does not match the blocks");
    }
    ip = r.p;
    while ((ip - indexStart) % 4 !== 0) {
      if (src[ip] !== 0) throw new DecodeError("xz index padding is not zero");
      ip++;
    }
    if (ip + 4 > src.length) throw new DecodeError("xz index truncated");
    if (crc32(src, indexStart, ip) !== le32(src, ip)) throw new DecodeError("xz index CRC mismatch");
    ip += 4;
    const indexSize = ip - indexStart;

    // Stream footer
    if (ip + 12 > src.length) throw new DecodeError("xz stream footer truncated");
    if (crc32(src, ip + 4, ip + 10) !== le32(src, ip)) throw new DecodeError("xz stream footer CRC mismatch");
    if ((le32(src, ip + 4) + 1) * 4 !== indexSize) throw new DecodeError("xz backward size mismatch");
    if (src[ip + 8] !== flags0 || src[ip + 9] !== flags1) throw new DecodeError("xz stream footer flags differ from header");
    if (src[ip + 10] !== 0x59 || src[ip + 11] !== 0x5a) throw new DecodeError("xz stream footer magic missing");
    ip += 12;
    streams++;
  }
  return parts.length === 1 ? parts[0]! : Buffer.concat(parts, total);
}
