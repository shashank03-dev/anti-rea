import { inflateSync } from "node:zlib";
import { bzip2Decompress } from "./bzip2.js";
import { crc32 } from "./crc.js";
import { DecodeError, LimitError, xzDecompress } from "./xz.js";

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

export class UnsupportedImage extends Error {}

export interface Partition {
  readonly name: string;
  readonly data: Buffer;
}

const SECTOR = 512;

export function looksLikeUdif(buf: Buffer): boolean {
  if (buf.length < 512) return false;
  const k = buf.length - 512;
  return buf.toString("latin1", k, k + 4) === "koly" && buf.readUInt32BE(k + 4) === 4 && buf.readUInt32BE(k + 8) === 512;
}

/** Encrypted images (hdiutil -encryption) start with this header; their content is unreadable without the passphrase. */
export function looksLikeEncryptedDmg(buf: Buffer): boolean {
  return buf.length >= 8 && (buf.toString("latin1", 0, 8) === "encrcdsa" || buf.toString("latin1", buf.length - 8) === "cdsaencr");
}

const u64 = (b: Buffer, off: number): number => {
  const v = b.readBigUInt64BE(off);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new DecodeError("udif field out of range");
  return Number(v);
};

/** Minimal plist reading: the `<dict>` entries of the `blkx` array, with their Name and base64 Data. */
function blkxTables(xml: string): { name: string; data: Buffer }[] {
  const at = xml.search(/<key>\s*blkx\s*<\/key>/);
  if (at === -1) throw new DecodeError("udif property list has no blkx table");
  const arrStart = xml.indexOf("<array>", at);
  const arrEnd = xml.indexOf("</array>", arrStart);
  if (arrStart === -1 || arrEnd === -1) throw new DecodeError("udif blkx array malformed");
  const out: { name: string; data: Buffer }[] = [];
  const body = xml.slice(arrStart, arrEnd);
  for (const m of body.matchAll(/<dict>([\s\S]*?)<\/dict>/g)) {
    const d = m[1]!;
    const name = /<key>\s*(?:CFName|Name)\s*<\/key>\s*<string>([\s\S]*?)<\/string>/.exec(d)?.[1] ?? "";
    const data = /<key>\s*Data\s*<\/key>\s*<data>([\s\S]*?)<\/data>/.exec(d)?.[1];
    if (data === undefined) throw new DecodeError("udif blkx entry has no Data");
    out.push({ name: name.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">"), data: Buffer.from(data.replace(/\s+/g, ""), "base64") });
  }
  return out;
}

/** Apple Data Compression (UDCO chunks): a small LZ77 variant. */
export function adcDecompress(src: Buffer, outLen: number): Buffer {
  const out = Buffer.alloc(outLen);
  let ip = 0;
  let op = 0;
  while (ip < src.length && op < outLen) {
    const b = src[ip++]!;
    if (b & 0x80) {
      const n = (b & 0x7f) + 1;
      if (ip + n > src.length || op + n > outLen) throw new DecodeError("adc literal run out of range");
      src.copy(out, op, ip, ip + n);
      ip += n;
      op += n;
      continue;
    }
    let len: number;
    let dist: number;
    if (b & 0x40) {
      if (ip + 2 > src.length) throw new DecodeError("adc match truncated");
      len = (b & 0x3f) + 4;
      dist = ((src[ip]! << 8) | src[ip + 1]!) + 1;
      ip += 2;
    } else {
      if (ip + 1 > src.length) throw new DecodeError("adc match truncated");
      len = ((b >> 2) & 0x0f) + 3;
      dist = (((b & 0x03) << 8) | src[ip]!) + 1;
      ip += 1;
    }
    if (dist > op || op + len > outLen) throw new DecodeError("adc match out of range");
    for (let i = 0; i < len; i++, op++) out[op] = out[op - dist]!;
  }
  if (op !== outLen) throw new DecodeError("adc output shorter than the chunk");
  return out;
}

const T_ZERO = 0x00000000;
const T_RAW = 0x00000001;
const T_IGNORE = 0x00000002;
const T_ADC = 0x80000004;
const T_ZLIB = 0x80000005;
const T_BZIP2 = 0x80000006;
const T_LZFSE = 0x80000007;
const T_LZMA = 0x80000008;
const T_COMMENT = 0x7ffffffe;
const T_END = 0xffffffff;

/** Decode every partition of a UDIF image. `maxBytes` bounds the sum of partition sizes. */
export function readUdif(buf: Buffer, maxBytes: number): Partition[] {
  if (!looksLikeUdif(buf)) throw new DecodeError("not a UDIF image (no koly trailer)");
  const k = buf.length - 512;
  const dataForkOffset = u64(buf, k + 24);
  const dataForkLength = u64(buf, k + 32);
  const segmentCount = buf.readUInt32BE(k + 60);
  const xmlOffset = u64(buf, k + 216);
  const xmlLength = u64(buf, k + 224);
  if (segmentCount > 1) throw new UnsupportedImage("segmented disk image (multiple .dmgpart files)");
  if (dataForkOffset + dataForkLength > k) throw new DecodeError("udif data fork out of range");
  if (xmlLength === 0 || xmlOffset + xmlLength > k) throw new DecodeError("udif property list out of range");
  const tables = blkxTables(buf.toString("utf8", xmlOffset, xmlOffset + xmlLength));

  const parts: Partition[] = [];
  let total = 0;
  for (const t of tables) {
    const m = t.data;
    if (m.length < 204 || m.toString("latin1", 0, 4) !== "mish") throw new DecodeError("udif block table missing mish header");
    const sectorCount = u64(m, 16);
    const dataOffset = u64(m, 24);
    const ckType = m.readUInt32BE(64);
    const ckBits = m.readUInt32BE(68);
    const ckValue = m.readUInt32BE(72);
    const nChunks = m.readUInt32BE(200);
    if (204 + nChunks * 40 > m.length) throw new DecodeError("udif block table truncated");
    const size = sectorCount * SECTOR;
    total += size;
    if (total > maxBytes) throw new LimitError(`disk image expands to more than ${maxBytes} bytes`);
    const out = Buffer.alloc(size);
    let crc = 0;
    const checked = ckType === 2 && ckBits === 32 && ckValue !== 0;
    const feed = (b: Buffer) => {
      if (checked) crc = crc32(b, 0, b.length, crc);
    };
    for (let i = 0; i < nChunks; i++) {
      const c = 204 + i * 40;
      const type = m.readUInt32BE(c);
      if (type === T_END) break;
      if (type === T_COMMENT) continue;
      const sn = u64(m, c + 8);
      const sc = u64(m, c + 16);
      const off = dataForkOffset + dataOffset + u64(m, c + 24);
      const len = u64(m, c + 32);
      const at = sn * SECTOR;
      const want = sc * SECTOR;
      if (at + want > size) throw new DecodeError("udif chunk outside its partition");
      if (type === T_ZERO) {
        feed(Buffer.alloc(want));
        continue;
      }
      if (type === T_IGNORE) continue; // sectors whose content is irrelevant: left zero, excluded from the checksum
      if (off + len > dataForkOffset + dataForkLength) throw new DecodeError("udif chunk outside the data fork");
      const src = buf.subarray(off, off + len);
      let data: Buffer;
      switch (type) {
        case T_RAW:
          data = src;
          break;
        case T_ADC:
          data = adcDecompress(src, want);
          break;
        case T_ZLIB:
          data = inflateSync(src, { maxOutputLength: want });
          break;
        case T_BZIP2:
          data = bzip2Decompress(src, want).data;
          break;
        case T_LZMA:
          data = xzDecompress(src, want);
          break;
        case T_LZFSE:
          throw new UnsupportedImage("LZFSE-compressed disk image (ULFO) is not supported");
        default:
          throw new UnsupportedImage(`disk image chunk type 0x${type.toString(16)} is not supported`);
      }
      if (data.length !== want) throw new DecodeError("udif chunk decoded to the wrong size");
      data.copy(out, at);
      feed(data);
    }
    if (checked && crc >>> 0 !== ckValue) throw new DecodeError(`udif partition "${t.name}" checksum mismatch`);
    parts.push({ name: t.name, data: out });
  }
  return parts;
}
