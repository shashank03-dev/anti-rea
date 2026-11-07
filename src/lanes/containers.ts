import * as zlib from "node:zlib";
import { gunzipSync, inflateRawSync } from "node:zlib";
import { bzip2Decompress, looksLikeBzip2 } from "../codecs/bzip2.js";
import { looksLikeHfsPlus, readHfsPlus } from "../codecs/hfsplus.js";
import { looksLikeLz4, lz4Decompress } from "../codecs/lz4.js";
import { UnsupportedImage, looksLikeEncryptedDmg, looksLikeUdif, readUdif } from "../codecs/udif.js";
import { DecodeError, LimitError, XZ_MAGIC, looksLikeLzmaAlone, lzmaAloneDecompress, xzDecompress } from "../codecs/xz.js";

/** zstd needs Node >= 22.15 / 23.8; on older runtimes .zst stays an explicit coverage gap. */
const zstdDecompressSync = (zlib as unknown as { zstdDecompressSync?: (b: Buffer, o: { maxOutputLength: number }) => Buffer }).zstdDecompressSync;
export const ZSTD_SUPPORTED = typeof zstdDecompressSync === "function";

/**
 * Read-only, in-memory expansion of common delivery containers so the release
 * closure covers nested bytes (doc §6.3). Nothing is ever written to disk, so
 * entry names like `../x` cannot escape anywhere.
 *
 * Resource limits guard against decompression bombs (doc §9.3). Anything that
 * cannot be expanded is returned as an explicit unsupported reason — never
 * silently skipped.
 */

export interface Limits {
  /** Largest on-disk file that is read at all. */
  readonly maxFileBytes: number;
  /** Largest single decompressed container entry. */
  readonly maxEntryBytes: number;
  readonly maxTotalExpandedBytes: number;
  readonly maxDepth: number;
  readonly maxEntries: number;
  /** Content lanes decode bytes to text in chunks of this size (strings in V8 are capped near 512 MiB). */
  readonly scanChunkBytes: number;
  /** Overlap between chunks; must exceed the longest bounded match (PEM blocks are capped at 16 KiB). */
  readonly scanOverlapBytes: number;
}

export const DEFAULT_LIMITS: Limits = {
  maxFileBytes: 2 * 1024 * 1024 * 1024,
  maxEntryBytes: 256 * 1024 * 1024,
  maxTotalExpandedBytes: 1024 * 1024 * 1024,
  maxDepth: 4,
  maxEntries: 200_000,
  scanChunkBytes: 16 * 1024 * 1024,
  scanOverlapBytes: 64 * 1024,
};

export interface ContainerEntry {
  readonly name: string;
  readonly data: Buffer | null;
  /** Set when data is null: why this entry could not be read. */
  readonly reason?: string;
}

export type ContainerKind = "zip" | "asar" | "tar" | "gzip" | "xz" | "lzma" | "bzip2" | "zstd" | "lz4" | "ar" | "dmg";

/** Single-stream compressors: their payload is one file (often a tar). */
const STREAM_KINDS: ReadonlySet<ContainerKind> = new Set(["gzip", "xz", "lzma", "bzip2", "zstd", "lz4"]);

export type Expansion =
  | { readonly ok: true; readonly kind: ContainerKind; readonly entries: ContainerEntry[]; readonly notes: string[] }
  | { readonly ok: false; readonly kind: ContainerKind; readonly reason: string };

export type Classification =
  | { readonly type: "plain"; readonly note?: string }
  | { readonly type: "container"; readonly kind: ContainerKind }
  | { readonly type: "opaque"; readonly format: string };

const ZIP_EXT = /\.(zip|jar|apk|aab|ipa|aar|nupkg|whl|xpi|vsix|appx|msix|epub|war|ear|crx)$/i;
const OPAQUE_EXT: readonly [RegExp, string][] = [
  [/\.dmg$/i, "Apple disk image (not UDIF)"],
  [/\.msi$/i, "Windows Installer"],
  [/\.7z$/i, "7-Zip"],
  [/\.rar$/i, "RAR"],
  [/\.pkg$/i, "macOS installer package (xar)"],
  [/\.rpm$/i, "RPM package"],
  [/\.snap$/i, "snap (squashfs)"],
  [/\.appimage$/i, "AppImage (squashfs)"],
  [/\.cab$/i, "Cabinet"],
];

function has(buf: Buffer, bytes: readonly number[], at = 0): boolean {
  if (buf.length < at + bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) if (buf[at + i] !== bytes[i]) return false;
  return true;
}

function ascii(buf: Buffer, s: string, at = 0): boolean {
  return buf.length >= at + s.length && buf.toString("latin1", at, at + s.length) === s;
}

/**
 * Classify by magic bytes first, then by extension. Native executables
 * (PE / ELF / Mach-O) are PLAIN: their bytes are scanned directly. Only formats
 * whose payload is compressed or encoded in a way this version cannot decode
 * are opaque — and opaque content is reported as a coverage gap.
 */
export function classify(name: string, buf: Buffer): Classification {
  // A UDIF trailer is definitive, and must be checked first: the data fork of a UDBZ/ULMO/UDZO image
  // starts with its first chunk's bzip2/xz/zlib magic (v0.4 misread UDBZ and ULMO images as streams).
  if (looksLikeEncryptedDmg(buf)) return { type: "opaque", format: "encrypted Apple disk image" };
  if (looksLikeUdif(buf)) return { type: "container", kind: "dmg" };
  if (has(buf, [0x50, 0x4b, 0x03, 0x04]) || has(buf, [0x50, 0x4b, 0x05, 0x06])) return { type: "container", kind: "zip" };
  if (has(buf, [0x1f, 0x8b])) return { type: "container", kind: "gzip" };
  if (/\.asar$/i.test(name) && buf.length >= 16 && buf.readUInt32LE(0) === 4) return { type: "container", kind: "asar" };
  if (isTar(buf)) return { type: "container", kind: "tar" };

  if (has(buf, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { type: "opaque", format: "7-Zip" };
  if (ascii(buf, "Rar!\x1a\x07")) return { type: "opaque", format: "RAR" };
  if (has(buf, XZ_MAGIC)) return { type: "container", kind: "xz" };
  if (looksLikeBzip2(buf)) return { type: "container", kind: "bzip2" };
  if (has(buf, [0x28, 0xb5, 0x2f, 0xfd])) return ZSTD_SUPPORTED ? { type: "container", kind: "zstd" } : { type: "opaque", format: "zstd (needs Node >= 22.15)" };
  if (/\.(lzma|tlz)$/i.test(name) && looksLikeLzmaAlone(buf)) return { type: "container", kind: "lzma" };
  if (ascii(buf, "!<arch>\n")) return { type: "container", kind: "ar" };
  if (looksLikeLz4(buf)) return { type: "container", kind: "lz4" };
  if (has(buf, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { type: "opaque", format: "OLE compound file (MSI)" };
  if (ascii(buf, "xar!")) return { type: "opaque", format: "xar (macOS .pkg)" };
  if (ascii(buf, "MSCF")) return { type: "opaque", format: "Cabinet" };
  if (ascii(buf, "hsqs") || ascii(buf, "sqsh")) return { type: "opaque", format: "squashfs" };
  if (has(buf, [0xed, 0xab, 0xee, 0xdb])) return { type: "opaque", format: "RPM" };
  if (buf.length >= 512 && ascii(buf, "koly", buf.length - 512)) return { type: "opaque", format: "Apple disk image (unrecognised UDIF version)" };

  const pe = ascii(buf, "MZ");
  if (pe) {
    // Installers compress their payload; scanning the stub bytes would be a false negative.
    const head = buf.subarray(0, Math.min(buf.length, 8 * 1024 * 1024));
    if (head.indexOf("NullsoftInst") !== -1) return { type: "opaque", format: "NSIS installer" };
    if (head.indexOf("Inno Setup Setup Data") !== -1) return { type: "opaque", format: "Inno Setup installer" };
  }
  for (const [re, format] of OPAQUE_EXT) if (re.test(name)) return { type: "opaque", format };
  if (ZIP_EXT.test(name)) return { type: "container", kind: "zip" }; // will fail loudly if not actually a zip

  const native = pe
    ? "PE"
    : has(buf, [0x7f, 0x45, 0x4c, 0x46])
      ? "ELF"
      : has(buf, [0xcf, 0xfa, 0xed, 0xfe]) || has(buf, [0xce, 0xfa, 0xed, 0xfe]) || has(buf, [0xca, 0xfe, 0xba, 0xbe])
        ? "Mach-O"
        : null;
  if (native)
    return { type: "plain", note: `${native} binary scanned as raw bytes (Latin-1 and UTF-16LE views); packed or compressed sections are not decoded` };
  return { type: "plain" };
}

export function expand(kind: ContainerKind, name: string, buf: Buffer, limits: Limits): Expansion {
  try {
    switch (kind) {
      case "zip":
        return readZip(buf, limits);
      case "asar":
        return readAsar(buf, limits);
      case "tar":
        return { ok: true, kind, entries: readTar(buf, limits), notes: [] };
      case "ar":
        return readAr(buf, limits);
      case "dmg":
        return readDmg(buf, limits);
      default:
        if (STREAM_KINDS.has(kind)) return expandStream(kind, name, buf, limits);
        throw new Error(`unknown container kind ${kind}`);
    }
  } catch (e) {
    const msg = (e as Error).message;
    if (e instanceof UnsupportedImage) return { ok: false, kind, reason: msg };
    if (e instanceof LimitError) return { ok: false, kind, reason: `exceeds expansion limit (${msg})` };
    if (e instanceof DecodeError) return { ok: false, kind, reason: `failed to decode ${kind}: ${msg}` };
    const bomb = /maxOutputLength|buffer|too large|Cannot create a Buffer|exceeds limit/i.test(msg);
    return { ok: false, kind, reason: bomb ? `exceeds expansion limit (${msg})` : `failed to parse ${kind}: ${msg}` };
  }
}

// ---------------------------------------------------------------- compressed streams

const STREAM_SUFFIX: Record<string, [RegExp, string][]> = {
  gzip: [[/\.tgz$/i, ".tar"], [/\.gz$/i, ""]],
  xz: [[/\.txz$/i, ".tar"], [/\.xz$/i, ""]],
  lzma: [[/\.tlz$/i, ".tar"], [/\.lzma$/i, ""]],
  bzip2: [[/\.tbz2?$/i, ".tar"], [/\.bz2$/i, ""]],
  zstd: [[/\.tzst$/i, ".tar"], [/\.zstd?$/i, ""]],
  lz4: [[/\.tlz4$/i, ".tar"], [/\.lz4$/i, ""]],
};

function decompress(kind: ContainerKind, buf: Buffer, max: number): { data: Buffer; trailing: Buffer | null } {
  switch (kind) {
    case "gzip":
      return { data: gunzipSync(buf, { maxOutputLength: max }), trailing: null };
    case "xz":
      return { data: xzDecompress(buf, max), trailing: null };
    case "lzma":
      return { data: lzmaAloneDecompress(buf, max), trailing: null };
    case "bzip2":
      return bzip2Decompress(buf, max);
    case "zstd":
      return { data: zstdDecompressSync!(buf, { maxOutputLength: max }), trailing: null };
    case "lz4":
      return { data: lz4Decompress(buf, max), trailing: null };
    default:
      throw new Error(`${kind} is not a stream compressor`);
  }
}

function expandStream(kind: ContainerKind, name: string, buf: Buffer, limits: Limits): Expansion {
  const { data, trailing } = decompress(kind, buf, limits.maxEntryBytes);
  const notes: string[] = [];
  const extra: ContainerEntry[] = [];
  if (trailing) {
    notes.push(`${trailing.length} bytes follow the ${kind} stream; inspected as a separate entry`);
    extra.push({ name: "(trailing-bytes)", data: trailing });
  }
  if (isTar(data)) return { ok: true, kind: "tar", entries: [...readTar(data, limits), ...extra], notes: [`${kind}-compressed tar`, ...notes] };
  const base = name.slice(name.lastIndexOf("/") + 1);
  let inner = base;
  for (const [re, rep] of STREAM_SUFFIX[kind] ?? []) {
    if (re.test(base)) {
      inner = base.replace(re, rep);
      break;
    }
  }
  return { ok: true, kind, entries: [{ name: inner && inner !== base ? inner : "payload", data }, ...extra], notes };
}

// ---------------------------------------------------------------- dmg (UDIF disk images with HFS+ volumes)

/** Partitions that hold partition-map metadata or nothing, never files. */
const DMG_METADATA = /\b(?:MBR|GPT|Apple_Free|Apple_partition_map|Driver|Patches|DDM)\b/i;

function readDmg(buf: Buffer, limits: Limits): Expansion {
  const parts = readUdif(buf, limits.maxTotalExpandedBytes);
  const entries: ContainerEntry[] = [];
  const notes: string[] = [];
  const volumes = parts.filter((p) => looksLikeHfsPlus(p.data));
  for (const p of parts) {
    if (looksLikeHfsPlus(p.data)) {
      const r = readHfsPlus(p.data, { maxEntries: limits.maxEntries, maxEntryBytes: limits.maxEntryBytes });
      const prefix = volumes.length > 1 ? `${r.volume || p.name}/` : "";
      for (const e of r.entries) {
        if (entries.length >= limits.maxEntries) return { ok: false, kind: "dmg", reason: "disk image entry count exceeds limit" };
        entries.push(e.data ? { name: prefix + e.name, data: e.data } : { name: prefix + e.name, data: null, reason: e.reason ?? "unreadable" });
      }
      notes.push(...r.notes.map((n) => `${p.name}: ${n}`));
      continue;
    }
    if (p.data.length >= 36 && p.data.toString("latin1", 32, 36) === "NXSB") return { ok: false, kind: "dmg", reason: `APFS volume in disk image is not supported (${p.name})` };
    if (DMG_METADATA.test(p.name)) continue;
    if (p.data.some((b) => b !== 0)) return { ok: false, kind: "dmg", reason: `disk image partition with an unsupported filesystem (${p.name || "unnamed"})` };
  }
  if (volumes.length === 0) return { ok: false, kind: "dmg", reason: "disk image contains no readable filesystem" };
  notes.unshift(`UDIF disk image: ${volumes.length} HFS+ volume(s)`);
  return { ok: true, kind: "dmg", entries, notes };
}

// ---------------------------------------------------------------- ar (.deb, static libraries)

function readAr(buf: Buffer, limits: Limits): Expansion {
  const entries: ContainerEntry[] = [];
  const notes: string[] = [];
  let longNames: Buffer | null = null;
  let p = 8;
  while (p + 60 <= buf.length) {
    if (buf[p + 58] !== 0x60 || buf[p + 59] !== 0x0a) return { ok: false, kind: "ar", reason: "corrupt ar member header" };
    let name = buf.toString("latin1", p, p + 16).trimEnd();
    const size = parseInt(buf.toString("latin1", p + 48, p + 58).trim(), 10);
    if (!Number.isFinite(size) || size < 0) return { ok: false, kind: "ar", reason: "corrupt ar member size" };
    let start = p + 60;
    let len = size;
    if (start + size > buf.length) return { ok: false, kind: "ar", reason: "ar member truncated" };
    if (name.startsWith("#1/")) {
      // BSD: the name is stored at the start of the data.
      const n = parseInt(name.slice(3), 10);
      name = buf.toString("utf8", start, start + n).replace(/\0+$/, "");
      start += n;
      len -= n;
    } else if (name === "//") {
      longNames = buf.subarray(start, start + size); // GNU long-name table
      name = "";
    } else if (name === "/" || name === "/SYM64/" || name.startsWith("__.SYMDEF")) {
      name = ""; // symbol index
    } else if (/^\/\d+$/.test(name) && longNames) {
      const off = parseInt(name.slice(1), 10);
      const end = longNames.indexOf("/\n", off);
      name = longNames.toString("utf8", off, end === -1 ? longNames.length : end);
    } else if (name.endsWith("/")) {
      name = name.slice(0, -1);
    }
    if (name) {
      if (entries.length >= limits.maxEntries) return { ok: false, kind: "ar", reason: "ar entry count exceeds limit" };
      entries.push(len > limits.maxEntryBytes ? { name, data: null, reason: `entry size ${len} exceeds limit` } : { name, data: buf.subarray(start, start + len) });
    }
    p = p + 60 + size + (size % 2);
  }
  if (p < buf.length) {
    notes.push(`${buf.length - p} trailing bytes after the last ar member; inspected as a separate entry`);
    entries.push({ name: "(trailing-bytes)", data: buf.subarray(p) });
  }
  return { ok: true, kind: "ar", entries, notes };
}

// ---------------------------------------------------------------- zip

function readZip(buf: Buffer, limits: Limits): Expansion {
  const min = Math.max(0, buf.length - 65_557);
  let eocd = -1;
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return { ok: false, kind: "zip", reason: "no end-of-central-directory record (corrupt or not a zip)" };
  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOff = buf.readUInt32LE(eocd + 16);
  if (cdOff === 0xffffffff || cdSize === 0xffffffff || total === 0xffff) return { ok: false, kind: "zip", reason: "zip64 archives are not supported" };
  if (total > limits.maxEntries) return { ok: false, kind: "zip", reason: `entry count ${total} exceeds limit` };
  // Bytes prepended to the archive (self-extractor stubs etc.) shift every recorded offset.
  const delta = eocd - (cdOff + cdSize);
  if (delta < 0) return { ok: false, kind: "zip", reason: "central directory offset is inconsistent" };

  const entries: ContainerEntry[] = [];
  const notes: string[] = delta > 0 ? [`${delta} bytes precede the archive (offsets corrected)`] : [];
  let p = cdOff + delta;
  for (let k = 0; k < total; k++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50)
      return { ok: false, kind: "zip", reason: "corrupt central directory" };
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28);
    const elen = buf.readUInt16LE(p + 30);
    const clen = buf.readUInt16LE(p + 32);
    const lho = buf.readUInt32LE(p + 42) + delta;
    const name = buf.toString("utf8", p + 46, p + 46 + nlen);
    p += 46 + nlen + elen + clen;
    if (name.endsWith("/")) continue;

    if (flags & 0x1) {
      entries.push({ name, data: null, reason: "encrypted zip entry" });
      continue;
    }
    if (usize === 0xffffffff || csize === 0xffffffff) {
      entries.push({ name, data: null, reason: "zip64 entry not supported" });
      continue;
    }
    if (usize > limits.maxEntryBytes) {
      entries.push({ name, data: null, reason: `entry size ${usize} exceeds limit` });
      continue;
    }
    if (lho + 30 > buf.length || buf.readUInt32LE(lho) !== 0x04034b50) {
      entries.push({ name, data: null, reason: "corrupt local file header" });
      continue;
    }
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    if (start + csize > buf.length) {
      entries.push({ name, data: null, reason: "entry data truncated" });
      continue;
    }
    const comp = buf.subarray(start, start + csize);
    if (method === 0) {
      entries.push({ name, data: comp });
    } else if (method === 8) {
      try {
        entries.push({ name, data: inflateRawSync(comp, { maxOutputLength: limits.maxEntryBytes }) });
      } catch (e) {
        entries.push({ name, data: null, reason: `inflate failed or exceeds limit: ${(e as Error).message}` });
      }
    } else if (method === 12 || method === 14) {
      try {
        entries.push({ name, data: method === 12 ? zipBzip2(comp, usize, limits) : zipLzma(comp, usize, limits) });
      } catch (e) {
        const why = e instanceof LimitError ? "exceeds limit" : "failed";
        entries.push({ name, data: null, reason: `${method === 12 ? "bzip2" : "LZMA"} entry ${why}: ${(e as Error).message}` });
      }
    } else {
      entries.push({ name, data: null, reason: `unsupported compression method ${method}` });
    }
  }
  if (entries.some((e) => e.data === null)) notes.push("some zip entries could not be read");
  return { ok: true, kind: "zip", entries, notes };
}

/** Zip method 12: the entry is a complete bzip2 stream. */
function zipBzip2(comp: Buffer, usize: number, limits: Limits): Buffer {
  const { data } = bzip2Decompress(comp, limits.maxEntryBytes);
  if (data.length !== usize) throw new DecodeError("bzip2 entry size mismatch");
  return data;
}

/**
 * Zip method 14 (APPNOTE 5.8.8): 2-byte LZMA SDK version, 2-byte properties
 * size (5), the 5 property bytes, then raw LZMA data. Rewritten as an
 * LZMA_Alone header with the central directory's size.
 */
function zipLzma(comp: Buffer, usize: number, limits: Limits): Buffer {
  if (comp.length < 9 || comp.readUInt16LE(2) !== 5) throw new DecodeError("invalid LZMA entry header");
  const header = Buffer.alloc(13);
  comp.copy(header, 0, 4, 9);
  header.writeUInt32LE(usize >>> 0, 5);
  header.writeUInt32LE(Math.floor(usize / 2 ** 32), 9);
  const data = lzmaAloneDecompress(Buffer.concat([header, comp.subarray(9)]), limits.maxEntryBytes);
  if (data.length !== usize) throw new DecodeError("LZMA entry size mismatch");
  return data;
}

// ---------------------------------------------------------------- asar

interface AsarNode {
  files?: Record<string, AsarNode>;
  size?: number;
  offset?: string;
  unpacked?: boolean;
  link?: string;
}

function readAsar(buf: Buffer, limits: Limits): Expansion {
  // Layout: [u32 4][u32 headerPickleSize] then header pickle [u32 payload][u32 strLen][json], data at 8+headerPickleSize.
  const headerPickleSize = buf.readUInt32LE(4);
  const strLen = buf.readUInt32LE(12);
  if (16 + strLen > buf.length || 8 + headerPickleSize > buf.length)
    return { ok: false, kind: "asar", reason: "header exceeds file size" };
  const header = JSON.parse(buf.toString("utf8", 16, 16 + strLen)) as AsarNode;
  const base = 8 + headerPickleSize;
  const entries: ContainerEntry[] = [];
  const notes: string[] = [];

  const visit = (node: AsarNode, prefix: string) => {
    for (const [name, child] of Object.entries(node.files ?? {})) {
      const path = prefix ? `${prefix}/${name}` : name;
      if (entries.length >= limits.maxEntries) throw new Error("asar entry count exceeds limit");
      if (child.files) {
        visit(child, path);
      } else if (child.link !== undefined) {
        notes.push(`symlink entry ${path} -> ${child.link} not followed`);
      } else if (child.unpacked) {
        // Unpacked entries ship beside the archive in <name>.asar.unpacked/ and are covered by the filesystem walk.
        notes.push(`${path} is unpacked (covered via .asar.unpacked on disk if present)`);
      } else {
        const size = child.size ?? 0;
        const off = Number(child.offset ?? "0");
        if (size > limits.maxEntryBytes) {
          entries.push({ name: path, data: null, reason: `entry size ${size} exceeds limit` });
        } else if (!Number.isFinite(off) || base + off + size > buf.length) {
          entries.push({ name: path, data: null, reason: "entry offset outside archive" });
        } else {
          entries.push({ name: path, data: buf.subarray(base + off, base + off + size) });
        }
      }
    }
  };
  visit(header, "");
  return { ok: true, kind: "asar", entries, notes };
}

// ---------------------------------------------------------------- tar

function cstr(b: Buffer, off: number, len: number): string {
  const s = b.subarray(off, off + len);
  const z = s.indexOf(0);
  return s.toString("utf8", 0, z === -1 ? s.length : z);
}

export function isTar(buf: Buffer): boolean {
  if (buf.length < 512) return false;
  const h = buf.subarray(0, 512);
  if (h.every((x) => x === 0)) return false;
  const stored = parseInt(cstr(h, 148, 8).trim() || "x", 8);
  if (!Number.isFinite(stored)) return false;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i]!;
  return sum === stored;
}

/** Extract `path` from a pax extended header ("<len> key=value\n" records; len counts bytes). */
function paxPath(data: Buffer): string | null {
  let p = 0;
  while (p < data.length) {
    const sp = data.indexOf(0x20, p);
    if (sp === -1) break;
    const len = parseInt(data.toString("latin1", p, sp), 10);
    if (!Number.isFinite(len) || len <= 0 || p + len > data.length) break;
    const rec = data.toString("utf8", sp + 1, p + len - 1);
    const eq = rec.indexOf("=");
    if (eq !== -1 && rec.slice(0, eq) === "path") return rec.slice(eq + 1);
    p += len;
  }
  return null;
}

function readTar(buf: Buffer, limits: Limits): ContainerEntry[] {
  const entries: ContainerEntry[] = [];
  let p = 0;
  let override: string | null = null;
  while (p + 512 <= buf.length) {
    const h = buf.subarray(p, p + 512);
    if (h.every((x) => x === 0)) break;
    const size = parseInt(cstr(h, 124, 12).trim() || "0", 8);
    if (!Number.isFinite(size) || size < 0) throw new Error("corrupt tar header size");
    const type = String.fromCharCode(h[156] ?? 0);
    const magic = cstr(h, 257, 6);
    const prefix = magic.startsWith("ustar") ? cstr(h, 345, 155) : "";
    let name = override ?? (prefix ? `${prefix}/${cstr(h, 0, 100)}` : cstr(h, 0, 100));
    const dataStart = p + 512;
    const data = buf.subarray(dataStart, dataStart + size);
    if (type === "L") {
      override = cstr(data, 0, data.length); // GNU long name applies to the next header
    } else if (type === "x") {
      override = paxPath(data); // pax per-file header applies to the next header
    } else {
      override = null;
      if (type === "0" || type === "\0" || type === "7") {
        if (entries.length >= limits.maxEntries) throw new Error("tar entry count exceeds limit");
        if (name.startsWith("./")) name = name.slice(2);
        entries.push(size > limits.maxEntryBytes ? { name, data: null, reason: `entry size ${size} exceeds limit` } : { name, data });
      }
    }
    p = dataStart + Math.ceil(size / 512) * 512;
  }
  return entries;
}
