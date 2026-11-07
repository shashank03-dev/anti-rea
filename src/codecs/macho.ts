import { createHash } from "node:crypto";
import { DecodeError } from "./xz.js";
import { parsePlist, isDict, type PlistValue } from "./plist.js";

/**
 * Zero-dependency Mach-O and Apple code-signature reader.
 *
 * It parses fat (universal) and thin 32/64-bit little-endian Mach-O files, finds
 * LC_CODE_SIGNATURE, and decodes the embedded signature superblob:
 * CodeDirectories (identifier, team ID, flags, hash type), entitlements and the
 * CMS blob.
 *
 * It VERIFIES what can be verified offline: every code-page hash, and the
 * special-slot hashes of the Info.plist, the sealed-resources file and the
 * entitlements, against the bytes that actually ship. That detects
 * modification after signing.
 *
 * It does NOT validate the CMS certificate chain (that needs Apple's trust
 * roots and revocation data), so a signature can be internally consistent and
 * still be self-made. Use `codesign --verify` or Gatekeeper for chain trust.
 */

export const CS_ADHOC = 0x2;
export const CS_RUNTIME = 0x10000; // hardened runtime
export const CS_LINKER_SIGNED = 0x20000;

const MH_FILETYPES: Record<number, string> = { 1: "object", 2: "execute", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib-stub", 11: "kext" };
const CPU: Record<number, string> = { 7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "arm64", 0x0200000c: "arm64_32" };

export interface CodeDirectoryInfo {
  readonly identifier: string;
  readonly teamId?: string;
  readonly flags: number;
  readonly hashType: "sha1" | "sha256" | "sha256-truncated" | "sha384" | "unknown";
  /** cdhash: hash of the CodeDirectory blob with its own hash type, truncated to 20 bytes (hex). */
  readonly cdhash: string;
  readonly codeLimit: number;
  readonly pageSize: number;
  readonly nCodeSlots: number;
  readonly nSpecialSlots: number;
  /** Code pages whose hash does not match the shipped bytes. */
  readonly badPages: number;
  /** Special slots (1 = Info.plist, 3 = resources, 5 = entitlements, 7 = DER entitlements) and their expected hashes (hex). */
  readonly specialSlots: Readonly<Record<number, string>>;
  readonly hashSize: number;
}

export interface SliceInfo {
  readonly arch: string;
  readonly filetype: string;
  readonly offset: number;
  readonly size: number;
  readonly signed: boolean;
  /** All CodeDirectories (primary and alternates); [0] is the primary. */
  readonly codeDirectories: readonly CodeDirectoryInfo[];
  readonly entitlements?: Readonly<Record<string, PlistValue>>;
  /** True when a non-empty CMS signature blob is present (adhoc signatures have none). */
  readonly hasCmsSignature: boolean;
  readonly error?: string;
}

export interface MachOInfo {
  readonly fat: boolean;
  readonly slices: readonly SliceInfo[];
}

export function looksLikeMachO(b: Buffer): boolean {
  if (b.length < 32) return false;
  const le = b.readUInt32LE(0);
  if (le === 0xfeedfacf || le === 0xfeedface) return true;
  const be = b.readUInt32BE(0);
  if (be !== 0xcafebabe && be !== 0xcafebabf) return false;
  // 0xCAFEBABE is also the Java class-file magic; a fat header has a small arch count with in-range slices.
  const n = b.readUInt32BE(4);
  if (n === 0 || n > 16) return false;
  const entry = be === 0xcafebabf ? 32 : 20;
  if (8 + n * entry > b.length) return false;
  for (let i = 0; i < n; i++) {
    const at = 8 + i * entry;
    const off = be === 0xcafebabf ? Number(b.readBigUInt64BE(at + 8)) : b.readUInt32BE(at + 8);
    const size = be === 0xcafebabf ? Number(b.readBigUInt64BE(at + 16)) : b.readUInt32BE(at + 12);
    if (off + size > b.length || size < 32) return false;
  }
  return true;
}

function hashFor(type: number): { algo: string; size: number; name: CodeDirectoryInfo["hashType"] } {
  switch (type) {
    case 1:
      return { algo: "sha1", size: 20, name: "sha1" };
    case 2:
      return { algo: "sha256", size: 32, name: "sha256" };
    case 3:
      return { algo: "sha256", size: 20, name: "sha256-truncated" };
    case 4:
      return { algo: "sha384", size: 48, name: "sha384" };
    default:
      return { algo: "", size: 0, name: "unknown" };
  }
}

const cstr = (b: Buffer, at: number) => {
  const end = b.indexOf(0, at);
  return b.toString("utf8", at, end === -1 ? b.length : end);
};

function parseCodeDirectory(cd: Buffer, slice: Buffer): CodeDirectoryInfo {
  if (cd.length < 44 || cd.readUInt32BE(0) !== 0xfade0c02) throw new DecodeError("bad CodeDirectory magic");
  const length = cd.readUInt32BE(4);
  const blob = cd.subarray(0, Math.min(length, cd.length));
  const version = cd.readUInt32BE(8);
  const flags = cd.readUInt32BE(12);
  const hashOffset = cd.readUInt32BE(16);
  const identOffset = cd.readUInt32BE(20);
  const nSpecialSlots = cd.readUInt32BE(24);
  const nCodeSlots = cd.readUInt32BE(28);
  let codeLimit = cd.readUInt32BE(32);
  const hashSize = cd[36]!;
  const hashType = cd[37]!;
  const pageSizeLog = cd[39]!;
  const teamOffset = version >= 0x20200 && cd.length >= 52 ? cd.readUInt32BE(48) : 0;
  if (version >= 0x20300 && cd.length >= 64) {
    const codeLimit64 = Number(cd.readBigUInt64BE(56));
    if (codeLimit64 > 0) codeLimit = codeLimit64;
  }
  const h = hashFor(hashType);
  if (h.size !== 0 && hashSize !== h.size) throw new DecodeError("CodeDirectory hash size does not match its hash type");
  const pageSize = pageSizeLog === 0 ? 0 : 2 ** pageSizeLog;
  if (hashOffset + nCodeSlots * hashSize > blob.length || hashOffset < nSpecialSlots * hashSize) throw new DecodeError("CodeDirectory slots out of range");
  const specialSlots: Record<number, string> = {};
  for (let i = 1; i <= nSpecialSlots; i++) {
    const s = blob.subarray(hashOffset - i * hashSize, hashOffset - (i - 1) * hashSize);
    if (s.some((x) => x !== 0)) specialSlots[i] = s.toString("hex");
  }
  let badPages = 0;
  if (h.algo) {
    if (codeLimit > slice.length) badPages = nCodeSlots; // the signed range extends past the shipped bytes
    else
      for (let i = 0; i < nCodeSlots; i++) {
        const start = pageSize === 0 ? 0 : i * pageSize;
        const end = pageSize === 0 ? codeLimit : Math.min(codeLimit, start + pageSize);
        const want = blob.subarray(hashOffset + i * hashSize, hashOffset + (i + 1) * hashSize);
        const got = createHash(h.algo).update(slice.subarray(start, end)).digest().subarray(0, hashSize);
        if (!got.equals(want)) badPages++;
      }
  }
  const cdhash = h.algo ? createHash(h.algo).update(blob).digest().subarray(0, 20).toString("hex") : "";
  return {
    identifier: identOffset > 0 && identOffset < blob.length ? cstr(blob, identOffset) : "",
    ...(teamOffset > 0 && teamOffset < blob.length ? { teamId: cstr(blob, teamOffset) } : {}),
    flags,
    hashType: h.name,
    cdhash,
    codeLimit,
    pageSize,
    nCodeSlots,
    nSpecialSlots,
    badPages,
    specialSlots,
    hashSize,
  };
}

/** A detached CodeDirectory (code-less bundles keep it in _CodeSignature/CodeDirectory; its code slots cover Info.plist). */
export function parseDetachedCodeDirectory(cd: Buffer, main: Buffer): CodeDirectoryInfo {
  return parseCodeDirectory(cd, main);
}

function parseSlice(slice: Buffer, arch: string, offset: number): SliceInfo {
  const magic = slice.readUInt32LE(0);
  const is64 = magic === 0xfeedfacf;
  if (!is64 && magic !== 0xfeedface) return { arch, filetype: "unknown", offset, size: slice.length, signed: false, codeDirectories: [], hasCmsSignature: false, error: "not a little-endian Mach-O slice" };
  const cputype = slice.readUInt32LE(4);
  const filetype = MH_FILETYPES[slice.readUInt32LE(12)] ?? `type-${slice.readUInt32LE(12)}`;
  const ncmds = slice.readUInt32LE(16);
  let p = is64 ? 32 : 28;
  const base = { arch: arch || CPU[cputype] || `cpu-${cputype.toString(16)}`, filetype, offset, size: slice.length };
  for (let i = 0; i < ncmds; i++) {
    if (p + 8 > slice.length) return { ...base, signed: false, codeDirectories: [], hasCmsSignature: false, error: "load commands truncated" };
    const cmd = slice.readUInt32LE(p);
    const cmdsize = slice.readUInt32LE(p + 4);
    if (cmdsize < 8) return { ...base, signed: false, codeDirectories: [], hasCmsSignature: false, error: "load command size invalid" };
    if (cmd === 0x1d) {
      const dataoff = slice.readUInt32LE(p + 8);
      const datasize = slice.readUInt32LE(p + 12);
      if (dataoff + datasize > slice.length) return { ...base, signed: true, codeDirectories: [], hasCmsSignature: false, error: "code signature outside the file" };
      try {
        return { ...base, signed: true, ...parseSuperBlob(slice.subarray(dataoff, dataoff + datasize), slice) };
      } catch (e) {
        return { ...base, signed: true, codeDirectories: [], hasCmsSignature: false, error: (e as Error).message };
      }
    }
    p += cmdsize;
  }
  return { ...base, signed: false, codeDirectories: [], hasCmsSignature: false };
}

function parseSuperBlob(sig: Buffer, slice: Buffer): Pick<SliceInfo, "codeDirectories" | "entitlements" | "hasCmsSignature"> {
  if (sig.length < 12 || sig.readUInt32BE(0) !== 0xfade0cc0) throw new DecodeError("bad code-signature superblob magic");
  const count = sig.readUInt32BE(8);
  if (12 + count * 8 > sig.length) throw new DecodeError("code-signature index truncated");
  const cds: CodeDirectoryInfo[] = [];
  let entitlements: Record<string, PlistValue> | undefined;
  let hasCms = false;
  for (let i = 0; i < count; i++) {
    const type = sig.readUInt32BE(12 + i * 8);
    const off = sig.readUInt32BE(16 + i * 8);
    if (off + 8 > sig.length) throw new DecodeError("code-signature blob out of range");
    const len = sig.readUInt32BE(off + 4);
    const blob = sig.subarray(off, Math.min(sig.length, off + len));
    if (type === 0 || (type >= 0x1000 && type < 0x1005)) cds.push(parseCodeDirectory(blob, slice));
    else if (type === 5 && blob.readUInt32BE(0) === 0xfade7171) {
      const v = parsePlist(blob.subarray(8));
      if (isDict(v)) entitlements = v;
    } else if (type === 0x10000) hasCms = len > 8;
  }
  return { codeDirectories: cds, ...(entitlements ? { entitlements } : {}), hasCmsSignature: hasCms };
}

/** Parse a Mach-O file. Throws DecodeError only when the file is not Mach-O at all. */
export function readMachO(b: Buffer): MachOInfo {
  if (!looksLikeMachO(b)) throw new DecodeError("not a Mach-O file");
  const be = b.readUInt32BE(0);
  if (be === 0xcafebabe || be === 0xcafebabf) {
    const n = b.readUInt32BE(4);
    const entry = be === 0xcafebabf ? 32 : 20;
    const slices: SliceInfo[] = [];
    for (let i = 0; i < n; i++) {
      const at = 8 + i * entry;
      const cputype = b.readUInt32BE(at);
      const off = be === 0xcafebabf ? Number(b.readBigUInt64BE(at + 8)) : b.readUInt32BE(at + 8);
      const size = be === 0xcafebabf ? Number(b.readBigUInt64BE(at + 16)) : b.readUInt32BE(at + 12);
      slices.push(parseSlice(b.subarray(off, off + size), CPU[cputype] ?? `cpu-${cputype.toString(16)}`, off));
    }
    return { fat: true, slices };
  }
  return { fat: false, slices: [parseSlice(b, "", 0)] };
}

/** Hash bytes with a CodeDirectory's hash type, truncated to its slot size (for special-slot checks). */
export function slotHash(cd: CodeDirectoryInfo, data: Buffer): string {
  const h = hashFor(cd.hashType === "sha1" ? 1 : cd.hashType === "sha256" ? 2 : cd.hashType === "sha256-truncated" ? 3 : cd.hashType === "sha384" ? 4 : 0);
  if (!h.algo) return "";
  return createHash(h.algo).update(data).digest().subarray(0, cd.hashSize).toString("hex");
}
