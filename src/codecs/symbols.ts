import { DecodeError } from "./xz.js";
import { looksLikeMachO, machOSlices } from "./macho.js";

/**
 * Native debug-information and symbol facts (v0.7, reverse-engineering aids).
 *
 * What a release binary still carries that a reverse engineer would otherwise have to reconstruct:
 * - **Embedded DWARF**: `__DWARF` segment / `__debug_*` sections (Mach-O), `.debug_*` / `.zdebug_*` (ELF).
 * - **Mach-O debug map (stabs)**: `N_OSO` entries name every object file the binary was linked from
 *   (absolute build paths, usually including a user name), `N_SO` entries name source files,
 *   `N_FUN` entries name functions. `dsymutil` reads these to build a dSYM; `strip -S` removes them.
 * - **Local symbols**: names of non-exported functions and data. Exported symbols are needed for
 *   dynamic linking and are not counted; `strip -x` (or `strip`) removes the locals.
 * - **ELF `.symtab`**: present in an unstripped ELF (a stripped one keeps only `.dynsym`), including
 *   `STT_FILE` source-file names and `STB_LOCAL` function/object names.
 *
 * Counts are defined to agree with `nm -a` (Mach-O) and `llvm-objdump -t -h` (ELF); see test/v07.test.ts.
 */

export interface NativeSliceFacts {
  readonly format: "macho" | "elf";
  readonly arch: string;
  readonly filetype: string;
  /** Embedded debug-information section names (`__DWARF,__debug_info`, `.debug_info`, …). */
  readonly debugSections: readonly string[];
  /** Mach-O symbolic-debugging (stab) entries; 0 for ELF. */
  readonly stabs: number;
  /** Object files named by N_OSO stabs (the debug map): absolute build paths. */
  readonly debugMapObjects: readonly string[];
  /** Source files named by N_SO stabs (Mach-O) or STT_FILE symbols (ELF). */
  readonly sourceFiles: readonly string[];
  /** Non-exported, defined function/data symbols. */
  readonly localSymbols: number;
  /** Up to 10 local symbol names, for the report. */
  readonly localSample: readonly string[];
  /** ELF only: a `.symtab` section is present. */
  readonly hasSymtab: boolean;
  readonly error?: string;
}

export function looksLikeElf(b: Buffer): boolean {
  return b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 && (b[4] === 1 || b[4] === 2) && (b[5] === 1 || b[5] === 2);
}

export function isNativeBinary(b: Buffer): boolean {
  return looksLikeMachO(b) || looksLikeElf(b);
}

const cstr = (b: Buffer, at: number, max = b.length) => {
  if (at < 0 || at >= b.length) return "";
  const end = b.indexOf(0, at);
  return b.toString("utf8", at, Math.min(end === -1 ? b.length : end, max));
};
const fixed = (b: Buffer, at: number, n: number) => cstr(b.subarray(at, at + n), 0);

/** `__mh_execute_header` and friends are kept by the linker for dyld; they are not an aid. */
const LINKER_HEADER = /^__mh_\w+_header$/;
const MH_FILETYPES: Record<number, string> = { 1: "object", 2: "execute", 6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dsym", 11: "kext" };

const N_STAB = 0xe0;
const N_TYPE = 0x0e;
const N_EXT = 0x01;
const N_SECT = 0x0e;
const N_OSO = 0x66;
const N_SO = 0x64;

function machoSlice(s: Buffer, arch: string): NativeSliceFacts {
  const base = { format: "macho" as const, arch, hasSymtab: false };
  const empty = { debugSections: [], stabs: 0, debugMapObjects: [], sourceFiles: [], localSymbols: 0, localSample: [] };
  if (s.length < 32) return { ...base, filetype: "unknown", ...empty, error: "slice truncated" };
  const magic = s.readUInt32LE(0);
  const is64 = magic === 0xfeedfacf;
  if (!is64 && magic !== 0xfeedface) return { ...base, filetype: "unknown", ...empty, error: "not a little-endian Mach-O slice" };
  const filetype = MH_FILETYPES[s.readUInt32LE(12)] ?? `type-${s.readUInt32LE(12)}`;
  const ncmds = s.readUInt32LE(16);
  const debugSections: string[] = [];
  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | null = null;
  let p = is64 ? 32 : 28;
  for (let i = 0; i < ncmds; i++) {
    if (p + 8 > s.length) return { ...base, filetype, ...empty, error: "load commands truncated" };
    const cmd = s.readUInt32LE(p);
    const size = s.readUInt32LE(p + 4);
    if (size < 8 || p + size > s.length) return { ...base, filetype, ...empty, error: "load command size invalid" };
    if (cmd === 0x19 || cmd === 0x1) {
      const seg = fixed(s, p + 8, 16);
      const nsects = s.readUInt32LE(p + (cmd === 0x19 ? 64 : 48));
      const first = p + (cmd === 0x19 ? 72 : 56);
      const step = cmd === 0x19 ? 80 : 68;
      for (let k = 0; k < nsects && first + (k + 1) * step <= p + size; k++) {
        const sect = fixed(s, first + k * step, 16);
        const sseg = fixed(s, first + k * step + 16, 16);
        if (seg === "__DWARF" || /^__z?debug_/.test(sect)) debugSections.push(`${sseg || seg},${sect}`);
      }
    } else if (cmd === 0x2) {
      symtab = { symoff: s.readUInt32LE(p + 8), nsyms: s.readUInt32LE(p + 12), stroff: s.readUInt32LE(p + 16), strsize: s.readUInt32LE(p + 20) };
    }
    p += size;
  }
  let stabs = 0;
  let localSymbols = 0;
  const oso = new Set<string>();
  const so = new Set<string>();
  const sample: string[] = [];
  if (symtab) {
    const ent = is64 ? 16 : 12;
    if (symtab.symoff + symtab.nsyms * ent > s.length || symtab.stroff + symtab.strsize > s.length)
      return { ...base, filetype, debugSections, stabs: 0, debugMapObjects: [], sourceFiles: [], localSymbols: 0, localSample: [], error: "symbol table outside the file" };
    const strtab = s.subarray(symtab.stroff, symtab.stroff + symtab.strsize);
    for (let i = 0; i < symtab.nsyms; i++) {
      const at = symtab.symoff + i * ent;
      const strx = s.readUInt32LE(at);
      const type = s[at + 4]!;
      if (type & N_STAB) {
        stabs++;
        if (type === N_OSO || type === N_SO) {
          const name = cstr(strtab, strx);
          if (name) (type === N_OSO ? oso : so).add(name);
        }
        continue;
      }
      if ((type & N_EXT) === 0 && (type & N_TYPE) === N_SECT) {
        const name = cstr(strtab, strx);
        if (LINKER_HEADER.test(name)) continue;
        localSymbols++;
        if (sample.length < 10 && name) sample.push(name);
      }
    }
  }
  // N_SO entries come in (directory, file) pairs; report the files (a trailing "/" marks a directory).
  const sourceFiles = [...so].filter((n) => !n.endsWith("/"));
  return { ...base, filetype, debugSections, stabs, debugMapObjects: [...oso], sourceFiles, localSymbols, localSample: sample };
}

const ELF_TYPES: Record<number, string> = { 1: "relocatable", 2: "executable", 3: "shared-object", 4: "core" };
const ELF_MACHINES: Record<number, string> = { 3: "i386", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv" };

function elf(b: Buffer): NativeSliceFacts {
  const is64 = b[4] === 2;
  const le = b[5] === 1;
  const u16 = (o: number) => (le ? b.readUInt16LE(o) : b.readUInt16BE(o));
  const u32 = (o: number) => (le ? b.readUInt32LE(o) : b.readUInt32BE(o));
  const uN = (o: number) => (is64 ? Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o)) : u32(o));
  const filetype = ELF_TYPES[u16(16)] ?? `type-${u16(16)}`;
  const arch = ELF_MACHINES[u16(18)] ?? `machine-${u16(18)}`;
  const base = { format: "elf" as const, arch, filetype, stabs: 0, debugMapObjects: [] as string[] };
  const shoff = uN(is64 ? 0x28 : 0x20);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  let shnum = u16(is64 ? 0x3c : 0x30);
  let shstrndx = u16(is64 ? 0x3e : 0x32);
  const fail = (error: string): NativeSliceFacts => ({ ...base, debugSections: [], sourceFiles: [], localSymbols: 0, localSample: [], hasSymtab: false, error });
  if (shoff === 0) return fail("no section header table (sections cannot be inspected)");
  if (shentsize < (is64 ? 64 : 40) || shoff + shentsize > b.length) return fail("section header table outside the file");
  // Extended numbering: the real count / string-table index live in section 0.
  const sh = (i: number) => {
    const o = shoff + i * shentsize;
    return {
      name: u32(o),
      type: u32(o + 4),
      offset: uN(is64 ? o + 24 : o + 16),
      size: uN(is64 ? o + 32 : o + 20),
      link: u32(is64 ? o + 40 : o + 24),
      entsize: uN(is64 ? o + 56 : o + 36),
    };
  };
  if (shnum === 0) shnum = sh(0).size;
  if (shstrndx === 0xffff) shstrndx = sh(0).link;
  if (shoff + shnum * shentsize > b.length) return fail("section header table outside the file");
  const sections = Array.from({ length: shnum }, (_, i) => sh(i));
  const strSec = sections[shstrndx];
  if (!strSec || strSec.offset + strSec.size > b.length) return fail("section name table outside the file");
  const names = b.subarray(strSec.offset, strSec.offset + strSec.size);
  const debugSections: string[] = [];
  let symtabIdx = -1;
  sections.forEach((s, i) => {
    const n = cstr(names, s.name);
    if (/^\.z?debug_/.test(n)) debugSections.push(n);
    if (s.type === 2 && symtabIdx === -1) symtabIdx = i; // SHT_SYMTAB
  });
  const files = new Set<string>();
  const sample: string[] = [];
  let localSymbols = 0;
  if (symtabIdx !== -1) {
    const st = sections[symtabIdx]!;
    const str = sections[st.link];
    const ent = is64 ? 24 : 16;
    if (!str || st.offset + st.size > b.length || str.offset + str.size > b.length) return { ...fail("symbol table outside the file"), debugSections, hasSymtab: true };
    const strtab = b.subarray(str.offset, str.offset + str.size);
    const count = Math.floor(st.size / (st.entsize || ent));
    for (let i = 1; i < count; i++) {
      const o = st.offset + i * (st.entsize || ent);
      const name = cstr(strtab, u32(o));
      const info = is64 ? b[o + 4]! : b[o + 12]!;
      const shndx = is64 ? u16(o + 6) : u16(o + 14);
      const bind = info >> 4;
      const type = info & 0xf;
      if (type === 4 && name) files.add(name); // STT_FILE
      if (bind === 0 && (type === 1 || type === 2) && shndx !== 0 && name) {
        localSymbols++;
        if (sample.length < 10) sample.push(name);
      }
    }
  }
  return { ...base, debugSections, sourceFiles: [...files], localSymbols, localSample: sample, hasSymtab: symtabIdx !== -1 };
}

/** Debug and symbol facts for every slice of a Mach-O or ELF file. Throws DecodeError for anything else. */
export function readNativeSymbols(b: Buffer): NativeSliceFacts[] {
  if (looksLikeElf(b)) {
    try {
      return [elf(b)];
    } catch (e) {
      return [{ format: "elf", arch: "unknown", filetype: "unknown", debugSections: [], stabs: 0, debugMapObjects: [], sourceFiles: [], localSymbols: 0, localSample: [], hasSymtab: false, error: (e as Error).message }];
    }
  }
  if (!looksLikeMachO(b)) throw new DecodeError("not a Mach-O or ELF file");
  return machOSlices(b).map(({ arch, buf }) => {
    try {
      return machoSlice(buf, arch);
    } catch (e) {
      return { format: "macho" as const, arch, filetype: "unknown", debugSections: [], stabs: 0, debugMapObjects: [], sourceFiles: [], localSymbols: 0, localSample: [], hasSymtab: false, error: (e as Error).message };
    }
  });
}
