/**
 * Zero-dependency ELF reader (v0.8, exposure lane).
 *
 * Reads what `readelf -lhdS --notes` / `llvm-objdump -p -h` print: the file header, program headers,
 * section headers, the dynamic section (NEEDED, RUNPATH/RPATH, FLAGS, FLAGS_1, BIND_NOW), the static and
 * dynamic symbol tables (names, binding, definedness) and notes (GNU build-id, Go build id).
 * 32/64-bit and both byte orders. Every offset is bounds-checked; a damaged file yields `errors`,
 * never an exception, and every loop is capped.
 */

export const PT = { LOAD: 1, DYNAMIC: 2, INTERP: 3, NOTE: 4, GNU_EH_FRAME: 0x6474e550, GNU_STACK: 0x6474e551, GNU_RELRO: 0x6474e552, GNU_PROPERTY: 0x6474e553 } as const;
export const PF = { X: 1, W: 2, R: 4 } as const;
export const DT = { NULL: 0, NEEDED: 1, STRTAB: 5, STRSZ: 10, SONAME: 14, RPATH: 15, BIND_NOW: 24, RUNPATH: 29, FLAGS: 30, FLAGS_1: 0x6ffffffb } as const;
export const DF_BIND_NOW = 0x8;
export const DF_1_NOW = 0x1;
export const DF_1_PIE = 0x08000000;
export const EM = { CUDA: 190, AMDGPU: 224 } as const;

const TYPES: Record<number, string> = { 0: "none", 1: "relocatable", 2: "executable", 3: "shared-object", 4: "core" };
const MACHINES: Record<number, string> = { 3: "i386", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm", 62: "x86_64", 183: "aarch64", 190: "cuda", 224: "amdgpu", 243: "riscv", 247: "bpf", 258: "loongarch" };

export interface ElfSegment {
  readonly type: number;
  readonly flags: number;
  readonly offset: number;
  readonly vaddr: number;
  readonly filesz: number;
  readonly memsz: number;
}

export interface ElfSection {
  readonly name: string;
  readonly type: number;
  readonly flags: number;
  readonly addr: number;
  readonly offset: number;
  readonly size: number;
  readonly link: number;
  readonly entsize: number;
}

export interface ElfSymbol {
  readonly name: string;
  readonly bind: number; // 0 local, 1 global, 2 weak
  readonly type: number; // 0 notype, 1 object, 2 func, 3 section, 4 file
  readonly defined: boolean;
}

export interface ElfNote {
  readonly name: string;
  readonly type: number;
  readonly desc: Buffer;
}

export interface ElfInfo {
  readonly is64: boolean;
  readonly le: boolean;
  readonly type: number;
  readonly typeName: string;
  readonly machine: number;
  readonly machineName: string;
  readonly segments: readonly ElfSegment[];
  readonly sections: readonly ElfSection[];
  readonly interp?: string;
  readonly needed: readonly string[];
  readonly runpath: readonly string[];
  readonly rpath: readonly string[];
  readonly soname?: string;
  /** DT_FLAGS and DT_FLAGS_1 (0 when absent); `bindNow` folds in DT_BIND_NOW. */
  readonly dtFlags: number;
  readonly dtFlags1: number;
  readonly bindNow: boolean;
  readonly hasDynamic: boolean;
  readonly symtab: readonly ElfSymbol[];
  readonly dynsym: readonly ElfSymbol[];
  readonly notes: readonly ElfNote[];
  readonly errors: readonly string[];
}

export function looksLikeElf(b: Buffer): boolean {
  return b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 && (b[4] === 1 || b[4] === 2) && (b[5] === 1 || b[5] === 2);
}

const MAX_TABLE = 1_000_000;
const MAX_SYMBOLS = 2_000_000;

/** Parse an ELF file. Throws only when the bytes are not ELF at all. */
export function readElf(b: Buffer): ElfInfo {
  if (!looksLikeElf(b)) throw new RangeError("not an ELF file");
  const is64 = b[4] === 2;
  const le = b[5] === 1;
  const errors: string[] = [];
  const ok = (o: number, n: number) => o >= 0 && n >= 0 && o + n <= b.length;
  const u16 = (o: number) => (ok(o, 2) ? (le ? b.readUInt16LE(o) : b.readUInt16BE(o)) : 0);
  const u32 = (o: number) => (ok(o, 4) ? (le ? b.readUInt32LE(o) : b.readUInt32BE(o)) : 0);
  const u64 = (o: number) => (ok(o, 8) ? Number(le ? b.readBigUInt64LE(o) : b.readBigUInt64BE(o)) : 0);
  const uN = (o: number) => (is64 ? u64(o) : u32(o));
  const cstr = (buf: Buffer, at: number) => {
    if (at < 0 || at >= buf.length) return "";
    const end = buf.indexOf(0, at);
    return buf.toString("utf8", at, end === -1 ? buf.length : Math.min(end, at + 4096));
  };

  const type = u16(16);
  const machine = u16(18);
  const phoff = uN(is64 ? 0x20 : 0x1c);
  const shoff = uN(is64 ? 0x28 : 0x20);
  const phentsize = u16(is64 ? 0x36 : 0x2a);
  let phnum = u16(is64 ? 0x38 : 0x2c);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  let shnum = u16(is64 ? 0x3c : 0x30);
  let shstrndx = u16(is64 ? 0x3e : 0x32);

  // ---- sections (read first: extended numbering may hold phnum / shnum / shstrndx in section 0)
  const sections: ElfSection[] = [];
  const shMin = is64 ? 64 : 40;
  const rawSh = (i: number) => {
    const o = shoff + i * shentsize;
    return {
      nameOff: u32(o),
      type: u32(o + 4),
      flags: is64 ? u64(o + 8) : u32(o + 8),
      addr: is64 ? u64(o + 16) : u32(o + 12),
      offset: is64 ? u64(o + 24) : u32(o + 16),
      size: is64 ? u64(o + 32) : u32(o + 20),
      link: u32(is64 ? o + 40 : o + 24),
      info: u32(is64 ? o + 44 : o + 28),
      entsize: is64 ? u64(o + 56) : u32(o + 36),
    };
  };
  if (shoff !== 0) {
    if (shentsize < shMin || !ok(shoff, shentsize)) errors.push("section header table outside the file");
    else {
      const s0 = rawSh(0);
      if (shnum === 0) shnum = s0.size;
      if (shstrndx === 0xffff) shstrndx = s0.link;
      if (phnum === 0xffff) phnum = s0.info;
      if (shnum > MAX_TABLE || !ok(shoff, shnum * shentsize)) errors.push("section header table outside the file");
      else {
        const raws = Array.from({ length: shnum }, (_, i) => rawSh(i));
        const strSec = raws[shstrndx];
        const names = strSec && ok(strSec.offset, strSec.size) && strSec.type !== 8 ? b.subarray(strSec.offset, strSec.offset + strSec.size) : null;
        if (!names && shnum > 0) errors.push("section name table outside the file");
        for (const r of raws) sections.push({ name: names ? cstr(names, r.nameOff) : "", type: r.type, flags: r.flags, addr: r.addr, offset: r.offset, size: r.size, link: r.link, entsize: r.entsize });
      }
    }
  }

  // ---- program headers
  const segments: ElfSegment[] = [];
  const phMin = is64 ? 56 : 32;
  if (phoff !== 0 && phnum > 0) {
    if (phentsize < phMin || phnum > MAX_TABLE || !ok(phoff, phnum * phentsize)) errors.push("program header table outside the file");
    else
      for (let i = 0; i < phnum; i++) {
        const o = phoff + i * phentsize;
        segments.push(
          is64
            ? { type: u32(o), flags: u32(o + 4), offset: u64(o + 8), vaddr: u64(o + 16), filesz: u64(o + 32), memsz: u64(o + 40) }
            : { type: u32(o), offset: u32(o + 4), vaddr: u32(o + 8), filesz: u32(o + 16), memsz: u32(o + 20), flags: u32(o + 24) },
        );
      }
  }

  const vaddrToOffset = (va: number): number => {
    for (const s of segments) if (s.type === PT.LOAD && va >= s.vaddr && va < s.vaddr + s.filesz) return va - s.vaddr + s.offset;
    for (const s of sections) if (s.addr !== 0 && s.type !== 8 && va >= s.addr && va < s.addr + s.size) return va - s.addr + s.offset;
    return -1;
  };

  // ---- interpreter
  let interp: string | undefined;
  const pInterp = segments.find((s) => s.type === PT.INTERP);
  if (pInterp && ok(pInterp.offset, pInterp.filesz)) interp = cstr(b.subarray(pInterp.offset, pInterp.offset + pInterp.filesz), 0);

  // ---- dynamic section (PT_DYNAMIC, else SHT_DYNAMIC)
  const needed: string[] = [];
  const runpath: string[] = [];
  const rpath: string[] = [];
  let soname: string | undefined;
  let dtFlags = 0;
  let dtFlags1 = 0;
  let bindNowTag = false;
  const pDyn = segments.find((s) => s.type === PT.DYNAMIC);
  const sDyn = sections.find((s) => s.type === 6);
  const dynOff = pDyn ? pDyn.offset : sDyn ? sDyn.offset : -1;
  const dynSize = pDyn ? pDyn.filesz : sDyn ? sDyn.size : 0;
  const hasDynamic = dynOff >= 0 && dynSize > 0;
  if (hasDynamic) {
    if (!ok(dynOff, dynSize)) errors.push("dynamic section outside the file");
    else {
      const ent = is64 ? 16 : 8;
      const tags: [number, number][] = [];
      for (let o = dynOff; o + ent <= dynOff + dynSize && tags.length < MAX_TABLE; o += ent) {
        const tag = is64 ? u64(o) : u32(o);
        const val = is64 ? u64(o + 8) : u32(o + 4);
        if (tag === DT.NULL) break;
        tags.push([tag, val]);
      }
      const strtabVa = tags.find(([t]) => t === DT.STRTAB)?.[1];
      const strsz = tags.find(([t]) => t === DT.STRSZ)?.[1] ?? 0;
      let dynstr: Buffer | null = null;
      if (strtabVa !== undefined) {
        const off = vaddrToOffset(strtabVa);
        if (off >= 0 && ok(off, Math.min(strsz || b.length - off, b.length - off))) dynstr = b.subarray(off, off + Math.min(strsz || b.length - off, b.length - off));
      }
      if (!dynstr && sDyn) {
        const linked = sections[sDyn.link];
        if (linked && ok(linked.offset, linked.size)) dynstr = b.subarray(linked.offset, linked.offset + linked.size);
      }
      const str = (v: number) => (dynstr ? cstr(dynstr, v) : "");
      for (const [tag, val] of tags) {
        if (tag === DT.NEEDED) needed.push(str(val));
        else if (tag === DT.RUNPATH) runpath.push(...str(val).split(":").filter(Boolean));
        else if (tag === DT.RPATH) rpath.push(...str(val).split(":").filter(Boolean));
        else if (tag === DT.SONAME) soname = str(val);
        else if (tag === DT.FLAGS) dtFlags = val;
        else if (tag === DT.FLAGS_1) dtFlags1 = val;
        else if (tag === DT.BIND_NOW) bindNowTag = true;
      }
      if (!dynstr && tags.some(([t]) => t === DT.NEEDED || t === DT.RUNPATH || t === DT.RPATH)) errors.push("dynamic string table not found");
    }
  }

  // ---- symbol tables
  const readSyms = (sec: ElfSection): ElfSymbol[] => {
    const out: ElfSymbol[] = [];
    const strSec = sections[sec.link];
    const ent = sec.entsize || (is64 ? 24 : 16);
    if (!strSec || !ok(sec.offset, sec.size) || !ok(strSec.offset, strSec.size) || ent < (is64 ? 24 : 16)) {
      errors.push(`symbol table ${sec.name || sec.type} outside the file`);
      return out;
    }
    const strtab = b.subarray(strSec.offset, strSec.offset + strSec.size);
    const count = Math.min(Math.floor(sec.size / ent), MAX_SYMBOLS);
    for (let i = 1; i < count; i++) {
      const o = sec.offset + i * ent;
      const name = cstr(strtab, u32(o));
      const info = is64 ? b[o + 4]! : b[o + 12]!;
      const shndx = is64 ? u16(o + 6) : u16(o + 14);
      out.push({ name, bind: info >> 4, type: info & 0xf, defined: shndx !== 0 });
    }
    return out;
  };
  const symSec = sections.find((s) => s.type === 2);
  const dynSec = sections.find((s) => s.type === 11);
  const symtab = symSec ? readSyms(symSec) : [];
  const dynsym = dynSec ? readSyms(dynSec) : [];

  // ---- notes (PT_NOTE segments, else SHT_NOTE sections)
  const notes: ElfNote[] = [];
  const noteAreas: { offset: number; size: number }[] = segments.filter((s) => s.type === PT.NOTE).map((s) => ({ offset: s.offset, size: s.filesz }));
  if (noteAreas.length === 0) for (const s of sections) if (s.type === 7) noteAreas.push({ offset: s.offset, size: s.size });
  for (const a of noteAreas) {
    if (!ok(a.offset, a.size)) continue;
    let o = a.offset;
    while (o + 12 <= a.offset + a.size && notes.length < 256) {
      const namesz = u32(o);
      const descsz = u32(o + 4);
      const ntype = u32(o + 8);
      const nameAt = o + 12;
      const descAt = nameAt + ((namesz + 3) & ~3);
      const next = descAt + ((descsz + 3) & ~3);
      if (namesz > 4096 || descsz > 1 << 20 || next > a.offset + a.size || next <= o) break;
      notes.push({ name: b.toString("latin1", nameAt, nameAt + namesz).replace(/\0+$/, ""), type: ntype, desc: b.subarray(descAt, descAt + descsz) });
      o = next;
    }
  }

  return {
    is64,
    le,
    type,
    typeName: TYPES[type] ?? `type-${type}`,
    machine,
    machineName: MACHINES[machine] ?? `machine-${machine}`,
    segments,
    sections,
    ...(interp !== undefined ? { interp } : {}),
    needed,
    runpath,
    rpath,
    ...(soname !== undefined ? { soname } : {}),
    dtFlags,
    dtFlags1,
    bindNow: bindNowTag || (dtFlags & DF_BIND_NOW) !== 0 || (dtFlags1 & DF_1_NOW) !== 0,
    hasDynamic,
    symtab,
    dynsym,
    notes,
    errors,
  };
}

export function elfSection(b: Buffer, info: ElfInfo, name: string): Buffer | null {
  const s = info.sections.find((x) => x.name === name);
  if (!s || s.type === 8 || s.offset + s.size > b.length) return null;
  return b.subarray(s.offset, s.offset + s.size);
}

export interface ElfHardening {
  /** "pie" (position-independent executable), "no-pie" (ET_EXEC), "dso" (shared object: PIE does not apply), "n/a". */
  readonly pie: "pie" | "no-pie" | "dso" | "n/a";
  /** PT_GNU_STACK without PF_X; "missing" when there is no PT_GNU_STACK (the loader default applies). */
  readonly nx: "enabled" | "disabled" | "missing";
  readonly relro: "full" | "partial" | "none" | "static";
  readonly canary: boolean;
  readonly fortify: boolean;
  readonly stripped: boolean;
  readonly buildId?: string;
}

/** checksec-style hardening facts, defined to agree with `llvm-objdump -p` program headers and dynamic section. */
export function elfHardening(e: ElfInfo): ElfHardening {
  const stack = e.segments.find((s) => s.type === PT.GNU_STACK);
  const relroSeg = e.segments.some((s) => s.type === PT.GNU_RELRO);
  const isExecLike = e.type === 2 || (e.type === 3 && (e.interp !== undefined || (e.dtFlags1 & DF_1_PIE) !== 0));
  const pie = e.type === 2 ? "no-pie" : e.type === 3 ? (isExecLike ? "pie" : "dso") : "n/a";
  const names = new Set<string>();
  for (const s of e.dynsym) names.add(s.name);
  for (const s of e.symtab) names.add(s.name);
  const canary = names.has("__stack_chk_fail") || names.has("__stack_chk_guard") || names.has("__stack_chk_fail_local") || names.has("__intel_security_cookie");
  let fortify = false;
  for (const n of names) if (/^__\w+_chk$/.test(n) && !n.startsWith("__stack_chk")) { fortify = true; break; }
  const gnu = e.notes.find((n) => n.name === "GNU" && n.type === 3);
  return {
    pie,
    nx: !stack ? "missing" : (stack.flags & PF.X) !== 0 ? "disabled" : "enabled",
    relro: !e.hasDynamic ? "static" : relroSeg ? (e.bindNow ? "full" : "partial") : "none",
    canary,
    fortify,
    stripped: !e.sections.some((s) => s.type === 2),
    ...(gnu ? { buildId: gnu.desc.toString("hex") } : {}),
  };
}
