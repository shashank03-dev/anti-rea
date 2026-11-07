/**
 * Zero-dependency PE (Portable Executable) reader (v0.8, exposure lane).
 *
 * Reads what `llvm-objdump -p` / `dumpbin /headers` print for a Windows binary: the COFF header, the
 * optional header's `DllCharacteristics` (ASLR / DEP / CFG / high-entropy ASLR), the data directories
 * (debug, imports, CLR, security), the CodeView debug entry (RSDS → PDB GUID, age and build path), the
 * imported DLL names and whether an Authenticode certificate table is present. This also closes the
 * README gap "no PE debug-directory parsing" for the exposure report; the gated `aids` lane is unchanged.
 *
 * 32- and 64-bit. Every RVA and offset is bounds-checked and every loop is capped; a damaged file yields
 * `errors`, never an exception.
 */

export const DLLCHAR = {
  HIGH_ENTROPY_VA: 0x0020,
  DYNAMIC_BASE: 0x0040, // ASLR
  FORCE_INTEGRITY: 0x0080,
  NX_COMPAT: 0x0100, // DEP
  NO_SEH: 0x0400,
  GUARD_CF: 0x4000, // Control Flow Guard
} as const;

const MACHINE: Record<number, string> = { 0x14c: "i386", 0x8664: "x86_64", 0x1c0: "arm", 0xaa64: "arm64", 0x1c4: "armnt", 0x200: "ia64" };
const SUBSYSTEM: Record<number, string> = { 1: "native", 2: "gui", 3: "console", 9: "wince-gui", 16: "efi-application" };

export interface PeDebugInfo {
  readonly type: number;
  /** CodeView RSDS: the PDB path recorded at link time (absolute build path + project name). */
  readonly pdbPath?: string;
  readonly guid?: string;
  readonly age?: number;
}

export interface PeInfo {
  readonly machine: number;
  readonly machineName: string;
  readonly is64: boolean;
  readonly characteristics: number;
  readonly dll: boolean; // IMAGE_FILE_DLL
  readonly subsystem: number;
  readonly subsystemName: string;
  readonly dllCharacteristics: number;
  readonly aslr: boolean;
  readonly highEntropyAslr: boolean;
  readonly nxCompat: boolean;
  readonly guardCf: boolean;
  readonly forceIntegrity: boolean;
  /** A CLR (COM descriptor, data directory 14) is present ⇒ this is a managed .NET assembly. */
  readonly clr: boolean;
  /** An Authenticode certificate table (data directory 4) is present (presence only; chain not validated). */
  readonly authenticode: boolean;
  readonly debug: readonly PeDebugInfo[];
  /**
   * Section names, with COFF long names ("/<offset>" into the string table) resolved. MinGW and Go write
   * DWARF as `.debug_*` sections (Go: zlib-compressed `.zdebug_*`), whose names need the string table.
   */
  readonly sectionNames: readonly string[];
  /** COFF symbol-table entries (NumberOfSymbols). Images normally carry none; MinGW and Go keep them unless stripped. */
  readonly symbolCount: number;
  readonly imports: readonly string[];
  readonly errors: readonly string[];
}

export function looksLikePe(b: Buffer): boolean {
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return false; // "MZ"
  const pe = b.readUInt32LE(0x3c);
  return pe + 24 <= b.length && b.readUInt32LE(pe) === 0x00004550; // "PE\0\0"
}

const MAX = 4096;

export function readPe(b: Buffer): PeInfo {
  if (!looksLikePe(b)) throw new RangeError("not a PE file");
  const errors: string[] = [];
  const ok = (o: number, n: number) => o >= 0 && n >= 0 && o + n <= b.length;
  const u16 = (o: number) => (ok(o, 2) ? b.readUInt16LE(o) : 0);
  const u32 = (o: number) => (ok(o, 4) ? b.readUInt32LE(o) : 0);
  const cstr = (at: number, cap = 4096) => {
    if (at < 0 || at >= b.length) return "";
    const end = b.indexOf(0, at);
    return b.toString("utf8", at, end === -1 ? Math.min(b.length, at + cap) : Math.min(end, at + cap));
  };

  const pe = u32(0x3c);
  const coff = pe + 4;
  const machine = u16(coff);
  const numSections = u16(coff + 2);
  const sizeOptional = u16(coff + 16);
  const characteristics = u16(coff + 18);
  const opt = coff + 20;
  const magic = u16(opt);
  const is64 = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) errors.push(`unknown optional header magic 0x${magic.toString(16)}`);
  const subsystem = u16(opt + 68);
  const dllCharacteristics = u16(opt + 70);
  const numDirs = is64 ? u32(opt + 108) : u32(opt + 92);
  const dirBase = is64 ? opt + 112 : opt + 96;
  const dir = (i: number): { rva: number; size: number } => (i < numDirs && i < 16 ? { rva: u32(dirBase + i * 8), size: u32(dirBase + i * 8 + 4) } : { rva: 0, size: 0 });

  // sections (for RVA → file offset)
  const secStart = opt + sizeOptional;
  const sections: { rva: number; vsize: number; raw: number; rawSize: number }[] = [];
  const sectionNames: string[] = [];
  // COFF string table: immediately after the symbol table (PointerToSymbolTable + 18 * NumberOfSymbols).
  const symPtr = u32(coff + 8);
  const strTab = symPtr > 0 ? symPtr + u32(coff + 12) * 18 : 0;
  for (let i = 0; i < Math.min(numSections, 96); i++) {
    const o = secStart + i * 40;
    if (!ok(o, 40)) break;
    sections.push({ rva: u32(o + 12), vsize: u32(o + 8), raw: u32(o + 20), rawSize: u32(o + 16) });
    const raw8 = b.subarray(o, o + 8);
    const nul = raw8.indexOf(0);
    let name = raw8.toString("latin1", 0, nul === -1 ? 8 : nul);
    if (/^\/\d+$/.test(name) && strTab > 0) {
      const at = strTab + Number(name.slice(1));
      if (ok(at, 1)) name = cstr(at, 256);
    }
    sectionNames.push(name);
  }
  const toOffset = (rva: number): number => {
    for (const s of sections) if (rva >= s.rva && rva < s.rva + Math.max(s.vsize, s.rawSize)) return rva - s.rva + s.raw;
    return -1;
  };

  // debug directory (type 2 = CODEVIEW → RSDS)
  const debug: PeDebugInfo[] = [];
  const dbg = dir(6);
  if (dbg.rva && dbg.size) {
    const off = toOffset(dbg.rva);
    const count = Math.min(Math.floor(dbg.size / 28), 64);
    if (off >= 0)
      for (let i = 0; i < count; i++) {
        const o = off + i * 28;
        if (!ok(o, 28)) break;
        const type = u32(o + 12);
        const dataOff = u32(o + 24); // PointerToRawData (file offset)
        const entry: { type: number; pdbPath?: string; guid?: string; age?: number } = { type };
        if (type === 2 && ok(dataOff, 24) && b.toString("latin1", dataOff, dataOff + 4) === "RSDS") {
          // GUID: first three fields little-endian, last two big-endian (registry format). Copy before
          // reversing: subarray() shares memory, and the input buffer must never be mutated.
          const g = Buffer.from(b.subarray(dataOff + 4, dataOff + 20));
          entry.guid =
            Buffer.from(g.subarray(0, 4)).reverse().toString("hex") +
            Buffer.from(g.subarray(4, 6)).reverse().toString("hex") +
            Buffer.from(g.subarray(6, 8)).reverse().toString("hex") +
            g.subarray(8, 16).toString("hex");
          entry.age = u32(dataOff + 20);
          entry.pdbPath = cstr(dataOff + 24);
        }
        debug.push(entry);
      }
  }

  // imports (DLL names)
  const imports: string[] = [];
  const imp = dir(1);
  if (imp.rva && imp.size) {
    const off = toOffset(imp.rva);
    if (off >= 0)
      for (let i = 0; i < MAX; i++) {
        const o = off + i * 20;
        if (!ok(o, 20)) break;
        const nameRva = u32(o + 12);
        const origThunk = u32(o);
        if (nameRva === 0 && origThunk === 0 && u32(o + 16) === 0) break; // null terminator
        const nameOff = toOffset(nameRva);
        if (nameOff >= 0) {
          const name = cstr(nameOff, 256);
          if (name) imports.push(name);
        }
      }
  }

  return {
    machine,
    machineName: MACHINE[machine] ?? `machine-0x${machine.toString(16)}`,
    is64,
    characteristics,
    dll: (characteristics & 0x2000) !== 0,
    subsystem,
    subsystemName: SUBSYSTEM[subsystem] ?? `subsystem-${subsystem}`,
    dllCharacteristics,
    aslr: (dllCharacteristics & DLLCHAR.DYNAMIC_BASE) !== 0,
    highEntropyAslr: (dllCharacteristics & DLLCHAR.HIGH_ENTROPY_VA) !== 0,
    nxCompat: (dllCharacteristics & DLLCHAR.NX_COMPAT) !== 0,
    guardCf: (dllCharacteristics & DLLCHAR.GUARD_CF) !== 0,
    forceIntegrity: (dllCharacteristics & DLLCHAR.FORCE_INTEGRITY) !== 0,
    clr: dir(14).rva !== 0 && dir(14).size !== 0,
    authenticode: dir(4).rva !== 0 && dir(4).size > 8,
    debug,
    sectionNames,
    symbolCount: symPtr > 0 && ok(symPtr, 1) ? u32(coff + 12) : 0,
    imports,
    errors,
  };
}

/** CLR (COM descriptor, data directory 14) RVA+size for the .NET analyzer, without re-reading headers. */
export function clrDirectory(b: Buffer): { rva: number; size: number } | null {
  if (!looksLikePe(b)) return null;
  const pe = b.readUInt32LE(0x3c);
  const opt = pe + 24;
  if (opt + 112 > b.length) return null;
  const is64 = b.readUInt16LE(opt) === 0x20b;
  const numDirs = is64 ? b.readUInt32LE(opt + 108) : b.readUInt32LE(opt + 92);
  const dirBase = is64 ? opt + 112 : opt + 96;
  if (numDirs <= 14) return null;
  const o = dirBase + 14 * 8;
  if (o + 8 > b.length) return null;
  const rva = b.readUInt32LE(o);
  const size = b.readUInt32LE(o + 4);
  return rva ? { rva, size } : null;
}

/** Resolve a CLR-header RVA to a file offset using the section table (for the .NET metadata root). */
export function rvaToOffset(b: Buffer, rva: number): number {
  if (!looksLikePe(b)) return -1;
  const pe = b.readUInt32LE(0x3c);
  const coff = pe + 4;
  if (coff + 20 > b.length) return -1;
  const numSections = b.readUInt16LE(coff + 2);
  const sizeOptional = b.readUInt16LE(coff + 16);
  const secStart = pe + 24 + sizeOptional;
  for (let i = 0; i < Math.min(numSections, 96); i++) {
    const o = secStart + i * 40;
    if (o + 40 > b.length) break;
    const secRva = b.readUInt32LE(o + 12);
    const vsize = b.readUInt32LE(o + 8);
    const raw = b.readUInt32LE(o + 20);
    const rawSize = b.readUInt32LE(o + 16);
    if (rva >= secRva && rva < secRva + Math.max(vsize, rawSize)) return rva - secRva + raw;
  }
  return -1;
}
