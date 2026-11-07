import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * pyinstaller (item scope): a PyInstaller executable carries a CArchive whose cookie
 * (`MEI\014\013\012\013\016`, then package length, TOC offset/length and Python version, all
 * big-endian) sits at the END of the archive. The bootloader embeds the same magic as a constant it
 * searches for, so the cookie is located from the end (as PyInstaller and pyinstxtractor do), never by the
 * first occurrence. The TOC names the embedded modules; type `s` entries are the entry scripts.
 * pyinstxtractor plus a bytecode decompiler (pycdc/decompyle3) recover near-source Python.
 */

const MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]); // "MEI\014\013\012\013\016"
/** PyInstaller's own bootstrap and runtime-hook scripts: not the application's code. */
const INTERNAL = /^(?:pyiboot\d*_|pyi_rth_|pyimod\d*_|pyi_)/;

interface Cookie {
  at: number;
  pyvers: number;
  scripts: string[];
  modules: number;
}

function readCookie(b: Buffer): Cookie | null {
  const at = b.lastIndexOf(MAGIC);
  if (at < 0 || at + 24 > b.length) return null;
  const pkgLen = b.readUInt32BE(at + 8);
  const tocOff = b.readUInt32BE(at + 12);
  const tocLen = b.readUInt32BE(at + 16);
  const pyvers = b.readUInt32BE(at + 20);
  // PyInstaller >= 2.1 cookies are 88 bytes (with a 64-byte Python library name); 2.0 cookies are 24.
  const lib = at + 88 <= b.length ? b.toString("latin1", at + 24, at + 88) : "";
  const cookieSize = /python/i.test(lib) ? 88 : 24;
  const start = at + cookieSize - pkgLen;
  const scripts: string[] = [];
  let modules = 0;
  if (start >= 0 && tocLen > 0 && start + tocOff + tocLen <= b.length) {
    let p = start + tocOff;
    const end = p + tocLen;
    for (let i = 0; i < 100_000 && p + 18 <= end; i++) {
      const entrySize = b.readUInt32BE(p);
      if (entrySize < 18 || p + entrySize > end) break;
      const type = String.fromCharCode(b[p + 17]!);
      const name = b.toString("utf8", p + 18, p + entrySize).replace(/\0+$/, "");
      if (type === "s" && !INTERNAL.test(name) && scripts.length < 20) scripts.push(name);
      if (type === "m" || type === "M" || type === "z" || type === "Z") modules++;
      p += entrySize;
    }
  }
  return { at, pyvers, scripts, modules };
}

function pythonVersion(v: number): string {
  if (v >= 300 && v < 400) return `${Math.floor(v / 100)}.${v % 100}`; // 311 ⇒ 3.11
  if (v >= 20 && v < 40) return `${Math.floor(v / 10)}.${v % 10}`; // 27 ⇒ 2.7, 39 ⇒ 3.9
  return "";
}

export const pyinstaller: Analyzer = {
  id: "pyinstaller",
  title: "PyInstaller archive (.pyc entry scripts, Python version)",
  mirrorsRea: "PyInstaller extraction + .pyc decompilation",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    return ctx.scope === "item" && ctx.bytes.indexOf(MAGIC) >= 0;
  },

  profile(): ProfileTags {
    return { languages: ["Python"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes, complete } = ctx as ItemContext;
    const path = item.ref.path;
    const c = readCookie(bytes);
    if (!c) return [];
    const ver = pythonVersion(c.pyvers);
    const scripts = c.scripts.length ? `; entry script(s): ${c.scripts.slice(0, 5).join(", ")}` : "";
    return [
      {
        analyzerId: this.id,
        rubricId: "code/near-source-bytecode",
        title: "PyInstaller archive ships Python bytecode",
        recovers: `the application's Python code as .pyc bytecode${ver ? ` (Python ${ver})` : ""}${scripts}; pyinstxtractor plus a decompiler (pycdc/decompyle3) reconstruct near-source Python`,
        remediation: "Python ships as bytecode that decompiles readily and has no official obfuscation; move sensitive logic to a server or a compiled native extension (Cython/Nuitka raise the cost)",
        avoidable: false,
        path,
        coverage: complete ? "full" : "partial",
        detail: `${path}: CArchive cookie at 0x${c.at.toString(16)}${ver ? `, Python ${ver}` : ""}, ${c.modules} module/archive entr(y/ies)`,
      },
    ];
  },
};
