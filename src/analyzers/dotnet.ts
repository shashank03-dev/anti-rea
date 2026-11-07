import { clrDirectory, looksLikePe, readPe, rvaToOffset } from "../codecs/pe.js";
import { shannonEntropy } from "../util/entropy.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * dotnet (item scope): what a REA tool recovers from a managed .NET assembly. CIL decompiles back to
 * near-source C#/F# with ILSpy or dnSpy, so a managed assembly that ships IL in the clear is a code
 * recoverability finding. Reads the CLR header and the ECMA-335 metadata root (`BSJB`): the IL/ReadyToRun
 * form, an embedded portable PDB (`#Pdb` stream), and a name-entropy heuristic over the `#Strings` heap to
 * tell obfuscated assemblies apart (so they are reported detected-only, not as cleanly recoverable code).
 * Unity's `Assembly-CSharp.dll` is the game's own C#, graded as original source text.
 */

interface MetaStream {
  readonly name: string;
  readonly offset: number; // file offset
  readonly size: number;
}

function readMetadata(b: Buffer): { version: string; streams: MetaStream[]; stringsSample: string[] } | null {
  const clr = clrDirectory(b);
  if (!clr) return null;
  const corOff = rvaToOffset(b, clr.rva);
  if (corOff < 0 || corOff + 72 > b.length) return null;
  const metaRva = b.readUInt32LE(corOff + 8);
  const metaOff = rvaToOffset(b, metaRva);
  if (metaOff < 0 || metaOff + 20 > b.length || b.readUInt32LE(metaOff) !== 0x424a5342) return null; // "BSJB"
  const verLen = b.readUInt32LE(metaOff + 12);
  if (verLen > 256 || metaOff + 16 + verLen + 4 > b.length) return null;
  const version = b.toString("latin1", metaOff + 16, metaOff + 16 + verLen).replace(/\0+$/, "");
  let p = metaOff + 16 + verLen; // padded already (verLen is the rounded length per spec)
  if (p + 4 > b.length) return null;
  const nStreams = b.readUInt16LE(p + 2);
  p += 4;
  const streams: MetaStream[] = [];
  for (let i = 0; i < Math.min(nStreams, 32) && p + 8 <= b.length; i++) {
    const off = b.readUInt32LE(p);
    const size = b.readUInt32LE(p + 4);
    let e = p + 8;
    while (e < b.length && b[e] !== 0 && e - (p + 8) < 32) e++;
    const name = b.toString("latin1", p + 8, e);
    streams.push({ name, offset: metaOff + off, size });
    p = e + 1;
    p = (p + 3) & ~3; // 4-byte align
  }
  // Sample the #Strings heap (all type/method/field/param names) for the obfuscation heuristic.
  const strings = streams.find((s) => s.name === "#Strings");
  const sample: string[] = [];
  if (strings && strings.offset + strings.size <= b.length && strings.size < 64 * 1024 * 1024) {
    const heap = b.subarray(strings.offset, strings.offset + strings.size);
    let i = 0;
    while (i < heap.length && sample.length < 4000) {
      const end = heap.indexOf(0, i);
      const s = heap.toString("utf8", i, end === -1 ? heap.length : end);
      if (s && /[A-Za-z_<]/.test(s[0]!)) sample.push(s);
      if (end === -1) break;
      i = end + 1;
    }
  }
  return { version, streams, stringsSample: sample };
}

/** Obfuscated when most identifiers are 1–2 chars or non-ASCII — the signature of a name-mangling obfuscator. */
function looksObfuscated(names: string[]): boolean {
  const ids = names.filter((n) => !/[.`<>]/.test(n) && n.length > 0);
  if (ids.length < 30) return false;
  const shortOrWeird = ids.filter((n) => n.length <= 2 || /[^\x20-\x7e]/.test(n) || shannonEntropy(n) < 1.5).length;
  return shortOrWeird / ids.length > 0.6;
}

export const dotnet: Analyzer = {
  id: "dotnet",
  title: ".NET managed assembly (IL, embedded PDB, obfuscation)",
  mirrorsRea: "IL / .NET decompilation (ILSpy, dnSpy)",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item" || !looksLikePe(ctx.bytes)) return false;
    try {
      return readPe(ctx.bytes).clr;
    } catch {
      return false;
    }
  },

  profile(): ProfileTags {
    return { frameworks: [".NET"], languages: ["C#"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const base = (path.split("!/").pop() ?? path).split("/").pop() ?? path;
    const out: RawFinding[] = [];
    const corOff = (() => {
      const clr = clrDirectory(bytes);
      return clr ? rvaToOffset(bytes, clr.rva) : -1;
    })();
    const flags = corOff >= 0 && corOff + 20 <= bytes.length ? bytes.readUInt32LE(corOff + 16) : 0;
    const r2r = corOff >= 0 && corOff + 72 <= bytes.length && bytes.readUInt32LE(corOff + 64) !== 0; // ManagedNativeHeader present
    const meta = readMetadata(bytes);
    const obfuscated = meta ? looksObfuscated(meta.stringsSample) : false;
    const isGameCode = /^Assembly-CSharp(?:-firstpass)?\.dll$/i.test(base);

    if (meta) {
      const tablesStream = meta.streams.find((s) => s.name === "#~" || s.name === "#-");
      const ilForm = r2r ? "ReadyToRun (precompiled, but IL is still present)" : (flags & 0x1) !== 0 ? "pure IL" : "mixed-mode";
      if (obfuscated) {
        out.push({ analyzerId: this.id, rubricId: "symbols/metadata-clear", title: "Obfuscated .NET assembly (names mangled)", recovers: "the control flow and logic as IL (decompilable), but type/method names appear obfuscated, so symbolic readability is reduced", remediation: "obfuscation raises the cost of recovery; it does not make IL unrecoverable. Verify the obfuscator covers strings and control flow if that matters", avoidable: false, path, coverage: "detected-only", detail: `${path}: ${ilForm}; ${tablesStream?.name === "#-" ? "uncompressed (#-) metadata" : "names mangled"}` });
      } else if (isGameCode) {
        out.push({ analyzerId: this.id, rubricId: "code/source-text", title: "Unity game code (Assembly-CSharp) ships as readable IL", recovers: "the game's own C# as near-source: full class/method names, logic and string literals via ILSpy/dnSpy", remediation: "enable IL2CPP for release builds, or an IL obfuscator; Mono/IL2CPP managed DLLs decompile cleanly otherwise", avoidable: true, path, coverage: "full", detail: `${path}: ${ilForm}` });
      } else {
        out.push({ analyzerId: this.id, rubricId: "code/near-source-bytecode", title: "Managed .NET assembly ships IL in the clear", recovers: `near-source C#/F#: method bodies, names and string literals (${ilForm}) decompile with ILSpy/dnSpy`, remediation: "if the logic is sensitive, apply a .NET obfuscator (note: this only raises cost), or move secrets server-side", avoidable: true, path, coverage: "full", detail: `${path}: ${ilForm}` });
      }
      if (meta.streams.some((s) => s.name === "#Pdb"))
        out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "Embedded portable PDB", recovers: "method names, source file paths and line numbers embedded in the assembly (#Pdb stream)", remediation: "build release assemblies without `<DebugType>embedded</DebugType>`; publish symbols separately", avoidable: true, path, coverage: "full", detail: path });
    }
    return out;
  },
};
