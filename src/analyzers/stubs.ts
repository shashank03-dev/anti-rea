import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * Roadmap stubs (item scope): formats a REA-class tool can analyze but this version does not parse yet.
 * Detecting and naming them keeps coverage honest — an unanalysed EVM contract or BEAM module is
 * reported as a known gap, not silently skipped.
 */

const BEAM_FOR1 = Buffer.from("FOR1", "latin1");
const BEAM_TAG = Buffer.from("BEAM", "latin1");

function stub(id: string, path: string, what: string): RawFinding {
  return {
    analyzerId: id,
    rubricId: "symbols/inherent",
    title: `${what} detected (not parsed by this version)`,
    recovers: `a REA-class tool can analyze this ${what}; Anti-REA detects it but does not parse its internals yet, so its recoverable surface is reported as a known gap`,
    remediation: "not yet analyzed by Anti-REA; treat its contents as recoverable until a dedicated analyzer lands",
    avoidable: false,
    path,
    coverage: "detected-only",
    detail: path,
  };
}

export const evm: Analyzer = {
  id: "evm",
  title: "EVM bytecode (roadmap stub)",
  mirrorsRea: "EVM/Solidity bytecode analysis",
  scope: "item",
  needs: { full: true },
  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    const b = ctx.bytes;
    if (b.length < 40 || b.length > 2 * 1024 * 1024) return false;
    // Cheap byte test before any decoding: the file must be hex digits (optional 0x, trailing whitespace).
    const isHex = (c: number) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
    let i = b[0] === 0x30 && (b[1] === 0x78 || b[1] === 0x58) ? 2 : 0;
    let end = b.length;
    while (end > i && (b[end - 1] === 0x0a || b[end - 1] === 0x0d || b[end - 1] === 0x20)) end--;
    if (end - i < 40) return false;
    for (; i < end; i++) if (!isHex(b[i]!)) return false;
    const t = b.toString("latin1", 0, end).replace(/^0x/i, "");
    // EVM runtime bytecode usually begins with the free-memory-pointer prologue, or carries solc metadata.
    return t.startsWith("6080604052") || t.includes("a264697066735822") || t.includes("a265627a7a72");
  },
  profile(): ProfileTags {
    return { platforms: ["EVM"] };
  },
  analyze(ctx: AnalyzerContext): RawFinding[] {
    return [stub(this.id, (ctx as ItemContext).item.ref.path, "EVM bytecode")];
  },
};

export const beam: Analyzer = {
  id: "beam",
  title: "Erlang/Elixir BEAM (roadmap stub)",
  mirrorsRea: "BEAM module decompilation",
  scope: "item",
  needs: { full: true },
  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    const b = ctx.bytes;
    return b.length >= 12 && b.subarray(0, 4).equals(BEAM_FOR1) && b.subarray(8, 12).equals(BEAM_TAG);
  },
  profile(): ProfileTags {
    return { languages: ["Erlang/Elixir"] };
  },
  analyze(ctx: AnalyzerContext): RawFinding[] {
    return [stub(this.id, (ctx as ItemContext).item.ref.path, "BEAM module")];
  },
};
