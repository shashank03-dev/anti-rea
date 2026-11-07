import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * wasm (item scope): a WebAssembly module's custom sections reveal structure — the `name` section
 * carries function and local names (what wasm-decompile / Ghidra use for readable output), and
 * `.debug_*` custom sections carry DWARF. Export names are inherent. Reads the section list only;
 * every length is a bounds-checked LEB128 and the loop is capped.
 */

const WASM_MAGIC = Buffer.from([0x00, 0x61, 0x73, 0x6d]);

function uleb(b: Buffer, o: number): [number, number] {
  let x = 0;
  let shift = 0;
  let p = o;
  for (let i = 0; i < 5 && p < b.length; i++) {
    const c = b[p++]!;
    x += (c & 0x7f) * 2 ** shift;
    if ((c & 0x80) === 0) break;
    shift += 7;
  }
  return [x >>> 0, p];
}

export const wasm: Analyzer = {
  id: "wasm",
  title: "WebAssembly name and debug sections",
  mirrorsRea: "WASM name-section / DWARF recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    return ctx.scope === "item" && ctx.bytes.length >= 8 && ctx.bytes.subarray(0, 4).equals(WASM_MAGIC);
  },

  profile(): ProfileTags {
    return { platforms: ["WebAssembly"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];
    let hasNames = false;
    const debugSections: string[] = [];
    let p = 8;
    for (let i = 0; i < 100000 && p < bytes.length; i++) {
      const id = bytes[p++]!;
      const [size, p2] = uleb(bytes, p);
      p = p2;
      if (size < 0 || p + size > bytes.length) break;
      const end = p + size;
      if (id === 0) {
        const [nameLen, p3] = uleb(bytes, p);
        if (p3 + nameLen <= end) {
          const name = bytes.toString("utf8", p3, p3 + nameLen);
          if (name === "name") hasNames = true;
          else if (name.startsWith(".debug_")) debugSections.push(name);
        }
      }
      p = end;
    }
    if (debugSections.length > 0)
      out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "WASM DWARF debug sections", recovers: `DWARF in custom sections (${debugSections.slice(0, 4).join(", ")}): source-level names, types and line numbers`, remediation: "strip debug sections for release (`wasm-opt --strip-debug`, or build without `-g`)", avoidable: true, path, coverage: "full", detail: path });
    if (hasNames)
      out.push({ analyzerId: this.id, rubricId: "symbols/local", title: "WASM name section", recovers: "function and local variable names, which make a decompile (wasm-decompile, Ghidra) far more readable", remediation: "strip names for release with `wasm-opt --strip-debug --strip-producers` or `wasm-strip`", avoidable: true, path, coverage: "full", detail: path });
    return out;
  },
};
