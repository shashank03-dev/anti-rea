import { DEFAULT_SOURCE_EXTENSIONS, DEFAULT_THIRD_PARTY, debugFileKind } from "../lanes/aids.js";
import { matchesAny } from "../util/glob.js";
import type { Analyzer, AnalyzerContext, ItemContext, RawFinding } from "./types.js";

/**
 * debug-files (item scope): source maps, PDB / portable-PDB files and original source files.
 *
 * One source of truth (plan item 3): this reuses the v0.7 `aids` lane's own detectors — `debugFileKind`
 * (recognises debug files by CONTENT: MSF/portable PDB, v3 source maps including indexed and XSSI-prefixed
 * ones, and whether `sourcesContent` ships the original text) and its source-extension and third-party
 * defaults — inside the analyzer pass, so the release is read once. dSYM companions are Mach-O and are
 * reported by `native-macho`.
 */

const EXTS = new Set<string>(DEFAULT_SOURCE_EXTENSIONS);
const DECL = /\.d\.[cm]?ts$/i;
const MSF7 = Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS", "latin1");
const MSF2 = Buffer.from("Microsoft C/C++ program database 2.00\r\n", "latin1");

const flat = (p: string) => p.replace(/!\//g, "/");
const relToRoot = (p: string) => {
  const f = flat(p);
  const i = f.indexOf("/");
  return i === -1 ? f : f.slice(i + 1);
};
const thirdPartyTree = (p: string) => matchesAny(flat(p), DEFAULT_THIRD_PARTY) || matchesAny(relToRoot(p), DEFAULT_THIRD_PARTY);

function isSource(path: string): boolean {
  const lower = path.toLowerCase();
  const dot = lower.lastIndexOf(".");
  return dot > lower.lastIndexOf("/") && EXTS.has(lower.slice(dot)) && !DECL.test(lower) && !thirdPartyTree(path);
}

/** Cheap prefilter before the JSON parse in debugFileKind. */
function maybeDebugFile(b: Buffer): boolean {
  if (b.subarray(0, MSF7.length).equals(MSF7) || b.subarray(0, MSF2.length).equals(MSF2)) return true;
  if (b.length > 16 && b.readUInt32LE(0) === 0x424a5342) return true; // portable PDB metadata root
  let i = 0;
  while (i < b.length && i < 64 && (b[i] === 0x20 || b[i] === 0x0a || b[i] === 0x0d || b[i] === 0x09 || b[i] === 0xef || b[i] === 0xbb || b[i] === 0xbf)) i++;
  const lead = b[i];
  if (lead !== 0x7b && lead !== 0x29) return false; // '{' or the XSSI prefix ")]}'"
  // Search the WHOLE buffer: bundlers (esbuild, webpack) write "sourcesContent" before "mappings", so in a
  // large map the key sits megabytes in. A head-only check missed exactly the maps that ship the most source.
  return b.indexOf('"mappings"') >= 0 || b.indexOf('"sections"') >= 0;
}

/** A `//# sourceMappingURL=data:…` (or CSS block) comment carrying a whole source map inside the shipped file. */
const INLINE_MAP = /^[ \t]*(?:\/\/[#@]|\/\*[#@])[ \t]*sourceMappingURL[ \t]*=[ \t]*data:([^,\s]*),([A-Za-z0-9+/=_%.~-]+)/gm;
const SCRIPT = /\.(?:m?js|cjs|css)$/i;
const INLINE_HINT = Buffer.from("sourceMappingURL=data:");

/** Decode each inline map comment in `bytes` (base64 or percent-encoded JSON); unreadable payloads are skipped. */
export function inlineSourceMaps(bytes: Buffer): Buffer[] {
  if (bytes.indexOf(INLINE_HINT) === -1) return [];
  const out: Buffer[] = [];
  for (const m of bytes.toString("utf8").matchAll(INLINE_MAP)) {
    const meta = m[1]!;
    const payload = m[2]!;
    if (payload.length < 32) continue; // tooling that BUILDS such comments, e.g. `data:…;base64,${x}`
    try {
      out.push(/;base64$/i.test(meta) ? Buffer.from(payload, "base64") : Buffer.from(decodeURIComponent(payload), "utf8"));
    } catch {
      // not decodable: not a map we can grade
    }
  }
  return out;
}

export const debugFiles: Analyzer = {
  id: "debug-files",
  title: "Source maps, PDB files and original sources",
  mirrorsRea: "source-map / PDB / source recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    return isSource(ctx.item.ref.path) || maybeDebugFile(ctx.bytes) || (SCRIPT.test(ctx.item.ref.path) && ctx.bytes.indexOf(INLINE_HINT) !== -1);
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];
    if (isSource(path))
      out.push({ analyzerId: this.id, rubricId: "code/source-text", title: "Original source file shipped", recovers: "the original source text (this is a source file, not a build output)", remediation: "exclude source files from the packaged release (check your bundler's file list / packaging globs)", avoidable: true, path, coverage: "full", detail: path });
    const kind = maybeDebugFile(bytes) ? debugFileKind(path, bytes) : null;
    if (kind === "source-map-with-sources")
      out.push({ analyzerId: this.id, rubricId: "code/source-text", title: "Source map ships the original source", recovers: "the original, unminified source text, inlined in the map's sourcesContent", remediation: "do not ship .map files; upload them to your error-tracking service, or build without sourcesContent", avoidable: true, path, coverage: "full", detail: `${path}: sourcesContent present` });
    else if (kind === "source-map")
      out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "Source map restores original names and layout", recovers: "original file names, line/column positions and (with the names list) identifiers for the minified bundle", remediation: "do not ship .map files; serve them only to your error-tracking service", avoidable: true, path, coverage: "full", detail: path });
    else if (kind === "pdb" || kind === "portable-pdb")
      out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: `Program database (${kind === "pdb" ? "MSF PDB" : "portable PDB"}) shipped`, recovers: "symbols, types and source file paths for the binary it accompanies", remediation: "keep .pdb files on your symbol server; do not ship them", avoidable: true, path, coverage: "full", detail: path });
    // Inline maps: the bundler embedded the whole map (often with sourcesContent) in the shipped script itself.
    if (SCRIPT.test(path))
      for (const map of inlineSourceMaps(bytes)) {
        const k = debugFileKind(`${path}.map`, map);
        if (k === "source-map-with-sources")
          out.push({ analyzerId: this.id, rubricId: "code/source-text", title: "Inline source map ships the original source", recovers: "the original, unminified source text, embedded in the shipped script as a data: URL", remediation: "build release bundles without inline source maps (esbuild/Vite/webpack: emit external maps, or none, for production) and upload maps to your error-tracking service", avoidable: true, path, coverage: "full", detail: `${path}: inline source map with sourcesContent` });
        else if (k === "source-map")
          out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "Inline source map restores original names and layout", recovers: "original file names and line/column positions, embedded in the shipped script", remediation: "build release bundles without inline source maps", avoidable: true, path, coverage: "full", detail: `${path}: inline source map` });
      }
    return out;
  },
};
