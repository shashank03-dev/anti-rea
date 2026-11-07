import type { Manifest, ReAidsDecl } from "../model/manifest.js";
import type { EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome, Severity } from "../model/result.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { matchesAny } from "../util/glob.js";
import { isNativeBinary, readNativeSymbols, type NativeSliceFacts } from "../codecs/symbols.js";
import type { Inventory, InventoryItem } from "./types.js";
import { contentCoverage, isBinary, lineCol, readItem, scannable } from "./types.js";

/**
 * Reverse-engineering-aids lane (v0.7, gate `reverseEngineeringAidShipped`).
 *
 * Protection cannot make shipped code unrecoverable, but a release should not hand a reverse engineer
 * what the build already removed for everyone else. This lane reports, from the shipped bytes:
 *
 * 1. **native** — Mach-O/ELF code that still carries embedded DWARF, a Mach-O debug map (stabs naming
 *    every object file and source file, with absolute build paths), or local (non-exported) symbol names.
 *    Counts agree with `dsymutil -s` (Mach-O) and `llvm-objdump` (ELF).
 * 2. **debugFiles** — debug artifacts recognised by CONTENT, not by name: MSF/PDB and portable PDB
 *    files, dSYM DWARF companions (Mach-O filetype MH_DSYM), split DWARF (`.dwo`, any ELF whose only
 *    content is debug sections is reported by check 1), and source maps (v3 JSON) — with
 *    `sourcesContent` meaning the original sources themselves ship.
 * 3. **sources** — original source files (TypeScript, JSX, Vue, Svelte, C/C++/Objective-C, Swift, Rust,
 *    Go, …) outside third-party trees.
 * 4. **minified** (opt-in) — owner JavaScript that is not whitespace-minified, or whose local
 *    identifiers are not mangled.
 * 5. **electron** (opt-in) — `webPreferences` that disable isolation (nodeIntegration on,
 *    contextIsolation/sandbox/webSecurity off, insecure content allowed) and `openDevTools()` calls.
 */

export const DEFAULT_SOURCE_EXTENSIONS = [
  ".ts", ".tsx", ".mts", ".cts", ".jsx", ".vue", ".svelte", ".coffee",
  ".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".swift", ".rs", ".go", ".kt", ".java", ".cs",
] as const;
export const DEFAULT_THIRD_PARTY = ["**/node_modules/**", "**/node_modules.asar/**", "**/node_modules.asar.unpacked/**"] as const;

/** Flat path for glob matching: container separators `!/` become `/`. */
const flat = (p: string) => p.replace(/!\//g, "/");
const relToRoot = (p: string) => {
  const f = flat(p);
  const i = f.indexOf("/");
  return i === -1 ? f : f.slice(i + 1);
};
const matches = (p: string, globs: readonly string[] | undefined) => !!globs && globs.length > 0 && (matchesAny(flat(p), globs) || matchesAny(relToRoot(p), globs));

// ------------------------------------------------------------------ debug files by content

export type DebugFileKind = "pdb" | "portable-pdb" | "source-map" | "source-map-with-sources";

const MSF7 = Buffer.from("Microsoft C/C++ MSF 7.00\r\n\x1aDS", "latin1");
const MSF2 = Buffer.from("Microsoft C/C++ program database 2.00\r\n", "latin1");

export function debugFileKind(path: string, buf: Buffer): DebugFileKind | null {
  if (buf.subarray(0, MSF7.length).equals(MSF7) || buf.subarray(0, MSF2.length).equals(MSF2)) return "pdb";
  // Portable PDB is a bare ECMA-335 metadata root; inside a .NET DLL the root sits after PE headers, never at 0.
  if (buf.length > 16 && buf.readUInt32LE(0) === 0x424a5342 && /\.pdb$/i.test(path)) return "portable-pdb";
  if (buf.length < 2 || buf.length > 512 * 1024 * 1024) return null;
  const head = buf.toString("latin1", 0, Math.min(buf.length, 64)).trimStart();
  if (!head.startsWith("{") && !head.startsWith(")]}'")) return null;
  let j: unknown;
  try {
    j = JSON.parse(buf.toString("utf8").replace(/^\)\]\}'[^\n]*\n/, ""));
  } catch {
    return null;
  }
  if (!j || typeof j !== "object") return null;
  const o = j as Record<string, unknown>;
  const isMap = (m: Record<string, unknown>) => m.version === 3 && (typeof m.mappings === "string" || Array.isArray(m.sections));
  if (!isMap(o)) return null;
  const withSources = (m: Record<string, unknown>): boolean =>
    (Array.isArray(m.sourcesContent) && m.sourcesContent.some((s) => typeof s === "string" && s.length > 0)) ||
    (Array.isArray(m.sections) && m.sections.some((s) => !!s && typeof s === "object" && !!(s as { map?: unknown }).map && withSources((s as { map: Record<string, unknown> }).map)));
  return withSources(o) ? "source-map-with-sources" : "source-map";
}

// ------------------------------------------------------------------ JavaScript shape

export interface JsShape {
  /** Bytes of CODE: the file with string/template/regex literal contents and comments removed. */
  readonly bytes: number;
  readonly lines: number;
  /** Share of code bytes on lines longer than 300 characters. Whitespace-minified code is a few very long lines. */
  readonly longLineShare: number;
  /** Declared bindings (var/let/const, function names, parameters, catch bindings) seen in code. */
  readonly declared: number;
  /** Share of declared bindings at most 2 characters long. Mangled code renames nearly every local. */
  readonly shortShare: number;
}

/**
 * longLineShare, shortShare and minDeclared were fixed on the development half of bench/minify.mjs's
 * corpus (round 1). minCodeBytes and literal stripping came from calibration on installed apps (round 2):
 * embedded text in string literals made minified bundles look readable. See docs/research/V07-CHANGES.md.
 */
export const MINIFY_THRESHOLDS = { longLineShare: 0.5, shortShare: 0.7, minDeclared: 8, minCodeBytes: 1024 } as const;

const ID = /^[A-Za-z_$][\w$]*$/;
const RESERVED = new Set(["if", "in", "do", "of", "as", "this", "new", "true", "false", "null", "void", "typeof", "async", "await", "function", "return"]);
/** After these keywords a `/` starts a regular expression, not a division. */
const REGEX_AFTER_WORD = new Set(["return", "typeof", "case", "do", "else", "in", "of", "void", "yield", "await", "delete", "throw", "new", "instanceof"]);

/**
 * The code of a JavaScript file: string, template and regular-expression literal CONTENTS and comments
 * are removed (delimiters kept, `${…}` template expressions kept as code). A small lexer, not a parser:
 * it decides regex-vs-division from the previous significant token, as tokenizers do.
 */
export function codeOnly(text: string): string {
  const out: string[] = [];
  let i = 0;
  const n = text.length;
  if (text.startsWith("#!")) i = Math.max(0, text.indexOf("\n"));
  let prev = ""; // previous significant character, or a word
  const templateDepth: number[] = []; // brace depth at which each open `${` resumes its template
  let braces = 0;
  let segStart = i;
  const flush = (end: number) => {
    if (end > segStart) out.push(text.slice(segStart, end));
  };
  const word = /[A-Za-z_$][\w$]*$/;
  const readTemplate = (from: number): number => {
    // from points just after a backtick or a closing `}` of `${…}`; returns index after the template part.
    let j = from;
    while (j < n) {
      const c = text[j]!;
      if (c === "\\") j += 2;
      else if (c === "`") return j + 1;
      else if (c === "$" && text[j + 1] === "{") {
        templateDepth.push(braces);
        braces++;
        return j + 2;
      } else j++;
    }
    return n;
  };
  while (i < n) {
    const c = text[i]!;
    if (c === "/" && text[i + 1] === "/") {
      flush(i);
      const e = text.indexOf("\n", i);
      i = e === -1 ? n : e;
      segStart = i;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      flush(i);
      const e = text.indexOf("*/", i + 2);
      i = e === -1 ? n : e + 2;
      segStart = i;
      out.push(" ");
      continue;
    }
    if (c === '"' || c === "'") {
      flush(i + 1);
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== "\n") j += text[j] === "\\" ? 2 : 1;
      i = Math.min(n, j + 1);
      segStart = j < n && text[j] === c ? j : i;
      prev = c;
      continue;
    }
    if (c === "`") {
      flush(i + 1);
      const j = readTemplate(i + 1);
      i = j;
      segStart = text[j - 1] === "`" ? j - 1 : j - 2; // keep the closing backtick or the `${`
      prev = "`";
      continue;
    }
    if (c === "}" && templateDepth.length > 0 && templateDepth[templateDepth.length - 1] === braces - 1) {
      templateDepth.pop();
      braces--;
      flush(i + 1);
      const j = readTemplate(i + 1);
      i = j;
      segStart = text[j - 1] === "`" ? j - 1 : j - 2;
      prev = "`";
      continue;
    }
    if (c === "/") {
      const w = word.exec(prev);
      const isRegex = prev === "" || "(,=:[!&|?{};+-*%<>~^".includes(prev) || (w !== null && REGEX_AFTER_WORD.has(w[0]));
      if (isRegex) {
        flush(i + 1);
        let j = i + 1;
        let cls = false;
        while (j < n && text[j] !== "\n") {
          const d = text[j]!;
          if (d === "\\") j += 2;
          else if (cls) {
            if (d === "]") cls = false;
            j++;
          } else if (d === "[") {
            cls = true;
            j++;
          } else if (d === "/") break;
          else j++;
        }
        segStart = j < n && text[j] === "/" ? j : j;
        i = j < n && text[j] === "/" ? j + 1 : j;
        prev = ")";
        continue;
      }
    }
    if (c === "{") braces++;
    else if (c === "}") braces = Math.max(0, braces - 1);
    if (!/\s/.test(c)) {
      if (/[\w$]/.test(c)) {
        let j = i;
        while (j < n && /[\w$]/.test(text[j]!)) j++;
        prev = text.slice(i, j);
        i = j;
        continue;
      }
      prev = c;
    }
    i++;
  }
  flush(n);
  return out.join("");
}

export function jsShape(source: string): JsShape {
  const text = codeOnly(source);
  let long = 0;
  let lines = 0;
  for (let start = 0; start <= text.length; ) {
    let end = text.indexOf("\n", start);
    if (end === -1) end = text.length;
    lines++;
    if (end - start > 300) long += end - start;
    start = end + 1;
  }
  const names: string[] = [];
  const push = (raw: string) => {
    const n = raw.trim().replace(/^\.\.\./, "").split(/[\s=:]/)[0]!;
    if (ID.test(n) && !RESERVED.has(n)) names.push(n);
  };
  const scan = (re: RegExp, each: (m: RegExpExecArray) => void) => {
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) each(m);
  };
  // Exported bindings are API names that a minifier must keep; they say nothing about mangling.
  scan(/(?<!\bexport\s+)\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)/g, (m) => push(m[1]!));
  // Destructuring patterns are dropped: their property keys are API names that cannot be mangled.
  const params = (list: string) => {
    let l = list;
    for (let prev = ""; prev !== l; ) {
      prev = l;
      l = l.replace(/\{[^{}]*\}|\[[^[\]]*\]/g, "");
    }
    for (const p of l.split(",")) if (!/[{}[\]]/.test(p)) push(p);
  };
  scan(/(\bexport\s+(?:default\s+)?(?:async\s+)?)?\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(([^()]*)\)/g, (m) => {
    if (m[2] && !m[1]) push(m[2]);
    params(m[3]!);
  });
  scan(/\(([^()]*)\)\s*=>/g, (m) => params(m[1]!));
  scan(/(?:^|[^\w$.)\]])([A-Za-z_$][\w$]*)\s*=>/g, (m) => push(m[1]!));
  scan(/\bcatch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/g, (m) => push(m[1]!));
  const short = names.filter((n) => n.length <= 2).length;
  return { bytes: text.length, lines, longLineShare: text.length === 0 ? 0 : long / text.length, declared: names.length, shortShare: names.length === 0 ? 0 : short / names.length };
}

export type MinifyLevel = "whitespace" | "identifiers";

/** null when there is too little code to judge (under minCodeBytes, or too few declarations for mangling). */
export function minifyVerdict(s: JsShape, level: MinifyLevel): { ok: boolean | null; why: string } {
  if (s.bytes < MINIFY_THRESHOLDS.minCodeBytes) return { ok: null, why: `only ${s.bytes} bytes of code; too small to judge` };
  const ws = s.longLineShare >= MINIFY_THRESHOLDS.longLineShare;
  if (!ws) return { ok: false, why: `not whitespace-minified: ${(s.longLineShare * 100).toFixed(0)}% of bytes on long lines over ${s.lines} line(s)` };
  if (level === "whitespace") return { ok: true, why: "whitespace-minified" };
  if (s.declared < MINIFY_THRESHOLDS.minDeclared) return { ok: null, why: `only ${s.declared} declared binding(s); mangling cannot be judged` };
  const mangled = s.shortShare >= MINIFY_THRESHOLDS.shortShare;
  return mangled
    ? { ok: true, why: "whitespace-minified and identifiers mangled" }
    : { ok: false, why: `identifiers not mangled: ${(s.shortShare * 100).toFixed(0)}% of ${s.declared} declared bindings are 1–2 characters` };
}

// ------------------------------------------------------------------ Electron webPreferences

export interface ElectronLead {
  readonly key: string;
  readonly value: string;
  readonly index: number;
}

const INSECURE: Record<string, RegExp> = {
  nodeIntegration: /^(?:true|!0)$/,
  nodeIntegrationInWorker: /^(?:true|!0)$/,
  nodeIntegrationInSubFrames: /^(?:true|!0)$/,
  contextIsolation: /^(?:false|!1)$/,
  sandbox: /^(?:false|!1)$/,
  webSecurity: /^(?:false|!1)$/,
  allowRunningInsecureContent: /^(?:true|!0)$/,
  experimentalFeatures: /^(?:true|!0)$/,
};

/** Balanced `{…}` starting at `open` (string-aware), capped at `cap` characters. */
function objectAt(text: string, open: number, cap = 8192): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < text.length && i - open < cap; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return text.slice(open, i + 1);
  }
  return null;
}

/** Insecure keys set inside `webPreferences: { … }` object literals, and `openDevTools(` calls. */
export function electronLeads(text: string): { insecure: ElectronLead[]; devTools: number[] } {
  const insecure: ElectronLead[] = [];
  const devTools: number[] = [];
  const re = /\bwebPreferences["']?\s*:\s*\{/g;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const open = m.index + m[0].length - 1;
    const body = objectAt(text, open);
    if (!body) continue;
    // Only keys of this object, not of nested objects.
    let depth = 0;
    let flatBody = "";
    for (const c of body) {
      if (c === "{") depth++;
      else if (c === "}") depth--;
      flatBody += depth <= 1 ? c : " ";
    }
    const kv = /(?:^|[{,\s])["']?([A-Za-z]+)["']?\s*:\s*(true|false|!0|!1)\b/g;
    for (let k = kv.exec(flatBody); k; k = kv.exec(flatBody)) {
      const rule = INSECURE[k[1]!];
      if (rule && rule.test(k[2]!)) insecure.push({ key: k[1]!, value: k[2]!, index: open + k.index });
    }
  }
  const dt = /\.openDevTools\s*\(/g;
  for (let m = dt.exec(text); m; m = dt.exec(text)) devTools.push(m.index);
  return { insecure, devTools };
}

// ------------------------------------------------------------------ facts

export interface NativeFact {
  readonly path: string;
  readonly slices: readonly NativeSliceFacts[];
}

export interface AidsFacts {
  readonly native: NativeFact[];
  readonly debugFiles: { path: string; kind: DebugFileKind | "dsym" }[];
  readonly sources: string[];
  readonly js: { path: string; shape: JsShape }[];
  readonly electron: { path: string; insecure: ElectronLead[]; devTools: number[]; text: string }[];
}

const JS_RE = /\.(?:m?js|cjs)$/i;

export function collectAidsFacts(inv: Inventory, decl: ReAidsDecl = {}): AidsFacts {
  const facts: AidsFacts = { native: [], debugFiles: [], sources: [], js: [], electron: [] };
  const srcCfg = decl.sources === false ? null : decl.sources ?? {};
  const exts = new Set((srcCfg?.extensions ?? DEFAULT_SOURCE_EXTENSIONS).map((e) => e.toLowerCase()));
  const srcExclude = srcCfg?.exclude ?? DEFAULT_THIRD_PARTY;
  const min = decl.minified;
  const el = decl.electron;
  const elExclude = el?.exclude ?? DEFAULT_THIRD_PARTY;
  for (const item of scannable(inv)) {
    const p = item.ref.path;
    const lower = p.toLowerCase();
    const ext = lower.slice(lower.lastIndexOf("."));
    if (srcCfg && exts.has(ext) && !lower.endsWith(".d.ts") && !lower.endsWith(".d.mts") && !lower.endsWith(".d.cts") && !matches(p, srcExclude)) facts.sources.push(p);
    const wantJs = JS_RE.test(p) && ((min && matches(p, min.include) && !matches(p, min.exclude)) || (el && (!el.include || matches(p, el.include)) && !matches(p, elExclude)));
    const buf = readItem(item);
    if (!buf) continue;
    if (isNativeBinary(buf)) {
      try {
        const slices = readNativeSymbols(buf);
        facts.native.push({ path: p, slices });
        if (slices.some((s) => s.filetype === "dsym")) facts.debugFiles.push({ path: p, kind: "dsym" });
      } catch {
        /* not native after all */
      }
      continue;
    }
    const kind = debugFileKind(p, buf);
    if (kind) facts.debugFiles.push({ path: p, kind });
    if (wantJs && !isBinary(buf)) {
      const text = buf.toString("utf8");
      if (min && matches(p, min.include) && !matches(p, min.exclude)) facts.js.push({ path: p, shape: jsShape(text) });
      if (el && (!el.include || matches(p, el.include)) && !matches(p, elExclude)) {
        const l = electronLeads(text);
        if (l.insecure.length > 0 || l.devTools.length > 0) facts.electron.push({ path: p, ...l, text });
      }
    }
  }
  return facts;
}

// ------------------------------------------------------------------ lane

export function aidsLane(manifest: Manifest, inv: Inventory, startedAt: string, facts?: AidsFacts): EvidenceRecord {
  const decl: ReAidsDecl = manifest.reAids ?? {};
  const f = facts ?? collectAidsFacts(inv, decl);
  const findings: Finding[] = [];
  const limitations: string[] = [
    "Stripping, minification and isolation raise the cost of reverse engineering; none makes shipped code unrecoverable. Exported symbols, Objective-C/Swift runtime metadata and string literals always remain.",
    "Windows PE debug directories (CodeView/PDB paths) are not parsed; shipped .pdb files are detected by content.",
  ];
  const ref = (path: string) => inv.items.find((i: InventoryItem) => i.ref.path === path)?.ref ?? { path, sha256: "", bytes: 0 };
  const add = (id: string, title: string, severity: Severity, detail: string, path: string, location?: Finding["location"]) =>
    findings.push({ id: `aids/${id}`, title, severity, confidence: "confirmed", gate: "reverseEngineeringAidShipped", artifact: ref(path), ...(location ? { location } : {}), detail });

  const nat = decl.native === false ? null : decl.native ?? {};
  if (nat) {
    const maxLocals = nat.maxLocalSymbols ?? 0;
    for (const n of f.native) {
      if (matches(n.path, nat.exclude)) continue;
      for (const s of n.slices) {
        const where = `${n.path} (${s.arch}, ${s.format} ${s.filetype})`;
        if (s.error) {
          limitations.push(`${where}: symbol table unreadable (${s.error}); its debug facts are unknown.`);
          continue;
        }
        if (s.filetype === "dsym") continue; // reported as a debug file
        if (nat.forbidDebugInfo !== false && s.debugSections.length > 0)
          add(`debug-info/${n.path}/${s.arch}`, "Embedded debug information shipped", "high", `${where}: ${s.debugSections.length} debug section(s) (${s.debugSections.slice(0, 4).join(", ")}) describe types, variables and source lines.`, n.path);
        if (nat.forbidDebugMap !== false && s.stabs > 0) {
          const paths = [...s.debugMapObjects, ...s.sourceFiles];
          add(
            `debug-map/${n.path}/${s.arch}`,
            "Debug map (stabs) shipped: build paths, source files and function names",
            "high",
            `${where}: ${s.stabs} stab entries naming ${s.debugMapObjects.length} object file(s) and ${s.sourceFiles.length} source file(s)${paths.length ? `, e.g. ${paths[0]}` : ""}. Remove with \`strip -S\` (keep a dSYM for symbolication).`,
            n.path,
          );
        }
        if (s.localSymbols > maxLocals)
          add(
            `local-symbols/${n.path}/${s.arch}`,
            "Unstripped local symbol names shipped",
            "medium",
            `${where}: ${s.localSymbols} non-exported symbol name(s)${s.localSample.length ? ` (e.g. ${s.localSample.slice(0, 3).join(", ")})` : ""}${maxLocals > 0 ? `; at most ${maxLocals} allowed` : ""}. Remove with \`strip -x\` (Mach-O) or \`strip --strip-unneeded\` (ELF).`,
            n.path,
          );
        if (s.format === "elf" && s.hasSymtab && s.filetype !== "relocatable" && s.localSymbols <= maxLocals && s.sourceFiles.length > 0)
          add(`elf-symtab/${n.path}/${s.arch}`, "ELF symbol table with source file names shipped", "medium", `${where}: .symtab names ${s.sourceFiles.length} source file(s), e.g. ${s.sourceFiles[0]}.`, n.path);
      }
    }
  }

  const dbg = decl.debugFiles === false ? null : decl.debugFiles ?? {};
  if (dbg)
    for (const d of f.debugFiles) {
      if (matches(d.path, dbg.exclude)) continue;
      const [title, sev, detail] =
        d.kind === "source-map-with-sources"
          ? ["Source map with embedded original sources shipped", "critical" as const, "sourcesContent carries the original, unminified source text."]
          : d.kind === "source-map"
            ? ["Source map shipped", "high" as const, "The mappings restore original file names, lines and (with names) identifiers."]
            : d.kind === "dsym"
              ? ["dSYM debug companion shipped", "high" as const, "A Mach-O MH_DSYM file holds the full DWARF for its binary."]
              : ["Program database (PDB) shipped", "high" as const, `A ${d.kind === "pdb" ? "MSF" : "portable"} PDB holds symbols, types and source paths.`];
      add(`debug-file/${d.path}`, title, sev, `${d.path}: ${detail}`, d.path);
    }

  if (decl.sources !== false)
    for (const p of f.sources) add(`source/${p}`, "Original source file shipped", "high", `${p} is source code, not a build output.`, p);

  if (decl.minified) {
    const level = decl.minified.level ?? "identifiers";
    let judged = 0;
    for (const j of f.js) {
      const v = minifyVerdict(j.shape, level);
      if (v.ok === null) continue;
      judged++;
      if (!v.ok) add(`unminified/${j.path}`, level === "whitespace" ? "JavaScript not minified" : "JavaScript not minified with mangled identifiers", "medium", `${j.path}: ${v.why}.`, j.path);
    }
    if (f.js.length === 0) limitations.push(`reAids.minified.include matched no shipped JavaScript (${decl.minified.include.join(", ")}).`);
    else if (judged < f.js.length) limitations.push(`${f.js.length - judged} matched JavaScript file(s) had too few declarations to judge identifier mangling.`);
  }

  if (decl.electron) {
    for (const e of f.electron) {
      if (decl.electron.forbidInsecureWebPreferences !== false)
        for (const l of e.insecure) {
          const at = lineCol(e.text, l.index);
          add(`electron-webpreferences/${e.path}/${l.key}@${l.index}`, `Insecure Electron webPreferences: ${l.key}: ${l.value}`, "high", `${e.path}: ${l.key} set to ${l.value} in a webPreferences object.`, e.path, { line: at.line, column: at.column });
        }
      if (decl.electron.forbidDevTools)
        for (const i of e.devTools) {
          const at = lineCol(e.text, i);
          add(`electron-devtools/${e.path}@${i}`, "Electron DevTools opened from shipped code", "medium", `${e.path}: openDevTools() call. Reachability is not analysed.`, e.path, { line: at.line, column: at.column });
        }
    }
    limitations.push("Electron webPreferences are read from object literals; values computed at runtime, and defaults inherited from session or app code, are not seen.");
  }

  // The lane is inconclusive only when nothing the declaration asks about could be inspected.
  const outcome: Outcome = findings.length > 0 ? "recovered" : "not-recovered-within-budget";
  return {
    id: "aids",
    lane: "aids",
    releaseId: inv.releaseId,
    tool: TOOL,
    invocation: { native: !!nat, debugFiles: !!dbg, sources: decl.sources !== false, minified: decl.minified ?? null, electron: decl.electron ?? null },
    accessGranted: "delivered release bytes (read-only); native symbol tables, file content and JavaScript text",
    budget: {},
    outcome,
    coverage: contentCoverage(inv),
    limitations,
    findings,
    startedAt,
    finishedAt: nowIso(),
  };
}
