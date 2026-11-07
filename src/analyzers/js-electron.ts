import { electronLeads } from "../lanes/aids.js";
import { isBinary, lineCol } from "../lanes/types.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * js-electron (item scope): Electron main/preload security, as a REA tool would read it from the
 * shipped JavaScript (inside app.asar or on disk). Adapts the v0.7 `electronLeads` reader for insecure
 * `webPreferences` and `openDevTools()`, and adds the preload IPC surface: a `contextBridge` that
 * exposes `ipcRenderer`, `require` or `process` wholesale hands the renderer the whole main process.
 * Unpacked `.node` addons are native code and are handled by the native analyzers.
 */

const JS = /\.(?:m?js|cjs)$/i;
const ELECTRON = /require\(\s*['"]electron['"]\s*\)|from\s+['"]electron['"]|\b(?:webPreferences|ipcMain|ipcRenderer|contextBridge|BrowserWindow)\b/;
/**
 * The second argument IS the object itself — `exposeInMainWorld('x', ipcRenderer)` or
 * `exposeInMainWorld('x', require('electron'))` — not a member of it: `process.versions` (the Electron
 * tutorial's pattern) exposes a plain data object and is not a lead.
 */
const EXPOSE_WHOLESALE = /\bexposeInMainWorld\s*\(\s*(['"`])[^'"`]+\1\s*,\s*(ipcRenderer|process|require\s*\(\s*['"]electron['"]\s*\)|require)\s*\)/g;
/** An object literal whose property VALUE is the object itself (`{ ipcRenderer }`, `{ ipc: ipcRenderer }`). */
const EXPOSE_IPC_OBJ = /\bexposeInMainWorld\s*\(\s*(['"`])[^'"`]+\1\s*,\s*\{(?:[^}]*?[,:])?\s*(ipcRenderer|require|process)\s*[,}]/g;

export const jsElectron: Analyzer = {
  id: "js-electron",
  title: "Electron webPreferences, DevTools and preload IPC surface",
  mirrorsRea: "Electron app.asar / main-process inspection",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    const { item, bytes } = ctx as ItemContext;
    if (!JS.test(item.ref.path) || isBinary(bytes)) return false;
    return ELECTRON.test(bytes.toString("utf8", 0, Math.min(bytes.length, 1 << 20)));
  },

  profile(): ProfileTags {
    return { frameworks: ["Electron"], languages: ["JavaScript"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const text = bytes.toString("utf8");
    const out: RawFinding[] = [];
    const leads = electronLeads(text);

    for (const l of leads.insecure) {
      const at = lineCol(text, l.index);
      out.push({ analyzerId: this.id, rubricId: "tamper/debuggable", title: `Insecure Electron webPreferences: ${l.key}: ${l.value}`, recovers: `a weakened renderer sandbox (${l.key}=${l.value}), which widens what injected or loaded content can reach`, remediation: `set ${l.key} to its secure value (contextIsolation:true, sandbox:true, nodeIntegration:false, webSecurity:true)`, avoidable: true, path, location: { line: at.line }, coverage: "full", detail: `${path}:${at.line}` });
    }
    for (const i of leads.devTools) {
      const at = lineCol(text, i);
      out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: "Electron DevTools opened from shipped code", recovers: "an openDevTools() call in shipped code; reachability is not analysed, but it points at a debug build", remediation: "gate openDevTools() behind a development-only check so it is not in the release", avoidable: true, path, location: { line: at.line }, coverage: "full", detail: `${path}:${at.line}` });
    }
    for (const re of [EXPOSE_WHOLESALE, EXPOSE_IPC_OBJ]) {
      re.lastIndex = 0;
      for (let m = re.exec(text); m; m = re.exec(text)) {
        const at = lineCol(text, m.index);
        out.push({ analyzerId: this.id, rubricId: "tamper/debuggable", title: `Preload exposes ${m[2]} to the renderer`, recovers: `the renderer is handed \`${m[2]}\` wholesale through contextBridge, which is effectively full main-process/IPC access`, remediation: "expose only specific, validated functions through contextBridge, never ipcRenderer/require/process directly", avoidable: true, path, location: { line: at.line }, coverage: "full", detail: `${path}:${at.line}` });
      }
    }
    return out;
  },
};
