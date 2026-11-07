import { existsSync, readFileSync, readlinkSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import type { Manifest } from "../model/manifest.js";
import type { EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome } from "../model/result.js";
import { sha256Hex, releaseId as computeReleaseId } from "../util/hash.js";
import { walkFiles } from "../util/walk.js";
import { matchesAny } from "../util/glob.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { DEFAULT_LIMITS, classify, expand, type Limits } from "./containers.js";
import type { Inventory, InventoryItem } from "./types.js";
import { lineCol, readItem, unsupported } from "./types.js";

/**
 * Build the release closure: every byte under the declared roots, plus the
 * contents of supported nested containers, each with a sha256 (doc §6.3).
 */
/** Shared builder: the same classification, expansion and limits for manifest roots and single paths. */
function inventoryBuilder(limits: Limits) {
  const items: InventoryItem[] = [];
  const notes: string[] = [];
  let expandedBytes = 0;

  const gap = (path: string, reason: string, extra: Partial<InventoryItem> = {}) =>
    items.push({ ref: { path, sha256: "", bytes: 0 }, source: null, kind: "file", depth: 0, supported: false, unsupportedReason: reason, ...extra });

  const add = (path: string, buf: Buffer, depth: number, parent?: string, abs?: string) => {
    const ref = { path, sha256: sha256Hex(buf), bytes: buf.length };
    const c = classify(path, buf);
    const base = { ref, parent, depth };
    const peek = abs ? ({ kind: "disk", abs } as const) : ({ kind: "mem", buf } as const);
    if (c.type === "plain") {
      items.push({ ...base, source: abs ? { kind: "disk", abs } : { kind: "mem", buf }, kind: parent ? "entry" : "file", supported: true, note: c.note });
      return;
    }
    if (c.type === "opaque") {
      items.push({ ...base, source: null, kind: "container", supported: false, unsupportedReason: `${c.format}: format not supported by this version (content not inspected)`, peek });
      return;
    }
    if (depth >= limits.maxDepth) {
      items.push({ ...base, source: null, kind: "container", supported: false, unsupportedReason: `nesting depth exceeds ${limits.maxDepth}`, peek });
      return;
    }
    const ex = expand(c.kind, path, buf, limits);
    if (!ex.ok) {
      items.push({ ...base, source: null, kind: "container", supported: false, unsupportedReason: ex.reason, peek });
      return;
    }
    items.push({ ...base, source: null, kind: "container", supported: true, raw: abs ? { kind: "disk", abs } : { kind: "mem", buf } });
    for (const n of ex.notes) notes.push(`${path}: ${n}`);
    for (const e of ex.entries) {
      const vpath = `${path}!/${e.name}`;
      if (e.data === null) {
        items.push({ ref: { path: vpath, sha256: "", bytes: 0 }, source: null, kind: "entry", parent: path, depth: depth + 1, supported: false, unsupportedReason: e.reason ?? "unreadable entry" });
        continue;
      }
      expandedBytes += e.data.length;
      if (expandedBytes > limits.maxTotalExpandedBytes) {
        items.push({
          ref: { path: vpath, sha256: sha256Hex(e.data), bytes: e.data.length },
          source: null,
          kind: "entry",
          parent: path,
          depth: depth + 1,
          supported: false,
          unsupportedReason: "total expanded bytes exceed limit",
        });
        continue;
      }
      add(vpath, e.data, depth + 1, path);
    }
  };

  /** A regular file on disk, at virtual path `path`. Over-size files are gaps whose bytes stay peekable. */
  const addDiskFile = (path: string, abs: string) => {
    let buf: Buffer;
    try {
      const size = statSync(abs).size;
      if (size > limits.maxFileBytes) {
        gap(path, `file size ${size} exceeds limit ${limits.maxFileBytes}`, { ref: { path, sha256: "", bytes: size }, peek: { kind: "disk", abs } });
        return;
      }
      buf = readFileSync(abs);
    } catch (e) {
      gap(path, `unreadable (${(e as NodeJS.ErrnoException).code ?? (e as Error).message})`);
      return;
    }
    add(path, buf, 0, undefined, abs);
  };

  const symlinks: string[] = [];
  /** Every file under a directory root, labelled `label/<rel>`. */
  const addDirectory = (label: string, absRoot: string) => {
    for (const f of walkFiles(absRoot)) {
      const path = `${label}/${f.rel}`;
      if (f.error) {
        gap(path, f.error);
        continue;
      }
      if (f.isSymlink) {
        // v0.6: a symlink ships a PATH, not bytes; a target inside the release is inspected as itself.
        // v0.5 recorded every symlink as a coverage gap, so every real macOS app bundle (framework
        // `Versions/Current` links) was inconclusive and blocked whatever its contents.
        let target = "?";
        try {
          target = readlinkSync(f.abs);
        } catch {}
        const inside = target !== "?" && !isAbsolute(target) && !relative(absRoot, resolve(dirname(f.abs), target)).startsWith("..");
        symlinks.push(`${path} -> ${target}${inside ? "" : " (target outside the release closure; only the link path ships)"}`);
        continue;
      }
      addDiskFile(path, f.abs);
    }
  };

  const finish = (): Inventory => {
    if (symlinks.length > 0)
      notes.push(`${symlinks.length} symbolic link(s) recorded, not followed (a link ships its path; targets inside the release are inspected as themselves): ${symlinks.slice(0, 10).join("; ")}${symlinks.length > 10 ? "; …" : ""}`);
    return { releaseId: computeReleaseId(items.map((i) => i.ref)), items, notes, limits };
  };

  return { notes, gap, addDiskFile, addDirectory, finish };
}

export function buildInventory(manifest: Manifest, baseDir: string, limits: Limits = DEFAULT_LIMITS): Inventory {
  const b = inventoryBuilder(limits);
  for (const root of manifest.releaseClosure.roots) {
    const label = root.replace(/\/+$/, "");
    const absRoot = resolve(baseDir, root);
    if (!existsSync(absRoot) || !statSync(absRoot).isDirectory()) {
      b.notes.push(`release root "${root}" does not exist or is not a directory`);
      b.gap(label, "declared release root missing");
      continue;
    }
    b.addDirectory(label, absRoot);
  }
  return b.finish();
}

/**
 * v0.8: the inventory of ONE path a launcher points at, with no manifest: a directory (an `.app`
 * bundle, an unpacked build) or a single file (`.apk`, `.ipa`, `.exe`, `.AppImage`, …). Items are
 * labelled with the path's base name, exactly as a manifest root of that name would label them.
 */
export function inventoryOfPath(absPath: string, limits: Limits = DEFAULT_LIMITS): { inventory: Inventory; label: string; kind: "file" | "directory" } {
  const b = inventoryBuilder(limits);
  const label = basename(absPath.replace(/\/+$/, "")) || absPath;
  if (!existsSync(absPath)) throw new RangeError(`${absPath} does not exist`);
  const st = statSync(absPath);
  if (st.isDirectory()) {
    b.addDirectory(label, absPath);
    return { inventory: b.finish(), label, kind: "directory" };
  }
  if (!st.isFile()) throw new RangeError(`${absPath} is neither a file nor a directory`);
  b.addDiskFile(label, absPath);
  return { inventory: b.finish(), label, kind: "file" };
}

/** Path relative to its own root or container, used for private-artifact glob matching. */
function localPath(path: string): string {
  const bang = path.lastIndexOf("!/");
  if (bang !== -1) return path.slice(bang + 2);
  const slash = path.indexOf("/");
  return slash === -1 ? path : path.slice(slash + 1);
}

// Only real source-map comments: a `//#` line on its own, or a `/*# ... */` block (CSS).
// Unanchored matching flags bundler code that *builds* such comments as strings.
const SOURCEMAP_LINE = /^[ \t]*\/\/[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+)[ \t\r]*$/gm;
const SOURCEMAP_BLOCK = /\/\*[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+?)[ \t]*\*\//g;
const MAX_SOURCEMAP_SCAN = 256 * 1024 * 1024;

export function inventoryLane(manifest: Manifest, inv: Inventory, startedAt: string): EvidenceRecord {
  const findings: Finding[] = [];
  const privateGlobs = manifest.releaseClosure.private ?? [];
  const shippedPaths = new Set(inv.items.map((i) => i.ref.path));
  const mapsArePrivate = privateGlobs.some((g) => /\.map\b/.test(g));

  for (const item of inv.items) {
    if (item.ref.sha256 === "") continue;
    const local = localPath(item.ref.path);
    if (privateGlobs.length > 0 && (matchesAny(local, privateGlobs) || matchesAny(item.ref.path, privateGlobs))) {
      findings.push({
        id: `inventory/private-shipped/${item.ref.path}`,
        title: "Artifact declared private is present in the shipped bytes",
        severity: "high",
        confidence: "confirmed",
        gate: "declaredPrivateArtifactShipped",
        artifact: item.ref,
        detail: "Declared private (releaseClosure.private) but found in the release closure. Private maps/symbols should stay under access control, not ship.",
      });
    }
  }

  for (const item of inv.items) {
    if (!item.source || !/\.(m?js|cjs|css)$/i.test(item.ref.path) || item.ref.bytes > MAX_SOURCEMAP_SCAN) continue;
    const text = readItem(item)!.toString("utf8");
    const refs = [...text.matchAll(SOURCEMAP_LINE), ...text.matchAll(SOURCEMAP_BLOCK)];
    for (const m of refs) {
      const url = m[1]!;
      const loc = { ...lineCol(text, m.index ?? 0), byteOffset: Buffer.byteLength(text.slice(0, m.index ?? 0)) };
      if (url.startsWith("data:")) {
        // A template like `data:...;base64,${b64}` in tooling code is not an embedded map.
        if (/[${}`'"+]/.test(url) || url.length < 64) continue;
        findings.push({
          id: `inventory/inline-sourcemap/${item.ref.path}`,
          title: "Inline source map embedded in shipped artifact",
          severity: "high",
          confidence: "confirmed",
          gate: mapsArePrivate ? "declaredPrivateArtifactShipped" : undefined,
          artifact: item.ref,
          location: loc,
          detail: "An inline (data:) source map ships original sources with the artifact.",
        });
        continue;
      }
      const external = /^[a-z][a-z0-9+.-]*:\/\//i.test(url);
      const dir = item.ref.path.slice(0, item.ref.path.lastIndexOf("/") + 1);
      const sibling = `${dir}${url}`;
      findings.push({
        id: `inventory/sourcemap-ref/${item.ref.path}`,
        title: external ? "Source map referenced at an external URL" : shippedPaths.has(sibling) ? "Source map reference resolves inside the release" : "Source map referenced but not shipped",
        severity: external ? "medium" : "info",
        confidence: "high",
        artifact: item.ref,
        location: loc,
        detail: external
          ? `References ${url}. Verify that host enforces access control; a reference alone does not prove the map is (in)accessible.`
          : shippedPaths.has(sibling)
            ? `Resolves to ${sibling}, which is in the release closure.`
            : `References ${url}, which is not in the release closure. Removing the file does not prove it is unavailable elsewhere.`,
      });
    }
  }

  const unsup = unsupported(inv);
  const privateHits = findings.some((f) => f.gate === "declaredPrivateArtifactShipped");
  const outcome: Outcome = privateHits ? "recovered" : unsup.length > 0 ? "inconclusive" : "not-recovered-within-budget";

  return {
    id: "inventory",
    lane: "inventory",
    releaseId: inv.releaseId,
    tool: TOOL,
    invocation: { roots: manifest.releaseClosure.roots, private: privateGlobs },
    accessGranted: "delivered release bytes (read-only), including supported nested containers",
    budget: { declared: "complete enumeration of the declared release roots" },
    outcome,
    coverage: {
      artifactsConsidered: inv.items.length,
      artifactsSupported: inv.items.length - unsup.length,
      artifactsUnsupported: unsup.length,
      notes: [...inv.notes, ...unsup.map((u) => `${u.ref.path}: ${u.unsupportedReason}`)],
    },
    limitations: [
      "Byte identity only: sha256 identifies bytes, it does not authenticate build context (use SLSA-style provenance for that).",
      "Only content under the declared roots is covered; remotely delivered modules, CDN assets and runtime downloads are out of scope unless placed under a root.",
      ...(unsup.length > 0 ? [`${unsup.length} artifact(s) could not be inspected and remain UNKNOWN.`] : []),
    ],
    findings,
    startedAt,
    finishedAt: nowIso(),
  };
}
