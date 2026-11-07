import { existsSync, readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { sha256Hex, releaseId as computeReleaseId } from "../util/hash.js";
import { walkFiles } from "../util/walk.js";
import { matchesAny } from "../util/glob.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { DEFAULT_LIMITS, classify, expand } from "./containers.js";
import { lineCol, readItem, unsupported } from "./types.js";
/**
 * Build the release closure: every byte under the declared roots, plus the
 * contents of supported nested containers, each with a sha256 (doc §6.3).
 */
export function buildInventory(manifest, baseDir, limits = DEFAULT_LIMITS) {
    const items = [];
    const notes = [];
    let expandedBytes = 0;
    const gap = (path, reason, extra = {}) => items.push({ ref: { path, sha256: "", bytes: 0 }, source: null, kind: "file", depth: 0, supported: false, unsupportedReason: reason, ...extra });
    const add = (path, buf, depth, parent, abs) => {
        const ref = { path, sha256: sha256Hex(buf), bytes: buf.length };
        const c = classify(path, buf);
        const base = { ref, parent, depth };
        if (c.type === "plain") {
            items.push({ ...base, source: abs ? { kind: "disk", abs } : { kind: "mem", buf }, kind: parent ? "entry" : "file", supported: true, note: c.note });
            return;
        }
        if (c.type === "opaque") {
            items.push({ ...base, source: null, kind: "container", supported: false, unsupportedReason: `${c.format}: format not supported by this version (content not inspected)` });
            return;
        }
        if (depth >= limits.maxDepth) {
            items.push({ ...base, source: null, kind: "container", supported: false, unsupportedReason: `nesting depth exceeds ${limits.maxDepth}` });
            return;
        }
        const ex = expand(c.kind, path, buf, limits);
        if (!ex.ok) {
            items.push({ ...base, source: null, kind: "container", supported: false, unsupportedReason: ex.reason });
            return;
        }
        items.push({ ...base, source: null, kind: "container", supported: true });
        for (const n of ex.notes)
            notes.push(`${path}: ${n}`);
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
    for (const root of manifest.releaseClosure.roots) {
        const label = root.replace(/\/+$/, "");
        const absRoot = resolve(baseDir, root);
        if (!existsSync(absRoot) || !statSync(absRoot).isDirectory()) {
            notes.push(`release root "${root}" does not exist or is not a directory`);
            gap(label, "declared release root missing");
            continue;
        }
        for (const f of walkFiles(absRoot)) {
            const path = `${label}/${f.rel}`;
            if (f.error) {
                gap(path, f.error);
                continue;
            }
            if (f.isSymlink) {
                gap(path, "symlink not followed");
                continue;
            }
            let buf;
            try {
                const size = statSync(f.abs).size;
                if (size > limits.maxFileBytes) {
                    gap(path, `file size ${size} exceeds limit ${limits.maxFileBytes}`, { ref: { path, sha256: "", bytes: size } });
                    continue;
                }
                buf = readFileSync(f.abs);
            }
            catch (e) {
                gap(path, `unreadable (${e.code ?? e.message})`);
                continue;
            }
            add(path, buf, 0, undefined, f.abs);
        }
    }
    return { releaseId: computeReleaseId(items.map((i) => i.ref)), items, notes, limits };
}
/** Path relative to its own root or container, used for private-artifact glob matching. */
function localPath(path) {
    const bang = path.lastIndexOf("!/");
    if (bang !== -1)
        return path.slice(bang + 2);
    const slash = path.indexOf("/");
    return slash === -1 ? path : path.slice(slash + 1);
}
// Only real source-map comments: a `//#` line on its own, or a `/*# ... */` block (CSS).
// Unanchored matching flags bundler code that *builds* such comments as strings.
const SOURCEMAP_LINE = /^[ \t]*\/\/[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+)[ \t\r]*$/gm;
const SOURCEMAP_BLOCK = /\/\*[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+?)[ \t]*\*\//g;
const MAX_SOURCEMAP_SCAN = 256 * 1024 * 1024;
export function inventoryLane(manifest, inv, startedAt) {
    const findings = [];
    const privateGlobs = manifest.releaseClosure.private ?? [];
    const shippedPaths = new Set(inv.items.map((i) => i.ref.path));
    const mapsArePrivate = privateGlobs.some((g) => /\.map\b/.test(g));
    for (const item of inv.items) {
        if (item.ref.sha256 === "")
            continue;
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
        if (!item.source || !/\.(m?js|cjs|css)$/i.test(item.ref.path) || item.ref.bytes > MAX_SOURCEMAP_SCAN)
            continue;
        const text = readItem(item).toString("utf8");
        const refs = [...text.matchAll(SOURCEMAP_LINE), ...text.matchAll(SOURCEMAP_BLOCK)];
        for (const m of refs) {
            const url = m[1];
            const loc = { ...lineCol(text, m.index ?? 0), byteOffset: Buffer.byteLength(text.slice(0, m.index ?? 0)) };
            if (url.startsWith("data:")) {
                // A template like `data:...;base64,${b64}` in tooling code is not an embedded map.
                if (/[${}`'"+]/.test(url) || url.length < 64)
                    continue;
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
    const outcome = privateHits ? "recovered" : unsup.length > 0 ? "inconclusive" : "not-recovered-within-budget";
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
