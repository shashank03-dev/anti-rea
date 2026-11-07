import { closeSync, openSync, readSync } from "node:fs";
import type { ArtifactRef, EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome } from "../model/result.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { isDict, parsePlist } from "../codecs/plist.js";
import { readAndroidManifest } from "../codecs/axml.js";
import { BUNDLE_ANALYZERS, ITEM_ANALYZERS } from "../analyzers/index.js";
import { graded, type Analyzer, type BundleContext, type BundleGroup, type ItemContext, type ProfileTags, type RawFinding, type RecoveryFinding } from "../analyzers/types.js";
import { attribute, emptyProfile, sameVendor, type ProductProfile } from "../analyzers/attribution.js";
import { redact } from "../analyzers/redact.js";
import { severityRank } from "../analyzers/rubric.js";
import type { Inventory, InventoryItem, ItemSource } from "./types.js";
import { contentCoverage, readItem, readRaw, scannable, unsupported } from "./types.js";

/**
 * Recovery lane (v0.8 exposure): drive the analyzers over the inventory, attribute every finding owner
 * vs third-party, redact what they say, and emit the findings plus one gate-free EvidenceRecord. This
 * lane is standalone — `assure` never runs it (plan item 13), so the hard-gate path is untouched by
 * construction.
 */

export interface RecoveryResult {
  readonly profile: ProductProfile;
  readonly findings: readonly RecoveryFinding[];
  readonly record: EvidenceRecord;
  /** Opaque or unanalysed artifacts, named so coverage stays honest. */
  readonly opaque: readonly string[];
}

export interface RecoveryOptions {
  readonly app?: { readonly name?: string; readonly version?: string };
}

const HEAD_SNIFF = 4096;
/** A bundle's Info.plist: macOS (`Contents/`), versioned or shallow frameworks, and iOS (at the bundle root). */
const INFO_PLIST = /(?:^|\/)([^/!]+\.(?:app|framework|xpc|appex|bundle|plugin))\/(?:Contents\/|Versions\/[^/]+\/Resources\/|Resources\/)?Info\.plist$/;
const APP_PLIST = /\.app\/(?:Contents\/)?Info\.plist$/;

/** Read the first `n` bytes of an item's bytes source (for header-only analyzers on gap items). */
function readHead(src: ItemSource, n: number): Buffer {
  if (src.kind === "mem") return src.buf.subarray(0, n);
  const fd = openSync(src.abs, "r");
  try {
    const buf = Buffer.alloc(n);
    return buf.subarray(0, readSync(fd, buf, 0, n, 0));
  } finally {
    closeSync(fd);
  }
}

function mergeTags(profile: ProductProfile, tags: ProfileTags | null | undefined): void {
  if (!tags) return;
  const add = (into: string[], from?: readonly string[]) => {
    for (const v of from ?? []) if (v && !into.includes(v)) into.push(v);
  };
  add(profile.platforms, tags.platforms);
  add(profile.frameworks, tags.frameworks);
  add(profile.languages, tags.languages);
}

function plistDict(it: InventoryItem): Record<string, unknown> | null {
  try {
    const buf = readItem(it);
    const v = buf ? parsePlist(buf) : null;
    return v && isDict(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Info.plist items, outermost bundle first. */
function infoPlists(inv: Inventory): InventoryItem[] {
  return inv.items.filter((i) => i.source && INFO_PLIST.test(i.ref.path)).sort((a, b) => a.ref.path.split("/").length - b.ref.path.split("/").length);
}

/**
 * Best-effort app identity from the release's own metadata: the OUTERMOST .app Info.plist (a nested
 * helper or updater such as Sparkle's Updater.app must not win), else an APK's binary manifest, else
 * a non-dependency package.json. Shared by the CLI and the MCP server.
 */
export function detectApp(inv: Inventory, fallback: string): { name: string; version: string } {
  const app = infoPlists(inv).find((i) => APP_PLIST.test(i.ref.path));
  const d = app ? plistDict(app) : null;
  if (d) {
    const name = typeof d.CFBundleName === "string" ? d.CFBundleName : typeof d.CFBundleDisplayName === "string" ? d.CFBundleDisplayName : fallback;
    const version = typeof d.CFBundleShortVersionString === "string" ? d.CFBundleShortVersionString : typeof d.CFBundleVersion === "string" ? d.CFBundleVersion : "(unknown)";
    return { name, version };
  }
  const manifest = inv.items.find((i) => i.source && /\.(?:apk|aab)!\/AndroidManifest\.xml$/i.test(i.ref.path));
  if (manifest) {
    const m = readAndroidManifest(readItem(manifest) ?? Buffer.alloc(0));
    if (m.package) return { name: m.package, version: m.versionName ?? "(unknown)" };
  }
  const pkg = inv.items
    .filter((i) => i.source && /(?:^|\/)package\.json$/.test(i.ref.path) && !/node_modules/.test(i.ref.path))
    .sort((a, b) => a.ref.path.split(/\/|!\//).length - b.ref.path.split(/\/|!\//).length)[0];
  if (pkg) {
    try {
      const j = JSON.parse(readItem(pkg)!.toString("utf8")) as { name?: unknown; version?: unknown };
      if (typeof j.name === "string") return { name: j.name, version: typeof j.version === "string" ? j.version : "(unknown)" };
    } catch {
      /* ignore */
    }
  }
  return { name: fallback, version: "(unknown)" };
}

/**
 * The app's bundle-id prefix, and the bundled frameworks/helpers whose bundle id is NOT the app's (plan
 * item 5: "frameworks whose bundle ID prefix differs from the app's"). The outermost bundle is the app.
 */
function bundleVendors(inv: Inventory, profile: ProductProfile): void {
  const plists = infoPlists(inv);
  const appPlist = plists.find((i) => APP_PLIST.test(i.ref.path));
  const appId = appPlist ? plistDict(appPlist)?.CFBundleIdentifier : undefined;
  if (typeof appId !== "string" || !appId.includes(".")) return;
  profile.bundleIdPrefix = appId.split(".").slice(0, 2).join(".");
  for (const it of plists) {
    if (it === appPlist) continue;
    const id = plistDict(it)?.CFBundleIdentifier;
    const m = INFO_PLIST.exec(it.ref.path);
    if (typeof id !== "string" || !m) continue;
    if (sameVendor(id, profile.bundleIdPrefix)) continue;
    // The bundle directory ends where the matched bundle name ends (by match position, not by searching).
    const end = m.index + (m[0].startsWith("/") ? 1 : 0) + m[1]!.length;
    const root = it.ref.path.slice(0, end).replace(/!\//g, "/");
    if (!profile.vendorRoots.includes(root)) profile.vendorRoots.push(root);
  }
}

/** Groups for bundle analyzers, one at a time: each expanded container, then the release itself. */
function* groupsFor(inv: Inventory): Generator<BundleGroup> {
  const children = new Map<string, InventoryItem[]>();
  const top: InventoryItem[] = [];
  for (const it of inv.items) {
    if (it.parent === undefined) top.push(it);
    else {
      const list = children.get(it.parent);
      if (list) list.push(it);
      else children.set(it.parent, [it]);
    }
  }
  const lazy = (it: InventoryItem) => {
    let memo: Buffer | null | undefined;
    return () => (memo === undefined ? (memo = readRaw(it)) : memo);
  };
  for (const it of inv.items) if (it.kind === "container" && it.supported) yield { root: it.ref.path, raw: lazy(it), entries: children.get(it.ref.path) ?? [] };
  // The release group: top-level disk files (desktop Unity/Flutter layouts live here, not in a container).
  yield { root: "", raw: () => null, entries: top };
}

/** Segment-aware `entry()` lookup: an index by file name, then a tail check for multi-segment suffixes. */
function entryIndex(entries: readonly InventoryItem[]): (suffix: string) => InventoryItem | undefined {
  const byName = new Map<string, InventoryItem[]>();
  const relOf = (e: InventoryItem) => e.ref.path.split("!/").pop() ?? e.ref.path;
  for (const e of entries) {
    const rel = relOf(e);
    const name = rel.slice(rel.lastIndexOf("/") + 1);
    const list = byName.get(name);
    if (list) list.push(e);
    else byName.set(name, [e]);
  }
  return (suffix: string) => {
    const name = suffix.slice(suffix.lastIndexOf("/") + 1);
    const candidates = byName.get(name);
    if (!candidates) return undefined;
    if (!suffix.includes("/")) return candidates[0];
    return candidates.find((e) => {
      const rel = relOf(e);
      return rel === suffix || rel.endsWith(`/${suffix}`);
    });
  };
}

function safeDetect(a: Analyzer, ctx: ItemContext | BundleContext, limitations: string[]): boolean {
  try {
    return a.detect(ctx);
  } catch (e) {
    limitations.push(`${a.id} detection failed: ${(e as Error).message}`);
    return false;
  }
}

export function recoveryLane(inv: Inventory, startedAt: string, opts: RecoveryOptions = {}): RecoveryResult {
  const profile = emptyProfile(opts.app?.name ?? "(unknown)", opts.app?.version ?? "(unknown)");
  bundleVendors(inv, profile);
  const raws: RawFinding[] = [];
  const limitations: string[] = [];
  const tagsFromOwner = (path: string, tags: ProfileTags | null | undefined) => {
    // The profile describes the product, so a vendored Go binary in node_modules does not make it "Go".
    if (attribute(path, profile) === "owner") mergeTags(profile, tags);
  };
  const guard = (analyzerId: string, path: string, fn: () => RawFinding[]): RawFinding[] => {
    try {
      return fn();
    } catch (e) {
      limitations.push(`${analyzerId} on ${path}: analysis failed (${(e as Error).message}); its recovery facts are unknown.`);
      return [];
    }
  };

  // ---- item analyzers over scannable items
  for (const item of scannable(inv)) {
    const buf = readItem(item);
    if (!buf) continue;
    const ctx: ItemContext = { scope: "item", item, bytes: buf, complete: true, inv };
    for (const a of ITEM_ANALYZERS) {
      if (!safeDetect(a, ctx, limitations)) continue;
      tagsFromOwner(item.ref.path, a.profile?.(ctx));
      raws.push(...guard(a.id, item.ref.path, () => a.analyze(ctx)));
    }
  }

  // ---- header-only analyzers over gap items whose bytes are still peekable (a 7 GB model still has a header)
  const headOnly = ITEM_ANALYZERS.filter((a) => a.needs.head !== undefined && !a.needs.full && !a.needs.tail);
  const want = Math.max(HEAD_SNIFF, ...headOnly.map((a) => a.needs.head ?? 0));
  if (headOnly.length > 0)
    for (const item of inv.items) {
      if ((item.supported && item.source) || !item.peek) continue;
      let head: Buffer;
      try {
        head = readHead(item.peek, want);
      } catch {
        continue;
      }
      const complete = item.ref.bytes > 0 && head.length >= item.ref.bytes;
      const ctx: ItemContext = { scope: "item", item, bytes: head, complete, inv };
      for (const a of headOnly) {
        if (!safeDetect(a, ctx, limitations)) continue;
        tagsFromOwner(item.ref.path, a.profile?.(ctx));
        raws.push(...guard(a.id, item.ref.path, () => a.analyze(ctx)).map((f) => (complete ? f : { ...f, coverage: "partial" as const })));
      }
    }

  // ---- bundle analyzers over containers and the release group (one group in memory at a time)
  if (BUNDLE_ANALYZERS.length > 0)
    for (const group of groupsFor(inv)) {
      const ctx: BundleContext = { scope: "bundle", group, inv, read: (it) => readItem(it), entry: entryIndex(group.entries) };
      for (const a of BUNDLE_ANALYZERS) {
        if (!safeDetect(a, ctx, limitations)) continue;
        mergeTags(profile, a.profile?.(ctx));
        raws.push(...guard(a.id, group.root || "(release)", () => a.analyze(ctx)));
      }
    }

  // ---- attribution + redaction (of everything an analyzer says about the bytes), then rank.
  const findings: RecoveryFinding[] = raws.map((r) => {
    const f = graded(r, attribute(r.path, profile, r.origin));
    return { ...f, recovers: redact(f.recovers), ...(f.detail ? { detail: redact(f.detail) } : {}) };
  });
  findings.sort((a, b) => {
    if (a.origin !== b.origin) return a.origin === "owner" ? -1 : 1;
    const s = severityRank(b.severity) - severityRank(a.severity);
    if (s !== 0) return s;
    return a.path < b.path ? -1 : a.path > b.path ? 1 : a.analyzerId.localeCompare(b.analyzerId);
  });

  // ---- opaque / unanalysed artifacts, named for honesty.
  const opaque = unsupported(inv).map((u) => `${u.ref.path}: ${u.unsupportedReason}`);
  if (opaque.length > 0) limitations.push(`${opaque.length} artifact(s) could not be inspected; what a REA tool would recover from them is UNKNOWN.`);
  if (profile.vendorRoots.length > 0) limitations.push(`Attributed third-party by bundle id (not ${profile.bundleIdPrefix}.*): ${profile.vendorRoots.slice(0, 10).join("; ")}${profile.vendorRoots.length > 10 ? "; …" : ""}`);

  return { profile, findings, record: toRecord(inv, findings, limitations, startedAt), opaque };
}

function toRecord(inv: Inventory, findings: readonly RecoveryFinding[], limitations: string[], startedAt: string): EvidenceRecord {
  const refs = new Map<string, ArtifactRef>(inv.items.map((i) => [i.ref.path, i.ref]));
  const mapped: Finding[] = findings.map((f, i) => ({
    id: `recovery/${f.analyzerId}/${f.path}#${i}`,
    title: f.title,
    severity: f.severity,
    confidence: "confirmed",
    // NO gate: the recovery lane is advisory by construction (plan item 13; asserted in test/v08.test.ts).
    artifact: refs.get(f.path) ?? { path: f.path, sha256: "", bytes: 0 },
    ...(f.location ? { location: f.location } : {}),
    detector: f.analyzerId,
    detail: `[${f.surface}; ${f.origin}; ${f.avoidable ? "avoidable" : "inherent"}; ${f.coverage}] recovers: ${f.recovers}. Remediation: ${f.remediation}.`,
  }));
  const outcome: Outcome = findings.length > 0 ? "recovered" : "not-recovered-within-budget";
  return {
    id: "recovery",
    lane: "recovery",
    releaseId: inv.releaseId,
    tool: TOOL,
    invocation: { analyzers: [...ITEM_ANALYZERS, ...BUNDLE_ANALYZERS].map((a) => a.id) },
    accessGranted: "delivered release bytes (read-only); static inspection only",
    budget: { declared: "static inspection of every shipped artifact" },
    outcome,
    coverage: contentCoverage(inv),
    limitations: [
      "Advisory only: this lane reports what a REA-class tool would recover and the toolchain settings that reduce it. It never claims an app cannot be reverse engineered, and it trips no gate.",
      ...limitations,
    ],
    findings: mapped,
    startedAt,
    finishedAt: nowIso(),
  };
}
