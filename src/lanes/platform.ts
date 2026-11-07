import { createHash } from "node:crypto";
import type { Manifest, PlatformDecl } from "../model/manifest.js";
import type { EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome } from "../model/result.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { CS_ADHOC, CS_LINKER_SIGNED, CS_RUNTIME, looksLikeMachO, parseDetachedCodeDirectory, readMachO, slotHash, type CodeDirectoryInfo, type MachOInfo } from "../codecs/macho.js";
import { isDict, parsePlist, type PlistValue } from "../codecs/plist.js";
import type { Inventory, InventoryItem } from "./types.js";
import { readRaw } from "./types.js";

/**
 * Platform lane (research §14 stage 2: platform adapters; stage 3: tamper resistance, statically).
 *
 * It reads what the shipped bytes say about how the release is protected:
 * - **macOS code signing:** per Mach-O file, whether it is signed, ad hoc or Developer-ID (CMS
 *   present), its team ID, hardened runtime and entitlements. Every code-page hash is re-verified,
 *   and so is each bundle's seal: the Info.plist and CodeResources slot hashes, every sealed
 *   resource's SHA-256, nested-code cdhashes, and files added after signing.
 * - **Electron:** the fuse wire (RunAsNode, OnlyLoadAppFromAsar, asar-integrity validation…) and,
 *   on macOS, the `ElectronAsarIntegrity` header hashes against each shipped `.asar`.
 * - **Windows:** whether PE files carry an Authenticode signature.
 *
 * Owner-declared expectations in `manifest.platform` turn facts into gate findings
 * (`platformHardeningViolation`). Nothing here validates certificate CHAINS: a self-made signature can
 * be internally consistent. Chain trust needs `codesign --verify`, Gatekeeper or signtool.
 */

// ---------------------------------------------------------------- Electron fuses

/** The Electron fuse sentinel (`@electron/fuses`); it is followed by a version byte, a length byte and one byte per fuse. */
const FUSE_SENTINEL = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1");
/** Fuse order of wire version 1, as defined by `@electron/fuses` (FuseV1Options). */
export const FUSE_NAMES = [
  "RunAsNode",
  "EnableCookieEncryption",
  "EnableNodeOptionsEnvironmentVariable",
  "EnableNodeCliInspectArguments",
  "EnableEmbeddedAsarIntegrityValidation",
  "OnlyLoadAppFromAsar",
  "LoadBrowserProcessSpecificV8Snapshot",
  "GrantFileProtocolExtraPrivileges",
  "WasmTrapHandlers",
] as const;
export type FuseName = (typeof FUSE_NAMES)[number];
export type FuseState = "enabled" | "disabled" | "removed" | "unknown";

export interface FuseWire {
  readonly path: string;
  readonly version: number;
  readonly fuses: Readonly<Record<string, FuseState>>;
}

export function readFuses(buf: Buffer): { version: number; fuses: Record<string, FuseState> } | null {
  const at = buf.indexOf(FUSE_SENTINEL);
  if (at === -1) return null;
  const p = at + FUSE_SENTINEL.length;
  if (p + 2 > buf.length) return null;
  const version = buf[p]!;
  const n = buf[p + 1]!;
  if (p + 2 + n > buf.length) return null;
  const fuses: Record<string, FuseState> = {};
  for (let i = 0; i < n; i++) {
    const c = buf[p + 2 + i]!;
    const name = version === 1 && i < FUSE_NAMES.length ? FUSE_NAMES[i]! : `fuse${i}`;
    fuses[name] = c === 0x31 ? "enabled" : c === 0x30 ? "disabled" : c === 0x72 ? "removed" : "unknown";
  }
  return { version, fuses };
}

// ---------------------------------------------------------------- facts

export interface MachOFact {
  readonly path: string;
  readonly slices: readonly {
    readonly arch: string;
    readonly filetype: string;
    readonly signed: boolean;
    readonly adhoc: boolean;
    readonly linkerSigned: boolean;
    readonly developerSigned: boolean;
    readonly hardenedRuntime: boolean;
    readonly identifier?: string;
    readonly teamId?: string;
    readonly cdhashes: readonly string[];
    readonly badPages: number;
    readonly entitlements: readonly string[];
    readonly error?: string;
  }[];
}

export interface BundleFact {
  readonly path: string; // bundle root (…/X.app or …/X.framework/Versions/A)
  readonly kind: "app" | "framework";
  readonly executable?: string;
  readonly identifier?: string;
  /** Seal problems; empty when the bundle's seal is intact. */
  readonly sealProblems: readonly string[];
  readonly sealedFiles: number;
  /** Electron ASAR integrity, when declared in Info.plist. */
  readonly asarIntegrity?: readonly { readonly file: string; readonly declared: string; readonly actual?: string; readonly absent?: boolean; readonly ok: boolean }[];
}

export interface PeFact {
  readonly path: string;
  readonly authenticode: boolean;
}

export interface PlatformFacts {
  readonly machO: readonly MachOFact[];
  readonly bundles: readonly BundleFact[];
  readonly fuses: readonly FuseWire[];
  readonly pe: readonly PeFact[];
  readonly errors: readonly string[];
}

const hex = (b: PlistValue | undefined) => (Buffer.isBuffer(b) ? b.toString("hex") : undefined);

function peFact(path: string, b: Buffer): PeFact | null {
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return null;
  const pe = b.readUInt32LE(0x3c);
  if (pe + 24 > b.length || b.readUInt32LE(pe) !== 0x00004550) return null;
  const opt = pe + 24;
  const magic = b.readUInt16LE(opt);
  const dirs = magic === 0x20b ? opt + 112 : magic === 0x10b ? opt + 96 : -1;
  if (dirs < 0 || dirs + 5 * 8 > b.length) return { path, authenticode: false };
  const size = b.readUInt32LE(dirs + 4 * 8 + 4); // IMAGE_DIRECTORY_ENTRY_SECURITY
  return { path, authenticode: size > 8 };
}

function machOFact(path: string, m: MachOInfo): MachOFact {
  return {
    path,
    slices: m.slices.map((s) => {
      const cd = s.codeDirectories[0];
      return {
        arch: s.arch,
        filetype: s.filetype,
        signed: s.signed && !!cd,
        adhoc: !!cd && (cd.flags & CS_ADHOC) !== 0,
        linkerSigned: !!cd && (cd.flags & CS_LINKER_SIGNED) !== 0,
        developerSigned: !!cd && (cd.flags & CS_ADHOC) === 0 && s.hasCmsSignature,
        hardenedRuntime: !!cd && (cd.flags & CS_RUNTIME) !== 0,
        ...(cd?.identifier ? { identifier: cd.identifier } : {}),
        ...(cd?.teamId ? { teamId: cd.teamId } : {}),
        cdhashes: s.codeDirectories.map((c) => c.cdhash),
        badPages: s.codeDirectories.reduce((n, c) => n + c.badPages, 0),
        entitlements: Object.entries(s.entitlements ?? {})
          .filter(([, v]) => v !== false)
          .map(([k]) => k)
          .sort(),
        ...(s.error ? { error: s.error } : {}),
      };
    }),
  };
}

/** Pick the highest-weight CodeResources rule matching a path (Apple's resource-rules semantics). */
function bestRule(rules: { re: RegExp; omit: boolean; nested: boolean; optional: boolean; weight: number }[], rel: string) {
  let best: (typeof rules)[number] | null = null;
  for (const r of rules) if (r.re.test(rel) && (!best || r.weight > best.weight)) best = r;
  return best;
}

/** Bundle layout for an Info.plist path: macOS app-style (Contents/), versioned or shallow framework. */
function bundleOfInfo(path: string): { bundle: string; root: string; kind: "app" | "framework"; exeDir: string } | null {
  let m = /^(.*?[^/!]+\.(?:app|xpc|appex|bundle|plugin|docktileplugin|kext|systemextension|dext|qlgenerator|mdimporter|saver|prefPane|component|vst3?|driver|service))\/Contents\/Info\.plist$/.exec(path);
  if (m) return { bundle: m[1]!, root: `${m[1]}/Contents`, kind: "app", exeDir: `${m[1]}/Contents/MacOS` };
  m = /^(.*?[^/!]+\.framework)(\/Versions\/[^/]+)?\/Resources\/Info\.plist$/.exec(path);
  if (m) return { bundle: m[2] ? m[1]! + m[2] : m[1]!, root: m[1]! + (m[2] ?? ""), kind: "framework", exeDir: m[1]! + (m[2] ?? "") };
  return null;
}

/** CFBundle's executable lookup: CFBundleExecutable, else the bundle's name without its extension. */
function exeNameOf(info: { [k: string]: PlistValue }, bundlePath: string): string {
  if (typeof info.CFBundleExecutable === "string") return info.CFBundleExecutable;
  const base = bundlePath.replace(/\/Versions\/[^/]+$/, "").split("/").pop() ?? "";
  return base.replace(/\.[^.]+$/, "");
}

/**
 * Minimal designated-requirement check for sealed nested code. codesign validates nested code against
 * the recorded requirement (not the recorded cdhash, which goes stale when a helper is re-signed);
 * we check the two clauses that carry identity: `identifier "X"` and `certificate leaf[subject.OU] = T`.
 */
function satisfiesRequirement(req: string, ident: string | undefined, team: string | undefined): boolean {
  const id = /identifier "?([^"\s)]+)"?/.exec(req)?.[1];
  const ou = /leaf\[subject\.OU\]\s*=\s*"?([A-Z0-9]+)"?/.exec(req)?.[1];
  return (id === undefined || id === ident) && (ou === undefined || ou === team);
}

export function collectPlatformFacts(inv: Inventory): PlatformFacts {
  const byPath = new Map<string, InventoryItem>();
  for (const i of inv.items) if (i.ref.sha256) byPath.set(i.ref.path, i);
  const machO: MachOFact[] = [];
  const machInfo = new Map<string, MachOInfo>();
  const fuses: FuseWire[] = [];
  const pe: PeFact[] = [];
  const errors: string[] = [];

  for (const it of inv.items) {
    if (!it.supported || !it.source) continue;
    const b = readRaw(it);
    if (!b || b.length < 64) continue;
    if (looksLikeMachO(b)) {
      try {
        const m = readMachO(b);
        machInfo.set(it.ref.path, m);
        machO.push(machOFact(it.ref.path, m));
      } catch (e) {
        errors.push(`${it.ref.path}: ${(e as Error).message}`);
      }
    } else {
      const p = peFact(it.ref.path, b);
      if (p) pe.push(p);
    }
    if (b.indexOf(FUSE_SENTINEL) !== -1) {
      const f = readFuses(b);
      if (f) fuses.push({ path: it.ref.path, ...f });
    }
  }

  // ---- bundles: apps (and XPC services, plug-ins) and frameworks
  const bundles: BundleFact[] = [];
  for (const it of inv.items) {
    const lay = bundleOfInfo(it.ref.path);
    if (!lay) continue;
    const app = lay.kind === "app";
    const kind = lay.kind;
    const root = lay.root;
    const problems: string[] = [];
    let info: PlistValue;
    const infoBytes = readRaw(it);
    try {
      info = parsePlist(infoBytes!);
    } catch (e) {
      bundles.push({ path: lay.bundle, kind, sealProblems: [`Info.plist unreadable: ${(e as Error).message}`], sealedFiles: 0 });
      continue;
    }
    if (!isDict(info)) continue;
    const exeName = exeNameOf(info, lay.bundle);
    const exeCandidate = `${lay.exeDir}/${exeName}`;
    const exePath = typeof info.CFBundleExecutable === "string" || byPath.has(exeCandidate) ? exeCandidate : undefined;
    const mi = exePath ? machInfo.get(exePath) : undefined;
    const bundlePath = lay.bundle;
    const fact: { -readonly [K in keyof BundleFact]: BundleFact[K] } = {
      path: bundlePath,
      kind,
      ...(exePath ? { executable: exePath } : {}),
      ...(typeof info.CFBundleIdentifier === "string" ? { identifier: info.CFBundleIdentifier } : {}),
      sealProblems: problems,
      sealedFiles: 0,
    };

    // Electron ASAR integrity (macOS): { "Resources/app.asar": { algorithm: "SHA256", hash: "<hex>" } }
    const integ = info.ElectronAsarIntegrity;
    if (isDict(integ)) {
      fact.asarIntegrity = Object.entries(integ).map(([file, d]) => {
        const declared = isDict(d) && typeof d.hash === "string" ? d.hash.toLowerCase() : "";
        const item = byPath.get(`${root}/${file}`);
        const raw = item ? readRaw(item) : null;
        let actual: string | undefined;
        if (raw && raw.length >= 16 && raw.readUInt32LE(0) === 4) {
          const len = raw.readUInt32LE(12);
          if (16 + len <= raw.length) actual = createHash("sha256").update(raw.subarray(16, 16 + len)).digest("hex");
        }
        // A declared archive that is not shipped is never loaded, so there is nothing to validate.
        if (!item) return { file, declared, absent: true, ok: true };
        return { file, declared, ...(actual ? { actual } : {}), ok: !!actual && actual === declared };
      });
    }

    // ---- seal: CodeDirectory special slots, sealed resources, added files
    // Resource-only bundles (no executable, no own signature) are sealed file-by-file by the enclosing bundle.
    // Code-less bundles that ARE signed keep a detached CodeDirectory whose code slots cover Info.plist.
    const detached = !exePath ? byPath.get(`${root}/_CodeSignature/CodeDirectory`) : undefined;
    if (!exePath && !detached) {
      if (fact.asarIntegrity) bundles.push(fact); // keep integrity facts; there is no seal of its own to check
      continue;
    }
    let primary: CodeDirectoryInfo[];
    if (detached) {
      try {
        primary = [parseDetachedCodeDirectory(readRaw(detached)!, infoBytes!)];
      } catch (e) {
        problems.push(`detached CodeDirectory unreadable: ${(e as Error).message}`);
        bundles.push(fact);
        continue;
      }
      if (primary[0]!.badPages > 0) problems.push("Info.plist does not match the detached signature");
    } else if (!mi) {
      problems.push(`main executable ${exePath} missing or not Mach-O`);
      bundles.push(fact);
      continue;
    } else primary = mi.slices.map((s) => s.codeDirectories[0]).filter((c): c is CodeDirectoryInfo => !!c);
    if (primary.length === 0) {
      problems.push("main executable is not signed");
      bundles.push(fact);
      continue;
    }
    for (const s of mi?.slices ?? []) for (const cd of s.codeDirectories) if (cd.badPages > 0) problems.push(`${s.arch}: ${cd.badPages} code page(s) of the main executable do not match the signature`);
    const resPath = `${root}/_CodeSignature/CodeResources`;
    const resItem = byPath.get(resPath);
    const resBytes = resItem ? readRaw(resItem) : null;
    for (const cd of primary) {
      const want1 = cd.specialSlots[1];
      if (want1 && infoBytes && slotHash(cd, infoBytes) !== want1) problems.push("Info.plist was modified after signing");
      const want3 = cd.specialSlots[3];
      if (want3) {
        if (!resBytes) problems.push("sealed-resources file _CodeSignature/CodeResources is missing");
        else if (slotHash(cd, resBytes) !== want3) problems.push("_CodeSignature/CodeResources was modified after signing");
      }
    }
    if (resBytes && primary.some((cd) => cd.specialSlots[3])) {
      let res: PlistValue;
      try {
        res = parsePlist(resBytes);
      } catch (e) {
        problems.push(`CodeResources unreadable: ${(e as Error).message}`);
        bundles.push(fact);
        continue;
      }
      const files2 = isDict(res) && isDict(res.files2) ? res.files2 : {};
      const rules2 = isDict(res) && isDict(res.rules2) ? res.rules2 : {};
      const rules = Object.entries(rules2).flatMap(([pat, v]) => {
        try {
          const o = isDict(v) ? v : {};
          return [{ re: new RegExp(pat), omit: o.omit === true, nested: o.nested === true, optional: o.optional === true, weight: typeof o.weight === "number" ? o.weight : 1 }];
        } catch {
          return [];
        }
      });
      const sealed = new Set<string>();
      for (const [rel, spec] of Object.entries(files2)) {
        sealed.add(rel);
        fact.sealedFiles++;
        const full = `${root}/${rel}`;
        const s = isDict(spec) ? spec : { hash2: spec };
        if (typeof s.symlink === "string") continue; // symlinks are recorded, not followed
        const optional = s.optional === true;
        if (s.cdhash !== undefined) {
          // nested code: a bundle or a standalone Mach-O; compare with any cdhash of its main binary
          const want = hex(s.cdhash);
          let target = machInfo.get(full);
          if (!target) {
            const infos = [`${full}/Contents/Info.plist`, `${full}/Resources/Info.plist`, ...[...byPath.keys()].filter((p) => p.startsWith(`${full}/Versions/`) && /^[^/]+\/Resources\/Info\.plist$/.test(p.slice(full.length + 10)))];
            for (const ip of infos) {
              const lay2 = byPath.has(ip) ? bundleOfInfo(ip) : null;
              if (!lay2) continue;
              try {
                const ni = parsePlist(readRaw(byPath.get(ip)!)!);
                if (isDict(ni)) target = machInfo.get(`${lay2.exeDir}/${exeNameOf(ni, lay2.bundle)}`);
              } catch {}
              if (target) break;
            }
          }
          if (!target) {
            if (!optional) problems.push(`sealed nested code ${rel} is missing`);
            continue;
          }
          const cds = target.slices.flatMap((x) => x.codeDirectories);
          if (typeof s.requirement === "string") {
            if (!cds.some((c) => satisfiesRequirement(s.requirement as string, c.identifier, c.teamId))) problems.push(`nested code ${rel} does not satisfy its sealed requirement`);
            continue;
          }
          const have = new Set(cds.map((c) => c.cdhash));
          if (want && !have.has(want)) problems.push(`nested code ${rel} does not match its sealed cdhash`);
          continue;
        }
        const want = hex(s.hash2) ?? undefined;
        const item = byPath.get(full);
        if (!item) {
          if (!optional) problems.push(`sealed resource ${rel} is missing`);
          continue;
        }
        if (want && item.ref.sha256 !== want) problems.push(`sealed resource ${rel} was modified after signing`);
      }
      // files added after signing: under this bundle, not sealed, not omitted, not inside nested code
      for (const p of byPath.keys()) {
        if (!p.startsWith(`${root}/`)) continue;
        const rel = p.slice(root.length + 1);
        if (rel.includes("!/")) continue; // entries of a container: the container itself is sealed
        if (sealed.has(rel) || rel === "Info.plist" || rel.startsWith("_CodeSignature/") || rel === "CodeResources" || rel.startsWith("_MASReceipt/") || `${root}/${rel}` === exePath) continue;
        if ([...sealed].some((s) => rel.startsWith(`${s}/`))) continue; // inside sealed nested code
        const r = bestRule(rules, rel);
        if (r && r.omit) continue;
        problems.push(`file ${rel} was added after signing (not in the bundle seal)`);
      }
    }
    bundles.push(fact);
  }
  return { machO, bundles, fuses, pe, errors };
}

// ---------------------------------------------------------------- expectations → evidence

export const DEFAULT_FORBIDDEN_ENTITLEMENTS = [
  "com.apple.security.get-task-allow", // lets any process attach a debugger: a development build
  "com.apple.security.cs.allow-dyld-environment-variables", // DYLD_INSERT_LIBRARIES code injection
  "com.apple.security.cs.disable-executable-page-protection",
];

export function platformLane(manifest: Manifest, inv: Inventory, startedAt: string, facts = collectPlatformFacts(inv)): EvidenceRecord {
  const decl: PlatformDecl = manifest.platform ?? {};
  const findings: Finding[] = [];
  const limitations: string[] = [
    "Code-signature checks verify page and resource hashes against the shipped bytes; certificate chains, notarization and revocation are not validated (use codesign/spctl or signtool for chain trust).",
  ];
  let inconclusive = false;
  const v = (id: string, title: string, detail: string, path?: string) =>
    findings.push({
      id: `platform/${id}`,
      title,
      severity: "high",
      confidence: "confirmed",
      gate: "platformHardeningViolation",
      ...(path ? { artifact: inv.items.find((i) => i.ref.path === path)?.ref ?? { path, sha256: "", bytes: 0 } } : {}),
      detail,
    });

  const mac = decl.macos;
  if (mac) {
    if (facts.machO.length === 0) {
      inconclusive = true;
      limitations.push("manifest.platform.macos is declared but the release contains no Mach-O code.");
    }
    const forbidden = new Set(mac.forbiddenEntitlements ?? DEFAULT_FORBIDDEN_ENTITLEMENTS);
    for (const f of facts.machO) {
      for (const s of f.slices) {
        const where = `${f.path} (${s.arch})`;
        if (s.error) v(`macho-unreadable/${f.path}/${s.arch}`, "Mach-O code signature unreadable", `${where}: ${s.error}`, f.path);
        if (mac.requireSigned !== false && !s.signed) v(`unsigned/${f.path}/${s.arch}`, "Unsigned Mach-O code", `${where} has no code signature`, f.path);
        if (mac.requireDeveloperId && s.signed && !s.developerSigned) v(`not-developer-signed/${f.path}/${s.arch}`, "Mach-O code is ad hoc or linker-signed, not Developer-ID signed", where, f.path);
        if (s.badPages > 0) v(`tampered-code/${f.path}/${s.arch}`, "Mach-O code modified after signing", `${where}: ${s.badPages} code page(s) do not match the signature`, f.path);
        if (mac.teamId && s.signed && s.developerSigned && s.teamId !== mac.teamId)
          v(`team/${f.path}/${s.arch}`, "Code signed by an unexpected team", `${where}: TeamIdentifier ${s.teamId ?? "none"}, expected ${mac.teamId}`, f.path);
        if (mac.requireHardenedRuntime && s.filetype === "execute" && !s.hardenedRuntime)
          v(`no-hardened-runtime/${f.path}/${s.arch}`, "Executable without the hardened runtime", where, f.path);
        for (const e of s.entitlements) if (forbidden.has(e)) v(`entitlement/${f.path}/${e}`, `Forbidden entitlement ${e}`, `${where} is signed with ${e}`, f.path);
      }
    }
    if (mac.requireIntactSeal !== false)
      for (const b of facts.bundles) for (const pr of b.sealProblems) v(`seal/${b.path}/${pr}`, "Bundle seal broken", `${b.path}: ${pr}`, b.executable ?? b.path);
  }

  const el = decl.electron;
  if (el) {
    if (el.fuses && Object.keys(el.fuses).length > 0) {
      if (facts.fuses.length === 0) {
        inconclusive = true;
        limitations.push("manifest.platform.electron.fuses is declared but no Electron fuse wire was found in the release.");
      }
      for (const w of facts.fuses)
        for (const [name, want] of Object.entries(el.fuses)) {
          const st = w.fuses[name];
          const ok = st === undefined ? false : want ? st === "enabled" : st === "disabled" || st === "removed";
          if (!ok) v(`fuse/${w.path}/${name}`, `Electron fuse ${name} is ${st ?? "absent"}`, `${w.path}: expected ${name} ${want ? "enabled" : "disabled"}`, w.path);
        }
    }
    if (el.requireAsarIntegrity) {
      const apps = facts.bundles.filter((b) => b.kind === "app" && /(?:^|\/)[^/]+\.app$/.test(b.path) && !/\.app\/Contents\/Frameworks\//.test(b.path));
      const asars = inv.items.filter((i) => /\.app\/Contents\/Resources\/[^/]+\.asar$/.test(i.ref.path));
      if (apps.length === 0 && asars.length > 0) {
        inconclusive = true;
        limitations.push("ASAR integrity is required, but the .asar files are not inside a macOS app bundle with an Info.plist; Windows/Linux integrity resources are not read by this version.");
      }
      for (const a of asars) {
        const bundle = apps.find((b) => a.ref.path.startsWith(`${b.path}/`));
        if (!bundle) continue;
        const rel = a.ref.path.slice(bundle.path.length + "/Contents/".length);
        const entry = bundle.asarIntegrity?.find((x) => x.file === rel);
        if (!entry) v(`asar-integrity-missing/${a.ref.path}`, "ASAR archive without an integrity hash", `${a.ref.path} is not listed in ElectronAsarIntegrity`, a.ref.path);
        else if (!entry.ok) v(`asar-integrity-mismatch/${a.ref.path}`, "ASAR header does not match its integrity hash", `${a.ref.path}: declared ${entry.declared.slice(0, 12)}…, actual ${entry.actual?.slice(0, 12) ?? "unreadable"}…`, a.ref.path);
      }
    }
  }

  if (decl.windows?.requireAuthenticode)
    for (const p of facts.pe) if (!p.authenticode) v(`no-authenticode/${p.path}`, "PE file without an Authenticode signature", p.path, p.path);

  for (const e of facts.errors) limitations.push(e);
  const outcome: Outcome = inconclusive ? "inconclusive" : findings.length > 0 ? "recovered" : "not-recovered-within-budget";
  return {
    id: "platform/hardening",
    lane: "platform",
    releaseId: inv.releaseId,
    tool: TOOL,
    invocation: { expectations: decl },
    accessGranted: "delivered artifacts, read-only",
    budget: { declared: "static inspection of every shipped Mach-O, PE and bundle" },
    outcome,
    coverage: {
      artifactsConsidered: facts.machO.length + facts.pe.length + facts.bundles.length,
      artifactsSupported: facts.machO.length + facts.pe.length + facts.bundles.length,
      artifactsUnsupported: facts.errors.length,
      notes: [
        `${facts.machO.length} Mach-O file(s), ${facts.bundles.length} bundle(s), ${facts.fuses.length} Electron fuse wire(s), ${facts.pe.length} PE file(s)`,
      ],
    },
    limitations,
    findings,
    startedAt,
    finishedAt: nowIso(),
  };
}
