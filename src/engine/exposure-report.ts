import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Severity } from "../model/result.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import type { ProductProfile } from "../analyzers/attribution.js";
import type { RecoveryFinding } from "../analyzers/types.js";
import { maxSeverity, severityRank, SURFACE_TITLE, type Surface } from "../analyzers/rubric.js";
import type { RecoveryResult } from "../lanes/recovery.js";

/**
 * Exposure report (v0.8): a report ABOUT the product (plan item 12), in two forms — `exposure.json`
 * (schema `anti-rea/exposure/v1`, machine-readable, always complete) and `exposure.md` (owner findings
 * first, third-party collapsed into counts unless asked for). Output is deterministic: sorted and
 * honouring `--now`.
 */

const SURFACE_ORDER: Surface[] = ["code", "symbols", "tamper", "mitigations", "models", "metadata"];

export interface ExposureReport {
  readonly schema: "anti-rea/exposure/v1";
  readonly tool: { readonly name: string; readonly version: string };
  readonly generatedAt: string;
  readonly releaseId: string;
  readonly product: {
    readonly name: string;
    readonly version: string;
    readonly platforms: readonly string[];
    readonly frameworks: readonly string[];
    readonly languages: readonly string[];
  };
  readonly summary: {
    readonly maxGrade: Severity | null;
    readonly ownerMaxGrade: Severity | null;
    readonly total: number;
    readonly owner: number;
    readonly thirdParty: number;
    readonly bySeverity: Readonly<Record<Severity, number>>;
    readonly surfaces: readonly Surface[];
  };
  readonly findings: readonly RecoveryFinding[];
  readonly checklist: readonly ChecklistItem[];
  readonly thirdParty: { readonly count: number; readonly bySeverity: Readonly<Record<Severity, number>>; readonly byAnalyzer: Readonly<Record<string, number>> };
  readonly coverage: {
    readonly artifactsConsidered: number;
    readonly artifactsSupported: number;
    readonly artifactsUnsupported: number;
    readonly opaque: readonly string[];
  };
  readonly matrix: readonly { readonly surface: Surface; readonly reports: string }[];
}

export interface ChecklistItem {
  readonly remediation: string;
  readonly surface: Surface;
  readonly severity: Severity; // max over the grouped findings
  readonly avoidable: boolean;
  readonly files: readonly string[];
}

const ZERO: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
const countsBy = (fs: readonly RecoveryFinding[]): Record<Severity, number> => {
  const c = { ...ZERO };
  for (const f of fs) c[f.severity]++;
  return c;
};

function buildChecklist(findings: readonly RecoveryFinding[]): ChecklistItem[] {
  const by = new Map<string, { surface: Surface; severity: Severity; avoidable: boolean; files: Set<string> }>();
  for (const f of findings) {
    const g = by.get(f.remediation) ?? { surface: f.surface, severity: f.severity, avoidable: f.avoidable, files: new Set<string>() };
    if (severityRank(f.severity) > severityRank(g.severity)) g.severity = f.severity;
    g.files.add(f.path);
    by.set(f.remediation, g);
  }
  return [...by.entries()]
    .map(([remediation, g]) => ({ remediation, surface: g.surface, severity: g.severity, avoidable: g.avoidable, files: [...g.files].sort().slice(0, 25) }))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.remediation.localeCompare(b.remediation));
}

const MATRIX: { surface: Surface; reports: string }[] = [
  { surface: "code", reports: "REA extracts original source (source maps, scripts, Mono IL). Anti-REA flags sourcesContent, shipped scripts and un-obfuscated managed code, with the toolchain fix." },
  { surface: "symbols", reports: "REA reconstructs names from DWARF/PDB/dSYM, stabs, .symtab and IL2CPP metadata. Anti-REA reports each, separating avoidable debug info from inherent runtime metadata." },
  { surface: "tamper", reports: "REA looks for debuggable/get-task-allow and weak signing. Anti-REA flags debug entitlements, insecure Electron settings, unsigned/ad-hoc code and v1-only APKs." },
  { surface: "mitigations", reports: "REA runs checksec-style checks. Anti-REA reports PIE/NX/RELRO/CFG on owner native code, language-aware so memory-safe toolchains are not false-flagged." },
  { surface: "models", reports: "REA reads model containers. Anti-REA reports plaintext GGUF/safetensors metadata (keys and architecture only, never values)." },
  { surface: "metadata", reports: "REA harvests build metadata. Anti-REA reports build paths, Go modules/VCS, cargo-auditable graphs and PDB paths, with secrets in ldflags redacted." },
];

export function buildExposureReport(result: RecoveryResult, profile: ProductProfile): ExposureReport {
  const findings = result.findings;
  const owner = findings.filter((f) => f.origin === "owner");
  const third = findings.filter((f) => f.origin === "third-party");
  const surfaces = SURFACE_ORDER.filter((s) => findings.some((f) => f.surface === s));
  const byAnalyzer: Record<string, number> = {};
  for (const f of third) byAnalyzer[f.analyzerId] = (byAnalyzer[f.analyzerId] ?? 0) + 1;
  const cov = result.record.coverage;
  return {
    schema: "anti-rea/exposure/v1",
    tool: TOOL,
    generatedAt: nowIso(),
    releaseId: result.record.releaseId,
    product: { name: profile.name, version: profile.version, platforms: [...profile.platforms].sort(), frameworks: [...profile.frameworks].sort(), languages: [...profile.languages].sort() },
    summary: {
      maxGrade: maxSeverity(findings.map((f) => f.severity)),
      ownerMaxGrade: maxSeverity(owner.map((f) => f.severity)),
      total: findings.length,
      owner: owner.length,
      thirdParty: third.length,
      bySeverity: countsBy(findings),
      surfaces,
    },
    findings,
    checklist: buildChecklist(owner),
    thirdParty: { count: third.length, bySeverity: countsBy(third), byAnalyzer },
    coverage: { artifactsConsidered: cov.artifactsConsidered, artifactsSupported: cov.artifactsSupported, artifactsUnsupported: cov.artifactsUnsupported, opaque: result.opaque },
    matrix: MATRIX.filter((m) => surfaces.includes(m.surface) || findings.length === 0),
  };
}

// ---------------------------------------------------------------- markdown

/**
 * Text derived from the release (file names, symbol names, module paths) is untrusted and is rendered in
 * places such as a GitHub step summary: escape table pipes, line breaks, HTML and link syntax.
 */
const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\]\(/g, "]\\(");
/** An inline code span that cannot be broken out of by a backtick in a file name. */
const code = (s: string) => `\`${esc(s).replace(/`/g, "'")}\``;
const GRADE = (s: Severity | null) => (s ? s.toUpperCase() : "none");

/** Collapse findings that differ only in detail (one per slice of a fat binary): same analyzer, title and path. */
function collapse(fs: readonly RecoveryFinding[]): { f: RecoveryFinding; n: number }[] {
  const out: { f: RecoveryFinding; n: number }[] = [];
  const at = new Map<string, number>();
  for (const f of fs) {
    const key = `${f.analyzerId}\u0000${f.title}\u0000${f.path}`;
    const i = at.get(key);
    if (i === undefined) {
      at.set(key, out.length);
      out.push({ f, n: 1 });
    } else out[i]!.n++;
  }
  return out;
}

/** A short terminal summary (the Markdown file carries the full report). */
export function renderExposureSummary(r: ExposureReport, max = 10): string {
  const s = r.summary;
  const lines = [
    `anti-rea expose: ${r.product.name} ${r.product.version}  release ${r.releaseId.slice(0, 12)}`,
    `highest exposure: ${GRADE(s.maxGrade)} (owner code: ${GRADE(s.ownerMaxGrade)}); ${s.owner} owner, ${s.thirdParty} third-party finding(s)`,
  ];
  const owner = collapse(r.findings.filter((f) => f.origin === "owner"));
  for (const { f, n } of owner.slice(0, max)) lines.push(`  [${f.severity}] ${f.title} — ${f.path}${n > 1 ? ` (×${n})` : ""}`);
  if (owner.length > max) lines.push(`  … ${owner.length - max} more owner finding(s) in the report`);
  if (r.checklist.length) lines.push(`checklist: ${r.checklist.length} action(s)`);
  if (r.coverage.opaque.length) lines.push(`not inspected: ${r.coverage.opaque.length} artifact(s) (recovery from them is unknown)`);
  return lines.join("\n");
}

export function renderExposureMarkdown(r: ExposureReport, opts: { includeThirdParty?: boolean } = {}): string {
  const L: string[] = [];
  L.push(`# Anti-REA exposure report — ${r.product.name} ${r.product.version}`);
  L.push("");
  L.push(`**If someone ran a REA-class tool on this release — highest exposure: ${GRADE(r.summary.maxGrade)}** (owner code: ${GRADE(r.summary.ownerMaxGrade)})`);
  L.push("");
  L.push("> Advisory only. This report lists what a reverse-engineering tool would recover and the standard");
  L.push("> toolchain settings that reduce it. It does not claim the app cannot be reverse engineered, and it");
  L.push("> changes no release gate.");
  L.push("");

  L.push("## Product profile");
  L.push("");
  L.push(`| | |`);
  L.push(`|---|---|`);
  L.push(`| Release ID | \`${r.releaseId.slice(0, 16)}…\` |`);
  L.push(`| Platforms | ${r.product.platforms.join(", ") || "—"} |`);
  L.push(`| Frameworks | ${r.product.frameworks.join(", ") || "—"} |`);
  L.push(`| Languages | ${r.product.languages.join(", ") || "—"} |`);
  L.push(`| Tool | ${r.tool.name} ${r.tool.version} |`);
  L.push(`| Generated | ${r.generatedAt} |`);
  L.push("");

  L.push("## Summary");
  L.push("");
  const s = r.summary;
  L.push(`${r.summary.total} finding(s): ${s.owner} in your own code, ${s.thirdParty} in third-party/vendored components.`);
  L.push("");
  L.push(`| Severity | critical | high | medium | low | info |`);
  L.push(`|---|---|---|---|---|---|`);
  L.push(`| Count | ${s.bySeverity.critical} | ${s.bySeverity.high} | ${s.bySeverity.medium} | ${s.bySeverity.low} | ${s.bySeverity.info} |`);
  L.push("");

  const owner = r.findings.filter((f) => f.origin === "owner");
  L.push("## Findings by attack surface (your code first)");
  L.push("");
  if (owner.length === 0) L.push("_No recoverable exposure found in owner code within the analyzed formats._");
  for (const surface of SURFACE_ORDER) {
    const fs = owner.filter((f) => f.surface === surface);
    if (fs.length === 0) continue;
    L.push("");
    L.push(`### ${SURFACE_TITLE[surface]}`);
    L.push("");
    for (const { f, n } of collapse(fs)) L.push(findingLine(f, n));
  }
  L.push("");

  L.push("## Hardening checklist");
  L.push("");
  if (r.checklist.length === 0) L.push("_Nothing to change in owner code._");
  else {
    L.push("| Grade | Action | Files |");
    L.push("|---|---|---|");
    for (const c of r.checklist) L.push(`| ${c.severity} | ${esc(c.remediation)}${c.avoidable ? "" : " _(inherent)_"} | ${c.files.map((f) => code(f)).join("<br>")} |`);
  }
  L.push("");

  L.push("## Third-party / vendored components");
  L.push("");
  if (r.thirdParty.count === 0) L.push("_None._");
  else {
    const b = r.thirdParty.bySeverity;
    L.push(`${r.thirdParty.count} finding(s) in vendored components (dependencies, bundled runtimes, engine libraries): critical ${b.critical}, high ${b.high}, medium ${b.medium}, low ${b.low}, info ${b.info}. These are usually your dependency's to fix, not yours.`);
    L.push("");
    const byA = Object.entries(r.thirdParty.byAnalyzer).sort((a, b2) => b2[1] - a[1]);
    if (byA.length) L.push(`By analyzer: ${byA.map(([k, v]) => `${k} (${v})`).join(", ")}.`);
    if (opts.includeThirdParty) {
      L.push("");
      for (const { f, n } of collapse(r.findings.filter((f2) => f2.origin === "third-party"))) L.push(findingLine(f, n));
    }
  }
  L.push("");

  L.push("## Coverage");
  L.push("");
  L.push(`${r.coverage.artifactsSupported}/${r.coverage.artifactsConsidered} artifact(s) inspected.`);
  if (r.coverage.opaque.length) {
    L.push("");
    L.push("Not inspected (recovery from these is UNKNOWN):");
    L.push("");
    for (const o of r.coverage.opaque) L.push(`- ${code(o)}`);
  }
  L.push("");

  L.push("## REA → Anti-REA");
  L.push("");
  L.push("| Surface | What this report mirrors |");
  L.push("|---|---|");
  for (const m of r.matrix) L.push(`| ${SURFACE_TITLE[m.surface]} | ${esc(m.reports)} |`);
  L.push("");
  return L.join("\n");
}

function findingLine(f: RecoveryFinding, n = 1): string {
  const loc = f.location?.line !== undefined ? `:${f.location.line}` : f.location?.byteOffset !== undefined ? `@0x${f.location.byteOffset.toString(16)}` : "";
  const tags = [f.avoidable ? "avoidable" : "inherent", f.coverage, ...(n > 1 ? [`×${n} slices/instances`] : [])];
  return `- **${esc(f.title)}** (${f.severity}; ${tags.join("; ")}) — ${code(f.path + loc)}\n  - Recovers: ${esc(f.recovers)}\n  - Fix: ${esc(f.remediation)}`;
}

export function writeExposureReport(r: ExposureReport, outDir: string, opts: { includeThirdParty?: boolean } = {}): { json: string; md: string } {
  mkdirSync(outDir, { recursive: true });
  const json = join(outDir, "exposure.json");
  const md = join(outDir, "exposure.md");
  writeFileSync(json, JSON.stringify(r, null, 2) + "\n");
  writeFileSync(md, renderExposureMarkdown(r, opts));
  return { json, md };
}
