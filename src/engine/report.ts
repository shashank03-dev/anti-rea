import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AssuranceReport, EvidenceRecord, Finding } from "../model/evidence.js";

const DECISION_LABEL = {
  pass: "PASS",
  "pass-with-exceptions": "PASS WITH EXCEPTIONS",
  block: "BLOCK",
} as const;

function esc(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

export function locationText(f: Finding): string {
  const path = f.artifact?.path ?? (f.reportedPath ? `${f.reportedPath} (as reported)` : undefined);
  if (!path) return "";
  const l = f.location;
  const pos = l ? (l.line !== undefined ? `:${l.line}` : l.byteOffset !== undefined ? `@0x${l.byteOffset.toString(16)}` : "") : "";
  const tags = [...(l?.encoding ? [l.encoding] : []), ...(l?.decoded?.length ? [`decoded: ${l.decoded.join(" > ")}`] : [])];
  return `${path}${pos}${tags.length ? ` [${tags.join("; ")}]` : ""}`;
}

function where(f: Finding): string {
  const t = locationText(f);
  return t ? `\`${t}\`` : "—";
}

function findingLine(f: Finding): string {
  const w = f.witness ? ` — witness \`${f.witness.preview}\` sha256 \`${f.witness.sha256.slice(0, 16)}…\`` : "";
  return `- **${esc(f.title)}** (${f.severity}, ${f.confidence}) at ${where(f)}${w}${f.detail ? `\n  - ${f.detail}` : ""}`;
}

function recordRow(r: EvidenceRecord): string {
  return `| ${r.lane} | ${r.assetId ?? "—"} | \`${r.outcome}\` | ${r.findings.length} | ${r.coverage.artifactsSupported}/${r.coverage.artifactsConsidered} | ${esc(r.budget.declared ?? (r.budget.queries !== undefined ? `${r.budget.queries} queries` : "—"))} |`;
}

export function renderMarkdown(rep: AssuranceReport): string {
  const L: string[] = [];
  const label = DECISION_LABEL[rep.decision];
  L.push(`# Anti-REA assurance report — ${rep.application.name} ${rep.application.version}`);
  L.push("");
  L.push(`**Release decision: ${label}**`);
  L.push("");
  L.push(`| | |`);
  L.push(`|---|---|`);
  L.push(`| Release ID (sha256 of inventory) | \`${rep.releaseId}\` |`);
  L.push(`| Release scope | ${esc(rep.releaseScope)} |`);
  L.push(`| Artifacts in closure | ${rep.inventory.length} |`);
  L.push(`| Manifest | \`${rep.manifestRef.path}\` (sha256 \`${rep.manifestRef.sha256.slice(0, 16)}…\`) |`);
  L.push(`| Policy | \`${rep.policyRef.path}\` (sha256 \`${rep.policyRef.sha256.slice(0, 16)}…\`) |`);
  L.push(`| Tool | ${rep.tool.name} ${rep.tool.version} |`);
  L.push(`| Generated | ${rep.generatedAt} |`);
  L.push("");

  if (rep.blockingReasons.length > 0) {
    L.push("## Blocking reasons");
    L.push("");
    for (const r of rep.blockingReasons) L.push(`- ${esc(r)}`);
    L.push("");
  }

  L.push("## Gates");
  L.push("");
  L.push("| Gate | Action | Blocking | Warnings | Excepted |");
  L.push("|---|---|---|---|---|");
  for (const g of rep.gates)
    L.push(`| ${g.gate} | ${g.action} | ${g.blocking.length} | ${g.warnings.length} | ${g.excepted.length} |`);
  L.push("");

  for (const g of rep.gates) {
    if (!g.tripped) continue;
    L.push(`### ${g.gate}`);
    L.push("");
    if (g.blocking.length) {
      L.push("Blocking:");
      L.push("");
      for (const f of g.blocking) L.push(findingLine(f));
      L.push("");
    }
    if (g.warnings.length) {
      L.push("Warnings (reported, not blocking):");
      L.push("");
      for (const f of g.warnings) L.push(findingLine(f));
      L.push("");
    }
    if (g.excepted.length) {
      L.push("Excepted (still reported):");
      L.push("");
      for (const x of g.excepted) L.push(`- \`${x.findingId}\` — owner ${x.owner}, scope "${esc(x.scope)}", expires ${x.expiry}: ${esc(x.rationale)}`);
      L.push("");
    }
    if (g.expiredExceptions.length) {
      L.push("Expired exceptions (did NOT apply):");
      L.push("");
      for (const x of g.expiredExceptions) L.push(`- \`${x.findingId}\` — owner ${x.owner}, expired ${x.expiry}`);
      L.push("");
    }
  }

  L.push("## Coverage");
  L.push("");
  L.push("| Lane | Required | Status |");
  L.push("|---|---|---|");
  for (const [lane, st] of Object.entries(rep.coverage.lanes))
    L.push(`| ${lane} | ${rep.coverage.requiredLanes.includes(lane) ? "yes" : "no"} | ${st} |`);
  L.push("");
  L.push(`Assets addressed: ${rep.coverage.assetsAddressed.map((a) => `\`${a}\``).join(", ") || "none"}`);
  L.push("");
  L.push(`Assets unaddressed: ${rep.coverage.assetsUnaddressed.map((a) => `\`${a}\``).join(", ") || "none"}`);
  L.push("");

  L.push("## Evidence records");
  L.push("");
  L.push("| Lane | Asset | Outcome | Findings | Supported/considered | Budget |");
  L.push("|---|---|---|---|---|---|");
  for (const r of rep.evidence) L.push(recordRow(r));
  L.push("");

  const info = rep.evidence.flatMap((r) => r.findings).filter((f) => !f.gate);
  if (info.length) {
    L.push("## Observations (no gate)");
    L.push("");
    for (const f of info) L.push(findingLine(f));
    L.push("");
  }

  L.push("## Limitations per record");
  L.push("");
  for (const r of rep.evidence) {
    if (r.limitations.length === 0) continue;
    L.push(`- **${r.id}** (\`${r.outcome}\`)`);
    for (const l of r.limitations) L.push(`  - ${l}`);
    for (const n of r.coverage.notes ?? []) L.push(`  - coverage: ${n}`);
  }
  L.push("");

  L.push("## Scope of this statement");
  L.push("");
  for (const l of rep.limitations) L.push(`- ${l}`);
  L.push("");
  return L.join("\n");
}

export function writeReport(rep: AssuranceReport, outDir: string): { json: string; md: string } {
  mkdirSync(outDir, { recursive: true });
  const json = join(outDir, "report.json");
  const md = join(outDir, "report.md");
  writeFileSync(json, JSON.stringify(rep, null, 2) + "\n");
  writeFileSync(md, renderMarkdown(rep));
  return { json, md };
}

export function renderSummary(rep: AssuranceReport): string {
  const lines = [
    `anti-rea: ${rep.application.name} ${rep.application.version}  release ${rep.releaseId.slice(0, 12)}  (${rep.inventory.length} artifacts)`,
    `decision: ${DECISION_LABEL[rep.decision]}`,
  ];
  for (const r of rep.blockingReasons) lines.push(`  ✗ ${r}`);
  const warns = rep.gates.flatMap((g) => g.warnings);
  for (const w of warns) lines.push(`  ! [warn] ${w.title}${locationText(w) ? ` (${locationText(w)})` : ""}`);
  for (const g of rep.gates) for (const x of g.excepted) lines.push(`  ~ [excepted:${g.gate}] ${x.findingId} (owner ${x.owner}, expires ${x.expiry})`);
  const lanes = Object.entries(rep.coverage.lanes)
    .map(([l, s]) => `${l}=${s}${rep.coverage.requiredLanes.includes(l) ? "*" : ""}`)
    .join(" ");
  lines.push(`lanes: ${lanes}   (* required)`);
  return lines.join("\n");
}
