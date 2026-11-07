#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { ConfigError, loadManifest, loadPolicy } from "./util/io.js";
import { setClock } from "./util/clock.js";
import { assure } from "./engine/evaluate.js";
import { renderSummary, writeReport } from "./engine/report.js";
import { buildInventory } from "./lanes/inventory.js";
import { buildPlan, loadAuthzResults } from "./lanes/authorization.js";
import { EXTERNAL_TOOLS, type ExternalImport, type ExternalTool } from "./lanes/external.js";
import { fingerprintOf } from "./lanes/detectors.js";
import { minTrialsForBound, zeroEventUpperBound } from "./engine/stats.js";
import { TOOL_NAME, TOOL_VERSION } from "./version.js";

const EXIT = { pass: 0, error: 1, block: 2 } as const;

const HELP = `${TOOL_NAME} ${TOOL_VERSION} — release assurance with hard gates

Usage:
  anti-rea assure --manifest <file> --policy <file> [--authz-results <file>] [--import <tool>:<file>]... [--out <dir>] [--json] [--now <ISO date>]
      Run every lane over the declared release closure, evaluate gates, write report.json + report.md.
      --import applies the asset model to findings from a dedicated scanner run over the same
      release: gitleaks:<report.json> (gitleaks --report-format json, without --redact) or
      trufflehog:<results.jsonl> (trufflehog filesystem --json). Repeatable.
      Exit code: 0 pass / pass-with-exceptions, 2 block, 1 error.

  anti-rea inventory --manifest <file> [--json]
      List the release closure (including nested container entries) with sha256 and the release ID.

  anti-rea fingerprint (--file <path> | --stdin)
      Print the canonical sha256 fingerprint of a secret for the manifest. The secret itself is never printed.

  anti-rea authz-plan --manifest <file> [--out <file>]
      Expand the declared authorization matrix into a test plan for your own harness to execute.

  anti-rea stats zero-event --n <trials> [--confidence 0.95]
  anti-rea stats min-trials --target <p> [--confidence 0.95]
      Exact one-sided upper bound for zero observed events in n independent trials (doc §11).

  anti-rea version | help
`;

type Flags = Record<string, string | true>;
const REPEATABLE = new Set(["import"]);

function parse(argv: string[]): { cmd: string[]; flags: Flags; multi: Record<string, string[]> } {
  const cmd: string[] = [];
  const flags: Flags = {};
  const multi: Record<string, string[]> = {};
  const set = (k: string, v: string | true) => {
    if (REPEATABLE.has(k)) {
      if (v === true) throw new UsageError(`--${k} needs a value`);
      (multi[k] ??= []).push(v);
    } else flags[k] = v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        set(a.slice(2, eq), a.slice(eq + 1));
      } else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          set(a.slice(2), next);
          i++;
        } else {
          set(a.slice(2), true);
        }
      }
    } else {
      cmd.push(a);
    }
  }
  return { cmd, flags, multi };
}

function parseImports(values: string[] | undefined): ExternalImport[] {
  return (values ?? []).map((v) => {
    const c = v.indexOf(":");
    const tool = v.slice(0, c) as ExternalTool;
    if (c <= 0 || !EXTERNAL_TOOLS.includes(tool)) throw new UsageError(`--import must be <tool>:<file> with tool in ${EXTERNAL_TOOLS.join(", ")}`);
    return { tool, path: v.slice(c + 1) };
  });
}

/** A report written inside a release root would be scanned as part of the next release. */
function assertOutsideRoots(out: string, manifestPath: string, roots: readonly string[]): void {
  const o = resolve(out);
  for (const r of roots) {
    const abs = resolve(dirname(resolve(manifestPath)), r);
    if (o === abs || o.startsWith(abs + sep)) throw new UsageError(`--out ${out} is inside release root "${r}"; write reports outside the shipped bytes`);
  }
}

class UsageError extends Error {}

function req(flags: Flags, name: string): string {
  const v = flags[name];
  if (typeof v !== "string" || v.length === 0) throw new UsageError(`missing required --${name}`);
  return v;
}

function num(flags: Flags, name: string, dflt?: number): number {
  const v = flags[name];
  if (v === undefined && dflt !== undefined) return dflt;
  const n = Number(v);
  if (typeof v !== "string" || !Number.isFinite(n)) throw new UsageError(`--${name} must be a number`);
  return n;
}

function readStdin(): Buffer {
  return readFileSync(0);
}

function main(argv: string[]): number {
  const { cmd, flags, multi } = parse(argv);
  const [c0, c1] = cmd;

  if (typeof flags.now === "string") {
    const d = new Date(flags.now);
    if (Number.isNaN(d.getTime())) throw new UsageError("--now must be an ISO date");
    setClock(d);
  }

  switch (c0) {
    case undefined:
    case "help":
      process.stdout.write(HELP);
      return EXIT.pass;
    case "version":
      process.stdout.write(`${TOOL_VERSION}\n`);
      return EXIT.pass;

    case "assure": {
      const manifest = loadManifest(req(flags, "manifest"));
      const policy = loadPolicy(req(flags, "policy"));
      const authz = typeof flags["authz-results"] === "string" ? loadAuthzResults(flags["authz-results"]) : null;
      const out = typeof flags.out === "string" ? flags.out : resolve(dirname(manifest.path), "anti-rea-report");
      assertOutsideRoots(out, manifest.path, manifest.value.releaseClosure.roots);
      const rep = assure({ manifest, policy, authzResults: authz, imports: parseImports(multi.import) });
      const files = writeReport(rep, out);
      if (flags.json === true) process.stdout.write(JSON.stringify(rep, null, 2) + "\n");
      else process.stdout.write(`${renderSummary(rep)}\nreport: ${files.md}\nevidence: ${files.json}\n`);
      return rep.decision === "block" ? EXIT.block : EXIT.pass;
    }

    case "inventory": {
      const manifest = loadManifest(req(flags, "manifest"));
      const inv = buildInventory(manifest.value, dirname(resolve(manifest.path)));
      if (flags.json === true) {
        process.stdout.write(
          JSON.stringify(
            {
              releaseId: inv.releaseId,
              items: inv.items.map((i) => ({ ...i.ref, kind: i.kind, supported: i.supported, unsupportedReason: i.unsupportedReason })),
              notes: inv.notes,
            },
            null,
            2,
          ) + "\n",
        );
      } else {
        process.stdout.write(`release ${inv.releaseId}\n`);
        for (const i of inv.items) {
          const tag = i.supported ? (i.kind === "container" ? "container" : "ok") : `UNSUPPORTED: ${i.unsupportedReason}`;
          process.stdout.write(`${(i.ref.sha256 || "-").slice(0, 12).padEnd(12)}  ${String(i.ref.bytes).padStart(9)}  ${i.ref.path}  [${tag}]\n`);
        }
        for (const n of inv.notes) process.stdout.write(`note: ${n}\n`);
      }
      return EXIT.pass;
    }

    case "fingerprint": {
      let raw: Buffer;
      if (typeof flags.file === "string") raw = readFileSync(flags.file);
      else if (flags.stdin === true) raw = readStdin();
      else throw new UsageError("provide --file <path> or --stdin");
      process.stdout.write(`${JSON.stringify({ type: "sha256", value: fingerprintOf(raw.toString("utf8")) })}\n`);
      return EXIT.pass;
    }

    case "authz-plan": {
      const manifest = loadManifest(req(flags, "manifest"));
      const plan = buildPlan(manifest.value);
      if (!plan) throw new UsageError("manifest declares no authorization matrix");
      const text = JSON.stringify(plan, null, 2) + "\n";
      if (typeof flags.out === "string") {
        writeFileSync(flags.out, text);
        process.stdout.write(`wrote ${plan.cases.length} cases to ${flags.out}\n`);
      } else process.stdout.write(text);
      return EXIT.pass;
    }

    case "stats": {
      const conf = num(flags, "confidence", 0.95);
      if (c1 === "zero-event") {
        const n = num(flags, "n");
        const p = zeroEventUpperBound(n, conf);
        process.stdout.write(`n=${n} confidence=${conf} upper bound=${(p * 100).toPrecision(4)}%\n`);
        process.stdout.write("valid only for independent trials with equal event probability; not a probability of security.\n");
        return EXIT.pass;
      }
      if (c1 === "min-trials") {
        const t = num(flags, "target");
        process.stdout.write(`${minTrialsForBound(t, conf)}\n`);
        return EXIT.pass;
      }
      throw new UsageError("stats subcommand must be zero-event or min-trials");
    }

    default:
      throw new UsageError(`unknown command "${c0}"`);
  }
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  if (e instanceof UsageError) {
    process.stderr.write(`error: ${e.message}\n\n${HELP}`);
  } else if (e instanceof ConfigError) {
    process.stderr.write(`config error: ${e.message}\n`);
  } else if (e instanceof RangeError) {
    process.stderr.write(`error: ${e.message}\n`);
  } else {
    process.stderr.write(`internal error: ${(e as Error).stack ?? String(e)}\n`);
  }
  process.exitCode = EXIT.error;
}
