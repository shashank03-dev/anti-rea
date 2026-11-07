import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import type { Manifest } from "../model/manifest.js";
import type { EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome } from "../model/result.js";
import { nowIso } from "../util/clock.js";
import { matchesAny } from "../util/glob.js";
import { TOOL } from "../version.js";
import type { Inventory } from "./types.js";

/**
 * Provenance lane (research §9.2 and §14 stage 4). Byte identity does not authenticate a build context;
 * signed provenance does. This lane checks that the bytes being released are exactly the bytes a trusted
 * builder attested to:
 * - it reads an in-toto Statement, bare or in a DSSE envelope (also inside a Sigstore bundle), from JSON
 *   or JSON Lines;
 * - it verifies DSSE signatures (Ed25519, ECDSA, RSA) against owner-pinned public keys;
 * - it checks the SLSA builder id;
 * - it requires every top-level release artifact to appear as a subject with the same SHA-256.
 *
 * Sigstore certificate chains, Rekor inclusion proofs and keyless (Fulcio) identities are not verified:
 * pin a key, or verify those with `cosign` / `gh attestation verify` and record the result.
 */

export interface DsseEnvelope {
  readonly payloadType: string;
  readonly payload: string; // base64
  readonly signatures: readonly { readonly keyid?: string; readonly sig: string }[];
}

export interface Statement {
  readonly _type: string;
  readonly subject: readonly { readonly name: string; readonly digest: Readonly<Record<string, string>> }[];
  readonly predicateType: string;
  readonly predicate?: Record<string, unknown>;
}

/** DSSE pre-authentication encoding: "DSSEv1" SP len(type) SP type SP len(body) SP body. */
export function pae(payloadType: string, payload: Buffer): Buffer {
  const t = Buffer.from(payloadType, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payload.length} `), payload]);
}

export function verifyDsse(env: DsseEnvelope, keys: readonly KeyObject[]): { valid: boolean; keyIndex?: number } {
  const msg = pae(env.payloadType, Buffer.from(env.payload, "base64"));
  for (const s of env.signatures ?? []) {
    const sig = Buffer.from(s.sig, "base64");
    for (let k = 0; k < keys.length; k++) {
      const key = keys[k]!;
      const algo = key.asymmetricKeyType === "ed25519" || key.asymmetricKeyType === "ed448" ? null : "sha256";
      try {
        if (cryptoVerify(algo, msg, key, sig)) return { valid: true, keyIndex: k };
      } catch {}
    }
  }
  return { valid: false };
}

interface Record_ {
  readonly envelope?: DsseEnvelope;
  readonly statement: Statement;
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);

function asStatement(x: unknown): Statement | null {
  if (!isObj(x) || typeof x._type !== "string" || !/in-toto\.io\/Statement/.test(x._type) || !Array.isArray(x.subject)) return null;
  return x as unknown as Statement;
}

/** Parse a provenance file: DSSE envelope(s), Sigstore bundle(s) or bare Statement(s), as JSON or JSON Lines. */
export function parseProvenance(text: string): Record_[] {
  const docs: unknown[] = [];
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) docs.push(...j);
    else docs.push(j);
  } catch {
    for (const line of text.split(/\r?\n/)) if (line.trim()) docs.push(JSON.parse(line));
  }
  const out: Record_[] = [];
  for (const d of docs) {
    const env = isObj(d) && isObj(d.dsseEnvelope) ? d.dsseEnvelope : d; // Sigstore bundle → its DSSE envelope
    if (isObj(env) && typeof env.payloadType === "string" && typeof env.payload === "string") {
      const st = asStatement(JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")));
      if (!st) throw new Error("DSSE payload is not an in-toto Statement");
      out.push({ envelope: env as unknown as DsseEnvelope, statement: st });
      continue;
    }
    const st = asStatement(d);
    if (!st) throw new Error("record is neither a DSSE envelope, a Sigstore bundle nor an in-toto Statement");
    out.push({ statement: st });
  }
  return out;
}

function builderOf(st: Statement): string | undefined {
  const p = st.predicate ?? {};
  const v1 = isObj(p.runDetails) && isObj(p.runDetails.builder) ? p.runDetails.builder.id : undefined;
  const v02 = isObj(p.builder) ? p.builder.id : undefined;
  return typeof v1 === "string" ? v1 : typeof v02 === "string" ? v02 : undefined;
}

export function provenanceLane(manifest: Manifest, baseDir: string, inv: Inventory, startedAt: string): EvidenceRecord {
  const decl = manifest.provenance;
  const findings: Finding[] = [];
  const limitations: string[] = [
    "Sigstore certificate chains, Rekor inclusion and keyless identities are not verified; trust comes from pinned public keys (provenance.publicKeys).",
  ];
  let outcome: Outcome = "not-recovered-within-budget";
  const fail = (id: string, title: string, detail: string, path?: string) =>
    findings.push({
      id: `provenance/${id}`,
      title,
      severity: "high",
      confidence: "confirmed",
      gate: "provenanceMismatch",
      ...(path ? { artifact: inv.items.find((i) => i.ref.path === path)?.ref ?? { path, sha256: "", bytes: 0 } } : {}),
      detail,
    });
  const record = (extra: Partial<EvidenceRecord> = {}): EvidenceRecord => ({
    id: "provenance/build",
    lane: "provenance",
    releaseId: inv.releaseId,
    tool: TOOL,
    invocation: decl ? { statement: decl.statement, builderId: decl.builderId ?? null, publicKeys: decl.publicKeys?.length ?? 0 } : {},
    accessGranted: "delivered artifacts and provenance file, read-only",
    budget: { declared: "verification of the declared provenance" },
    outcome,
    coverage: { artifactsConsidered: 0, artifactsSupported: 0, artifactsUnsupported: 0 },
    limitations,
    findings,
    startedAt,
    finishedAt: nowIso(),
    ...extra,
  });

  if (!decl) {
    limitations.push("The policy requires the provenance lane, but the manifest declares no provenance.");
    outcome = "inconclusive";
    return record();
  }
  let records: Record_[];
  let keys: KeyObject[];
  try {
    records = parseProvenance(readFileSync(resolve(baseDir, decl.statement), "utf8"));
    keys = (decl.publicKeys ?? []).map((k) => createPublicKey(readFileSync(resolve(baseDir, k), "utf8")));
  } catch (e) {
    limitations.push(`Provenance could not be read: ${(e as Error).message}`);
    outcome = "inconclusive";
    return record();
  }
  if (records.length === 0) {
    limitations.push("The provenance file contains no statements.");
    outcome = "inconclusive";
    return record();
  }

  // Only statements that pass signature (when keys are pinned) and builder checks are trusted for coverage.
  const trusted: Statement[] = [];
  records.forEach((r, i) => {
    if (keys.length > 0) {
      if (!r.envelope) {
        fail(`unsigned/${i}`, "Provenance statement is not signed", `record ${i} is a bare Statement, but provenance.publicKeys pins signing keys`);
        return;
      }
      if (!verifyDsse(r.envelope, keys).valid) {
        fail(`bad-signature/${i}`, "Provenance signature does not verify with any pinned key", `record ${i}: ${r.envelope.signatures?.length ?? 0} signature(s), none valid`);
        return;
      }
    }
    if (decl.builderId !== undefined && builderOf(r.statement) !== decl.builderId) {
      fail(`builder/${i}`, "Provenance names an unexpected builder", `record ${i}: builder ${builderOf(r.statement) ?? "(none)"}, expected ${decl.builderId}`);
      return;
    }
    trusted.push(r.statement);
  });
  if (keys.length === 0) limitations.push("No public keys are pinned: provenance statements are accepted unsigned (integrity of the statement itself is not established).");

  const subjects = trusted.flatMap((s) => s.subject.map((x) => ({ name: x.name, sha256: (x.digest.sha256 ?? "").toLowerCase() })));
  const byDigest = new Set(subjects.map((s) => s.sha256));
  const top = inv.items.filter((i) => i.depth === 0 && i.ref.sha256 !== "" && !i.parent);
  const required = decl.subjects ? top.filter((i) => matchesAny(i.ref.path.replace(/^[^/]+\//, ""), decl.subjects!) || matchesAny(basename(i.ref.path), decl.subjects!)) : top;
  for (const it of required) {
    if (byDigest.has(it.ref.sha256)) continue;
    const named = subjects.find((s) => basename(s.name) === basename(it.ref.path));
    if (named) fail(`digest/${it.ref.path}`, "Shipped artifact differs from the attested build output", `${it.ref.path}: sha256 ${it.ref.sha256.slice(0, 16)}…, provenance subject ${named.name} has ${named.sha256.slice(0, 16)}…`, it.ref.path);
    else fail(`uncovered/${it.ref.path}`, "Shipped artifact is not covered by build provenance", `${it.ref.path} (sha256 ${it.ref.sha256.slice(0, 16)}…) is not a subject of any trusted statement`, it.ref.path);
  }
  if (findings.length > 0) outcome = "recovered";
  return record({
    coverage: { artifactsConsidered: required.length, artifactsSupported: required.length, artifactsUnsupported: 0, notes: [`${records.length} statement(s), ${trusted.length} trusted, ${subjects.length} subject(s)`] },
  });
}
