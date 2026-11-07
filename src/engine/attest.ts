import { createPrivateKey, createPublicKey, sign as cryptoSign, type KeyObject } from "node:crypto";
import type { AssuranceReport } from "../model/evidence.js";
import { sha256Hex } from "../util/hash.js";
import { pae, verifyDsse, type DsseEnvelope, type Statement } from "../lanes/provenance.js";

/**
 * Signed release-decision attestations (research §14 stage 4). A decision only means something
 * downstream if a deployer can check, without re-running Anti-REA, that THIS decision was made
 * about THESE bytes under THIS policy. The attestation is an in-toto Statement in a DSSE envelope:
 * - subjects: every top-level shipped artifact (path + sha256), so it binds to the bytes;
 * - predicate: release id, decision, gate results, required-lane status, manifest/policy digests,
 *   and the digest of the full report.json, so the evidence can be fetched and checked later.
 */

export const DECISION_PREDICATE = "https://anti-rea.dev/attestation/release-decision/v1";
export const PAYLOAD_TYPE = "application/vnd.in-toto+json";

export function decisionStatement(rep: AssuranceReport, reportJson: string): Statement {
  const top = rep.inventory.filter((a) => a.sha256 !== "" && !a.path.includes("!/"));
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: top.map((a) => ({ name: a.path, digest: { sha256: a.sha256 } })),
    predicateType: DECISION_PREDICATE,
    predicate: {
      tool: rep.tool,
      generatedAt: rep.generatedAt,
      application: rep.application,
      releaseId: rep.releaseId,
      releaseScope: rep.releaseScope,
      decision: rep.decision,
      blockingReasons: rep.blockingReasons,
      gates: rep.gates.map((g) => ({ gate: g.gate, action: g.action, tripped: g.tripped, blocking: g.blocking.length, warnings: g.warnings.length })),
      requiredLanes: rep.coverage.requiredLanes,
      lanes: rep.coverage.lanes,
      manifest: { path: rep.manifestRef.path, sha256: rep.manifestRef.sha256 },
      policy: { path: rep.policyRef.path, sha256: rep.policyRef.sha256 },
      report: { sha256: sha256Hex(reportJson) },
    },
  };
}

function signer(key: KeyObject): string | null {
  return key.asymmetricKeyType === "ed25519" || key.asymmetricKeyType === "ed448" ? null : "sha256";
}

export function keyId(pub: KeyObject): string {
  return sha256Hex(pub.export({ type: "spki", format: "der" }) as Buffer).slice(0, 16);
}

export function signStatement(st: Statement, privatePem: string): DsseEnvelope {
  const key = createPrivateKey(privatePem);
  const body = Buffer.from(JSON.stringify(st), "utf8");
  const sig = cryptoSign(signer(key), pae(PAYLOAD_TYPE, body), key);
  return { payloadType: PAYLOAD_TYPE, payload: body.toString("base64"), signatures: [{ keyid: keyId(createPublicKey(key)), sig: sig.toString("base64") }] };
}

export interface AttestationCheck {
  readonly signatureValid: boolean;
  readonly statement: Statement | null;
  readonly problems: string[];
}

/**
 * Verify an attestation: signature against a pinned public key, predicate type, and (optionally)
 * that each given artifact digest is a subject and that the decision is the expected one.
 */
export function verifyAttestation(
  env: DsseEnvelope,
  publicPem: string,
  opts: { artifacts?: readonly { path: string; sha256: string }[]; requireDecision?: string } = {},
): AttestationCheck {
  const problems: string[] = [];
  const pub = createPublicKey(publicPem);
  const signatureValid = env.payloadType === PAYLOAD_TYPE && verifyDsse(env, [pub]).valid;
  if (!signatureValid) problems.push("signature does not verify with the given public key");
  let st: Statement | null = null;
  try {
    st = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")) as Statement;
  } catch {
    problems.push("payload is not JSON");
  }
  if (st) {
    if (st.predicateType !== DECISION_PREDICATE) problems.push(`unexpected predicateType ${st.predicateType}`);
    const digests = new Set(st.subject.map((s) => s.digest.sha256));
    for (const a of opts.artifacts ?? []) if (!digests.has(a.sha256)) problems.push(`${a.path} (sha256 ${a.sha256.slice(0, 16)}…) is not a subject`);
    const decision = (st.predicate as { decision?: string } | undefined)?.decision;
    if (opts.requireDecision !== undefined && decision !== opts.requireDecision) problems.push(`decision is ${decision}, required ${opts.requireDecision}`);
  }
  return { signatureValid, statement: signatureValid ? st : null, problems };
}
