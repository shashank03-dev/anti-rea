import type { AssetDecl, Manifest } from "../model/manifest.js";
import type { EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome } from "../model/result.js";
import { sha256Hex } from "../util/hash.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { detectorIds, fingerprintOf, isKnownExample, runDetectors, tokens, witnessOf, type Candidate } from "./detectors.js";
import { DEFAULT_DECODE, decodeLayers } from "./decode.js";
import type { Inventory, InventoryItem, TextView } from "./types.js";
import { contentCoverage, isBinary, lineAt, readItem, scannable, textViews, unsupported } from "./types.js";

/**
 * Exposure lane (doc §11 "Secret exposure"): confirm exact forbidden
 * credentials, and surface unconfirmed credential-shaped leads for triage.
 *
 * Two passes over chunked text views (Latin-1, plus UTF-16LE for binaries) of
 * every scannable artifact, and over every base64 / hex / percent-encoded run in
 * them that decodes to readable text (up to two layers):
 *  1. Detectors: pattern hits; each candidate's canonical sha256 is compared to declared fingerprints.
 *  2. Fingerprint sweep: every credential-shaped token is hashed and compared, so a declared
 *     secret is confirmed even when no generic detector recognises its format.
 */

const GATE_FOR: Record<Candidate["kind"], "unconfirmedCredentialLead" | "unrecognizedTokenLead" | "keyedCredentialLead" | "lowConfidenceCredentialLead"> = {
  format: "unconfirmedCredentialLead",
  structural: "unrecognizedTokenLead",
  keyed: "keyedCredentialLead",
  heuristic: "lowConfidenceCredentialLead",
};

const LEAD_DETAIL: Record<Candidate["kind"], string> = {
  format:
    "Format-specific credential not matched to any declared asset. Blocks until triaged: rotate and remove it, or declare it (public-by-design with its fingerprint) if it is intentionally shipped.",
  structural:
    "A <prefix>_<random> token, the shape most providers now use for credentials, from a provider Anti-REA does not recognise. Blocks until triaged: rotate and remove it, or declare it (with its fingerprint) if it is intentionally shipped.",
  keyed:
    "A generated-looking value assigned to a key named like a credential (…_API_KEY, accessToken, client_secret, SEGMENT_WRITE_KEY) or passed to a credential-named function or API client constructor (setApiKey(\"…\"), new FooClient(\"…\")), with no recognised provider format. Blocks until triaged: rotate and remove it, or declare it (with its fingerprint) if it is intentionally shipped.",
  heuristic:
    "Credential-shaped value not matched to any declared asset. Triage whether it is a real credential and what authority it carries; declare it if intentionally shipped.",
};
/** Paths of test fixtures and test sources (any segment of a virtual path, including inside archives). */
const FIXTURE_PATH = /(?:^|[/!])(?:testdata|tests?|__tests__|__fixtures__|fixtures?|spec|test-vectors?)\/|(?:_test\.go|\.(?:test|spec)\.[cm]?[jt]sx?|_test\.py|(?:^|\/)test_[^/]*\.py)$/i;

export function exposureLane(manifest: Manifest, inv: Inventory, startedAt: string): EvidenceRecord[] {
  const fpIndex = new Map<string, AssetDecl>();
  for (const a of manifest.assets) for (const f of a.fingerprints ?? []) fpIndex.set(f.value, a);

  const confirmed = new Map<string, Finding[]>(); // assetId -> findings
  const leads: Finding[] = [];
  const seen = new Set<string>();
  const items = scannable(inv);
  const unsup = unsupported(inv);
  let suppressedExamples = 0;
  let decodedSpans = 0;

  const locate = (buf: Buffer, binary: boolean, v: TextView, index: number, decoded: readonly string[]) => {
    const byteOffset = v.base + index * v.stride;
    return {
      ...(binary ? {} : { line: lineAt(buf, byteOffset) }),
      byteOffset,
      ...(v.encoding === "utf16le" ? { encoding: "utf16le" as const } : {}),
      ...(decoded.length > 0 ? { decoded } : {}),
    };
  };

  const confirm = (asset: AssetDecl, item: InventoryItem, loc: NonNullable<Finding["location"]>, value: string, detector: string) => {
    const key = `${asset.id}|${item.ref.path}|${loc.line ?? `@${loc.byteOffset}`}`;
    if (seen.has(key)) return;
    seen.add(key);
    const serverOnly = asset.placement === "server-only";
    const list = confirmed.get(asset.id) ?? [];
    list.push({
      id: `exposure/confirmed/${asset.id}/${item.ref.path}:${loc.line ?? `@${loc.byteOffset}`}`,
      title: serverOnly
        ? `Declared server-only secret "${asset.id}" is present in the distribution`
        : `Declared secret "${asset.id}" is present (placement "${asset.placement}" permits local distribution)`,
      severity: serverOnly ? "critical" : asset.placement === "sensitive-local" ? "medium" : "info",
      confidence: "confirmed",
      gate: serverOnly ? "confirmedCriticalSecret" : undefined,
      assetId: asset.id,
      artifact: item.ref,
      location: loc,
      detector,
      witness: witnessOf(value),
      detail: serverOnly
        ? `Exact match against an owner-declared fingerprint. Authority: ${asset.description ?? "see asset declaration"}. Rotate the credential: removal from future builds does not revoke copies already distributed.`
        : "Present as declared. Verify that the credential's permissions and restrictions make local exposure acceptable.",
    });
    confirmed.set(asset.id, list);
  };

  for (const item of items) {
    const buf = readItem(item)!;
    const binary = isBinary(buf);
    const swept = new Set<string>();

    for (const v of textViews(buf, inv.limits)) {
      const spans = decodeLayers(v.text, DEFAULT_DECODE);
      decodedSpans += spans.length;
      const layers = [{ text: v.text, index: -1, chain: [] as readonly string[] }, ...spans];
      for (const layer of layers) {
        const at = (i: number) => (layer.chain.length === 0 ? i : layer.index);
        for (const c of runDetectors(layer.text)) {
          const loc = locate(buf, binary, v, at(c.index), layer.chain);
          if (loc.byteOffset >= v.ownEnd) continue; // found again, whole, in the next chunk
          const fp = fingerprintOf(c.value);
          const asset = fpIndex.get(fp);
          if (asset) {
            confirm(asset, item, loc, c.value, c.detector);
            continue;
          }
          if (isKnownExample(c)) {
            suppressedExamples++;
            continue;
          }
          const key = `lead|${item.ref.path}|${loc.byteOffset}|${fp}`;
          const sameValueKey = `leadv|${item.ref.path}|${fp}`;
          if (seen.has(key) || seen.has(sameValueKey)) continue;
          seen.add(key);
          seen.add(sameValueKey);
          // v0.4: a keyed lead (credential-looking only by its key name) inside a test fixture is a
          // published test vector far more often than a credential (validation set C: 32 of 32 were
          // Go crypto vectors such as `PrivateKey: "<hex>"`). It is still reported, as a warning.
          const fixture = c.kind === "keyed" && FIXTURE_PATH.test(item.ref.path);
          leads.push({
            id: `exposure/lead/${c.detector}/${item.ref.path}:${loc.line ?? `@${loc.byteOffset}`}`,
            title: `Unconfirmed lead: ${c.title}${layer.chain.length ? ` (${layer.chain.join("-in-")} encoded)` : ""}${fixture ? " (in a test fixture)" : ""}`,
            severity: fixture ? "low" : c.severity,
            confidence: fixture ? "low" : c.confidence,
            gate: fixture ? "lowConfidenceCredentialLead" : GATE_FOR[c.kind],
            artifact: item.ref,
            location: loc,
            detector: c.detector,
            witness: witnessOf(c.value),
            detail: LEAD_DETAIL[c.kind],
          });
        }

        if (fpIndex.size > 0) {
          for (const t of tokens(layer.text)) {
            const memo = layer.chain.length === 0 ? t.value : `${layer.index}|${t.value}`;
            if (swept.has(memo)) continue;
            swept.add(memo);
            const asset = fpIndex.get(sha256Hex(t.value));
            if (!asset) continue;
            const loc = locate(buf, binary, v, at(t.index), layer.chain);
            if (loc.byteOffset >= v.ownEnd) continue;
            confirm(asset, item, loc, t.value, "fingerprint-sweep");
          }
        }
      }
    }
  }

  const coverage = contentCoverage(inv, unsup.map((u) => `${u.ref.path}: ${u.unsupportedReason}`));
  const gapLimitation =
    unsup.length > 0 ? [`${unsup.length} artifact(s) could not be inspected; absence of a secret in those bytes is UNKNOWN.`] : [];
  const records: EvidenceRecord[] = [];
  const staticLimitation =
    "Static byte inspection only: secrets assembled at runtime, encrypted, compressed in an unsupported format, encoded beyond two layers of base64/hex/percent-encoding, split across literals, or fetched remotely are not detected.";

  for (const asset of manifest.assets.filter((a) => (a.fingerprints ?? []).length > 0)) {
    const found = confirmed.get(asset.id) ?? [];
    const outcome: Outcome = found.length > 0 ? "recovered" : unsup.length > 0 ? "inconclusive" : "not-recovered-within-budget";
    records.push({
      id: `exposure/${asset.id}`,
      lane: "exposure",
      assetId: asset.id,
      releaseId: inv.releaseId,
      tool: TOOL,
      invocation: { detectors: detectorIds(), fingerprintSweep: true, fingerprints: (asset.fingerprints ?? []).length },
      accessGranted: "delivered release bytes (read-only); static inspection only",
      budget: { declared: asset.attacker?.budget ?? "exhaustive static scan of all supported release bytes" },
      outcome,
      coverage,
      limitations: [staticLimitation, "A negative result is scoped to this release closure and these detectors; it is not a proof of absence.", ...gapLimitation],
      findings: found,
      startedAt,
      finishedAt: nowIso(),
    });
  }

  records.push({
    id: "exposure/detectors",
    lane: "exposure",
    releaseId: inv.releaseId,
    tool: TOOL,
    invocation: { detectors: detectorIds(), suppressedKnownExamples: suppressedExamples, decodedSpans },
    accessGranted: "delivered release bytes (read-only); static inspection only",
    budget: { declared: "exhaustive static scan of all supported release bytes" },
    outcome: leads.length > 0 ? "recovered" : unsup.length > 0 ? "inconclusive" : "not-recovered-within-budget",
    coverage,
    limitations: [
      "Detector hits are leads, not confirmed exposures. Detector negatives are limited by detector coverage (a deliberately small set; import a dedicated scanner for breadth).",
      staticLimitation,
      ...(suppressedExamples > 0 ? [`${suppressedExamples} publicly documented example credential(s) suppressed.`] : []),
      ...gapLimitation,
    ],
    findings: leads,
    startedAt,
    finishedAt: nowIso(),
  });

  return records;
}
