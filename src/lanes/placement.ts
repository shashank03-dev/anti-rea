import type { AssetDecl, Manifest } from "../model/manifest.js";
import type { EvidenceRecord, Finding } from "../model/evidence.js";
import type { Outcome } from "../model/result.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import type { Inventory } from "./types.js";
import { contentCoverage, isBinary, lineAt, readItem, scannable, unsupported } from "./types.js";

const MAX_LOCATIONS_PER_ARTIFACT = 5;

/**
 * Placement lane (doc §6.1, §10.2): does the covered distribution contain a
 * declared server-only implementation?
 *
 * Evidence is owner-declared marker literals, searched as raw bytes (UTF-8, and
 * UTF-16LE in binaries) — no string decoding, so file size is not a limit.
 * Marker presence is strong evidence of local presence; marker ABSENCE is not
 * proof of semantic absence (logic may be renamed, generated, encoded, or
 * carried in data/weights) — negatives are scoped observations only.
 */
export function placementLane(manifest: Manifest, inv: Inventory, startedAt: string): EvidenceRecord[] {
  const items = scannable(inv);
  const unsup = unsupported(inv);
  const base = {
    lane: "placement",
    releaseId: inv.releaseId,
    tool: TOOL,
    accessGranted: "delivered release bytes (read-only); literal marker search",
    coverage: contentCoverage(inv),
    startedAt,
  } as const;

  if (manifest.assets.length === 0) {
    return [
      {
        ...base,
        id: "placement",
        invocation: {},
        budget: {},
        outcome: "inconclusive",
        limitations: [
          "No assets are declared in the manifest, so asset placement cannot be evaluated. Declare what must never ship: server-only secrets by sha256 fingerprint (`anti-rea fingerprint --file <secret>`) and server-only code by marker names (research doc §6.2).",
        ],
        findings: [],
        finishedAt: nowIso(),
      },
    ];
  }

  const withMarkers = manifest.assets.filter((a) => a.placement !== "public-by-design" && (a.markers ?? []).length > 0);
  const hits = new Map<string, Finding[]>(withMarkers.map((a) => [a.id, []]));

  if (withMarkers.length > 0) {
    for (const item of items) {
      const buf = readItem(item)!;
      const binary = isBinary(buf);
      for (const asset of withMarkers) {
        const serverOnly = asset.placement === "server-only";
        for (const marker of asset.markers!) {
          const needles: ["utf8" | "utf16le", Buffer][] = [["utf8", Buffer.from(marker, "utf8")]];
          if (binary) needles.push(["utf16le", Buffer.from(marker, "utf16le")]);
          for (const [enc, needle] of needles) {
            const seenKeys = new Set<string>();
            let n = 0;
            for (let idx = buf.indexOf(needle); idx !== -1 && n < MAX_LOCATIONS_PER_ARTIFACT; idx = buf.indexOf(needle, idx + needle.length)) {
              const line = binary ? undefined : lineAt(buf, idx);
              const key = line !== undefined ? `L${line}` : `@${idx}`;
              if (seenKeys.has(key)) continue; // one finding per marker per line
              seenKeys.add(key);
              n++;
              hits.get(asset.id)!.push({
                id: `placement/${asset.id}/${item.ref.path}:${line ?? `@${idx}`}/${marker}`,
                title: serverOnly
                  ? `Server-only implementation marker "${marker}" found in the distribution`
                  : `Sensitive-local marker "${marker}" present (local placement declared)`,
                severity: serverOnly ? "critical" : "info",
                confidence: "high",
                gate: serverOnly ? "serverOnlyFoundInDistribution" : undefined,
                assetId: asset.id,
                artifact: item.ref,
                location: { ...(line !== undefined ? { line } : {}), byteOffset: idx, ...(enc === "utf16le" ? { encoding: "utf16le" as const } : {}) },
                detector: "owner-declared-marker",
                detail: serverOnly
                  ? "An owner-declared marker of a server-only implementation is in the shipped bytes. Reviewer should confirm the implementation (not just the name) ships, then relocate it behind a server-enforced interface."
                  : "Expected: the asset is local by design and therefore recoverable in principle. Resistance must be measured separately against a pre-registered budget.",
              });
            }
          }
        }
      }
    }
  }

  return manifest.assets.map((asset: AssetDecl): EvidenceRecord => {
    const markers = asset.markers ?? [];
    const findings = hits.get(asset.id) ?? [];
    const limitations: string[] = [];
    let outcome: Outcome;

    if (asset.placement === "public-by-design") {
      outcome = "not-applicable";
      limitations.push("Public-by-design: ordinary observation is not a protection failure.");
    } else if (markers.length === 0) {
      if (asset.placement === "server-only" && (asset.fingerprints ?? []).length === 0) {
        outcome = "inconclusive";
        limitations.push("Server-only asset declares neither markers nor fingerprints: its absence from the distribution cannot be evaluated. Declare evidence or record an exception.");
      } else {
        outcome = "not-applicable";
        limitations.push(
          asset.placement === "server-only" ? "Secret asset without implementation markers; covered by the exposure lane." : "No markers declared for this sensitive-local asset.",
        );
      }
    } else if (asset.placement === "server-only") {
      outcome = findings.length > 0 ? "recovered" : unsup.length > 0 ? "inconclusive" : "not-recovered-within-budget";
      if (findings.length === 0)
        limitations.push("No declared marker found. This does not establish semantic absence: logic may be renamed, generated, or carried in data, models or remote modules.");
    } else {
      outcome = "not-applicable";
      limitations.push(
        findings.length > 0
          ? "Present locally as declared. This lane does not measure local recovery resistance."
          : "Declared markers not found; this does NOT indicate resistance (names may simply have been transformed).",
      );
      if (asset.attacker && !asset.attacker.budget)
        limitations.push("No attack budget pre-registered for this asset; a resistance evaluation cannot be interpreted without one (doc §10.2).");
    }
    if (unsup.length > 0 && outcome !== "not-applicable") limitations.push(`${unsup.length} artifact(s) could not be inspected and remain UNKNOWN.`);

    return {
      ...base,
      id: `placement/${asset.id}`,
      assetId: asset.id,
      invocation: { placement: asset.placement, markers },
      budget: { declared: asset.attacker?.budget ?? "literal search of all supported release bytes" },
      outcome,
      limitations,
      findings,
      finishedAt: nowIso(),
    };
  });
}
