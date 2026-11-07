import type { Manifest } from "../model/manifest.js";
import type { EvidenceRecord } from "../model/evidence.js";
import type { Inventory } from "./types.js";
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
export declare function placementLane(manifest: Manifest, inv: Inventory, startedAt: string): EvidenceRecord[];
