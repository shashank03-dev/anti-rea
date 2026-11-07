import type { Manifest } from "../model/manifest.js";
import type { EvidenceRecord } from "../model/evidence.js";
import { type Limits } from "./containers.js";
import type { Inventory } from "./types.js";
/**
 * Build the release closure: every byte under the declared roots, plus the
 * contents of supported nested containers, each with a sha256 (doc §6.3).
 */
export declare function buildInventory(manifest: Manifest, baseDir: string, limits?: Limits): Inventory;
export declare function inventoryLane(manifest: Manifest, inv: Inventory, startedAt: string): EvidenceRecord;
