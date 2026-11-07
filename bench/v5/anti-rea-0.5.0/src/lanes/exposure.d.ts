import type { Manifest } from "../model/manifest.js";
import type { EvidenceRecord } from "../model/evidence.js";
import type { Inventory } from "./types.js";
export declare function exposureLane(manifest: Manifest, inv: Inventory, startedAt: string): EvidenceRecord[];
