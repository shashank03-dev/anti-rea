import type { Manifest } from "../model/manifest.js";
import type { EvidenceRecord } from "../model/evidence.js";
/**
 * External lane: import findings from a dedicated secret scanner run over the
 * same release, and apply the asset model to them.
 *
 * Scanners have far more provider formats and decoders than Anti-REA's own
 * detectors; what they lack is the owner's asset model. Each imported secret is
 * canonicalised and hashed IMMEDIATELY — the plaintext is never stored, and is
 * matched against declared fingerprints to separate server-only exposures from
 * declared public-by-design values and from undeclared leads.
 *
 * The import file itself contains plaintext secrets: treat it as sensitive and
 * delete it after the run.
 */
export type ExternalTool = "gitleaks" | "trufflehog";
export declare const EXTERNAL_TOOLS: readonly ExternalTool[];
export interface ExternalImport {
    readonly tool: ExternalTool;
    readonly path: string;
}
export declare function externalLane(manifest: Manifest, imports: readonly ExternalImport[], releaseId: string, startedAt: string): EvidenceRecord[];
