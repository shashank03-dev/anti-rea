import type { Confidence, Outcome, Severity } from "./result.js";
import type { GateId } from "./policy.js";

/**
 * Evidence record (research doc §9.2).
 *
 * Observations, static inference, and interpretation are kept separate. Secret
 * values are NEVER stored in plaintext — only a redacted preview and a sha256.
 */

export interface ArtifactRef {
  readonly path: string; // posix, relative to release root
  readonly sha256: string;
  readonly bytes: number;
}

export interface SecretWitness {
  /** sha256 of the exact matched secret value (enables fingerprint matching without plaintext). */
  readonly sha256: string;
  /** Redacted preview: a few leading chars, masked middle, length. Never the full value. */
  readonly preview: string;
  readonly length: number;
}

export interface Finding {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** The gate this finding can trip, if any. */
  readonly gate?: GateId;
  readonly assetId?: string;
  readonly artifact?: ArtifactRef;
  /** Path as reported by an external tool (relative to that tool's scan root). */
  readonly reportedPath?: string;
  /**
   * Line is present for text artifacts; binaries report only a byte offset.
   * `encoding` is set when the match was found in a UTF-16LE view of the bytes;
   * `decoded` lists the text encodings (outermost first) that were undone to find it,
   * in which case line/byteOffset point at the start of the encoded run.
   */
  readonly location?: {
    readonly line?: number;
    readonly column?: number;
    readonly byteOffset?: number;
    readonly encoding?: "utf16le";
    readonly decoded?: readonly string[];
  };
  readonly detector?: string;
  /** Secret witness when the finding concerns credential material. Plaintext excluded by construction. */
  readonly witness?: SecretWitness;
  readonly detail?: string;
}

export interface Budget {
  readonly declared?: string;
  readonly timeMs?: number;
  readonly queries?: number;
}

export interface Coverage {
  readonly artifactsConsidered: number;
  readonly artifactsSupported: number;
  readonly artifactsUnsupported: number;
  readonly notes?: readonly string[];
}

export interface EvidenceRecord {
  readonly id: string;
  readonly lane: string;
  readonly assetId?: string;
  readonly releaseId: string;
  readonly tool: { readonly name: string; readonly version: string };
  readonly invocation: Record<string, unknown>;
  readonly accessGranted: string; // what access the "attacker" had (e.g. "delivered artifacts, read-only")
  readonly budget: Budget;
  readonly outcome: Outcome;
  readonly coverage: Coverage;
  readonly limitations: readonly string[];
  readonly findings: readonly Finding[];
  readonly disposition?: string; // reviewer note; semantic conclusions need ground truth or a rubric
  readonly startedAt: string;
  readonly finishedAt: string;
}

export type ReleaseDecision = "pass" | "pass-with-exceptions" | "block";

export interface AppliedException {
  readonly findingId: string;
  readonly owner: string;
  readonly scope: string;
  readonly rationale: string;
  readonly expiry: string;
}

export interface GateResult {
  readonly gate: GateId;
  /** Policy action configured for this gate. */
  readonly action: "block" | "warn";
  readonly tripped: boolean;
  /** Findings that block the release (gate action block, no active exception). */
  readonly blocking: readonly Finding[];
  /** Findings reported but not blocking (gate or per-asset action warn). */
  readonly warnings: readonly Finding[];
  /** Blocking findings neutralised by an active, owned, unexpired exception. Still reported. */
  readonly excepted: readonly AppliedException[];
  /** Exceptions that matched but had expired, so did NOT apply. */
  readonly expiredExceptions: readonly AppliedException[];
}

export type LaneStatus = "concluded" | "inconclusive" | "not-run";

export interface AssuranceReport {
  readonly schema: "anti-rea/report/v1";
  readonly tool: { readonly name: string; readonly version: string };
  readonly generatedAt: string;
  readonly application: { readonly name: string; readonly version: string };
  readonly releaseId: string;
  readonly releaseScope: string;
  readonly manifestRef: { readonly path: string; readonly sha256: string };
  readonly policyRef: { readonly path: string; readonly sha256: string };
  readonly inventory: readonly ArtifactRef[];
  readonly evidence: readonly EvidenceRecord[];
  readonly gates: readonly GateResult[];
  readonly coverage: {
    readonly requiredLanes: readonly string[];
    readonly lanes: Readonly<Record<string, LaneStatus>>;
    readonly assetsAddressed: readonly string[];
    readonly assetsUnaddressed: readonly string[];
  };
  readonly decision: ReleaseDecision;
  readonly blockingReasons: readonly string[];
  readonly limitations: readonly string[];
}
