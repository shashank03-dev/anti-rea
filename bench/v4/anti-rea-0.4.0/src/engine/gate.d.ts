import type { Manifest } from "../model/manifest.js";
import type { Policy } from "../model/policy.js";
import type { EvidenceRecord, GateResult, LaneStatus, ReleaseDecision } from "../model/evidence.js";
/**
 * Hard-gate evaluation (doc §10.2). There is no score and nothing can offset a
 * blocking finding except an explicit, owned, scoped, unexpired exception —
 * and excepted findings remain in the report.
 */
export interface GateEvaluation {
    readonly gates: GateResult[];
    readonly decision: ReleaseDecision;
    readonly blockingReasons: string[];
    readonly lanes: Record<string, LaneStatus>;
}
export declare function laneStatuses(evidence: readonly EvidenceRecord[]): Record<string, LaneStatus>;
export declare function evaluateGates(policy: Policy, manifest: Manifest, evidence: readonly EvidenceRecord[], today: string): GateEvaluation;
