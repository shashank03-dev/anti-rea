import type { AuthorizationCase, Manifest } from "../model/manifest.js";
import type { EvidenceRecord } from "../model/evidence.js";
/**
 * Authorization lane (doc §7.4, §11 "Authorization integrity").
 *
 * Anti-REA does not send traffic. It (1) expands the declared
 * principal × tenant × object × operation matrix into a test plan with
 * server-side ground truth, and (2) evaluates results that the owner's own
 * harness executed against THEIR service. Any expected-deny case observed as
 * allowed is a reproduced prohibited effect.
 */
export interface PlannedCase extends AuthorizationCase {
    readonly id: string;
}
export interface AuthzPlan {
    readonly schema: "anti-rea/authz-plan/v1";
    readonly target?: string;
    readonly cases: readonly PlannedCase[];
}
export type Observed = "allowed" | "denied" | "error";
export interface AuthzResults {
    readonly schema: "anti-rea/authz-results/v1";
    readonly target?: string;
    readonly executor: string;
    readonly executedAt: string;
    readonly results: readonly {
        readonly id: string;
        readonly observed: Observed;
        readonly evidence?: string;
    }[];
}
export declare function caseId(c: Pick<AuthorizationCase, "principal" | "tenant" | "object" | "operation">): string;
export declare function buildPlan(manifest: Manifest): AuthzPlan | null;
export declare function loadAuthzResults(path: string): AuthzResults;
export declare function authorizationLane(manifest: Manifest, releaseId: string, results: AuthzResults | null, startedAt: string): EvidenceRecord;
