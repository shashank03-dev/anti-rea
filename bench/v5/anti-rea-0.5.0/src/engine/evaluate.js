import { dirname, resolve } from "node:path";
import { now, nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { buildInventory, inventoryLane } from "../lanes/inventory.js";
import { exposureLane } from "../lanes/exposure.js";
import { placementLane } from "../lanes/placement.js";
import { authorizationLane } from "../lanes/authorization.js";
import { DEFAULT_LIMITS } from "../lanes/containers.js";
import { externalLane } from "../lanes/external.js";
import { evaluateGates } from "./gate.js";
/**
 * The end-to-end pipeline (doc §9):
 *   release inventory & identity → asset objectives → static exposure +
 *   placement + authorization lanes → coverage reconciliation → hard gates.
 */
export function assure(input) {
    const { manifest: m, policy: p } = input;
    const manifest = m.value;
    const policy = p.value;
    const baseDir = dirname(resolve(m.path));
    const startedAt = nowIso();
    const inv = buildInventory(manifest, baseDir, input.limits ?? DEFAULT_LIMITS);
    const evidence = [
        inventoryLane(manifest, inv, startedAt),
        ...exposureLane(manifest, inv, startedAt),
        ...placementLane(manifest, inv, startedAt),
    ];
    // Authorization only contributes when declared or required, so an app without a
    // server API is not penalised unless the policy says the lane is mandatory.
    if (manifest.authorization || policy.requiredLanes.includes("authorization")) {
        evidence.push(authorizationLane(manifest, inv.releaseId, input.authzResults ?? null, startedAt));
    }
    if ((input.imports ?? []).length > 0)
        evidence.push(...externalLane(manifest, input.imports, inv.releaseId, startedAt));
    const today = now().toISOString().slice(0, 10);
    const g = evaluateGates(policy, manifest, evidence, today);
    const addressed = [];
    const unaddressed = [];
    // An asset is addressed only if it has evidence and NONE of its records is inconclusive:
    // a not-applicable placement record must not mask an inconclusive exposure record.
    for (const a of manifest.assets) {
        const recs = evidence.filter((r) => r.assetId === a.id);
        (recs.length > 0 && recs.every((r) => r.outcome !== "inconclusive") ? addressed : unaddressed).push(a.id);
    }
    return {
        schema: "anti-rea/report/v1",
        tool: TOOL,
        generatedAt: nowIso(),
        application: manifest.application,
        releaseId: inv.releaseId,
        releaseScope: policy.releaseScope,
        manifestRef: { path: m.path, sha256: m.sha256 },
        policyRef: { path: p.path, sha256: p.sha256 },
        inventory: inv.items.map((i) => i.ref),
        evidence,
        gates: g.gates,
        coverage: {
            requiredLanes: policy.requiredLanes,
            lanes: g.lanes,
            assetsAddressed: addressed,
            assetsUnaddressed: unaddressed,
        },
        decision: g.decision,
        blockingReasons: g.blockingReasons,
        limitations: [
            "This is a scoped assurance statement about the declared release closure, assets, lanes and budgets — not a universal claim that the application cannot be reverse engineered (doc §3).",
            "Static lanes cannot observe values assembled at runtime; runtime instrumentation, behavioral-cloning and tamper lanes are not implemented in this version.",
            "\"Not recovered within budget\" is a right-censored observation, never a proof of impossibility.",
            "No aggregate protection score is produced: gates are the release authority (doc §10).",
        ],
    };
}
