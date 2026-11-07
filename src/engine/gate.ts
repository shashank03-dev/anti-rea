import type { Manifest } from "../model/manifest.js";
import type { GateId, Policy, PolicyException } from "../model/policy.js";
import { ALL_GATES, DEFAULT_GATES, KNOWN_LANES } from "../model/policy.js";
import { locationText } from "./report.js";
import type { AppliedException, EvidenceRecord, Finding, GateResult, LaneStatus, ReleaseDecision } from "../model/evidence.js";

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

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

export function laneStatuses(evidence: readonly EvidenceRecord[]): Record<string, LaneStatus> {
  const out: Record<string, LaneStatus> = {};
  for (const lane of KNOWN_LANES) {
    const recs = evidence.filter((r) => r.lane === lane);
    out[lane] = recs.length === 0 ? "not-run" : recs.some((r) => r.outcome === "inconclusive") ? "inconclusive" : "concluded";
  }
  return out;
}

function laneOf(f: Finding): string | undefined {
  return f.id.split("/")[0];
}

function active(ex: PolicyException, today: string): boolean {
  return ex.expiry >= today; // ISO dates compare lexicographically; expiry is inclusive
}

function toApplied(f: Finding, ex: PolicyException): AppliedException {
  return { findingId: f.id, owner: ex.owner, scope: ex.scope, rationale: ex.rationale, expiry: ex.expiry };
}

export function evaluateGates(
  policy: Policy,
  manifest: Manifest,
  evidence: readonly EvidenceRecord[],
  today: string, // YYYY-MM-DD
): GateEvaluation {
  const lanes = laneStatuses(evidence);
  const all: Finding[] = evidence.flatMap((r) => r.findings);

  // Synthesise findings for required lanes that did not run to a conclusion.
  for (const lane of policy.requiredLanes) {
    const st = lanes[lane];
    if (st === "concluded") continue;
    const why = evidence
      .filter((r) => r.lane === lane && r.outcome === "inconclusive")
      .flatMap((r) => r.limitations.map((l) => (r.assetId ? `[${r.assetId}] ${l}` : l)));
    all.push({
      id: `${lane}/required-lane-${st}`,
      // The one-line reason is what a release owner reads first: say WHY and how to resolve it, not just that it happened.
      title: `Required lane "${lane}" ${st === "not-run" ? "did not run" : "is inconclusive"}${why.length > 0 ? `: ${clip(why[0]!, 220)}` : ""} — fix the cause, or record a policy exception { gate: "requiredLaneInconclusive", lane: "${lane}" } with owner, scope, rationale and expiry`,
      severity: "high",
      confidence: "confirmed",
      gate: "requiredLaneInconclusive",
      detail: why.length > 0 ? why.join(" | ") : "No evidence records were produced for this lane.",
    });
  }

  const assetAction = new Map(manifest.assets.map((a) => [a.id, a.onConfirmedDistribution]));
  const exceptions = policy.exceptions ?? [];
  const gates: GateResult[] = [];
  const blockingReasons: string[] = [];

  for (const gate of ALL_GATES) {
    const action = policy.gates[gate] ?? DEFAULT_GATES[gate];
    const tripping = all.filter((f) => f.gate === gate);
    const blocking: Finding[] = [];
    const warnings: Finding[] = [];
    const excepted: AppliedException[] = [];
    const expired: AppliedException[] = [];

    for (const f of tripping) {
      const perAsset = f.assetId ? assetAction.get(f.assetId) : undefined;
      const effective = perAsset === "warn" && gate !== "requiredLaneInconclusive" ? "warn" : action;
      if (effective === "warn") {
        warnings.push(f);
        continue;
      }
      const matches = exceptions.filter(
        (ex) => ex.gate === gate && (!ex.assetId || ex.assetId === f.assetId) && (!ex.lane || ex.lane === laneOf(f)),
      );
      const live = matches.find((ex) => active(ex, today));
      if (live) {
        excepted.push(toApplied(f, live));
      } else {
        for (const ex of matches) expired.push(toApplied(f, ex));
        blocking.push(f);
      }
    }
    // One reason per distinct finding title, listing every location (no duplicate lines).
    const grouped = new Map<string, string[]>();
    for (const f of blocking) {
      const locs = grouped.get(f.title) ?? [];
      const t = locationText(f);
      // A universal binary yields one finding per architecture slice at the same path: list the path once.
      if (t && !locs.includes(t)) locs.push(t);
      grouped.set(f.title, locs);
    }
    for (const [title, locs] of grouped) blockingReasons.push(`[${gate}] ${title}${locs.length ? ` @ ${locs.join(", ")}` : ""}`);
    gates.push({ gate: gate as GateId, action, tripped: tripping.length > 0, blocking, warnings, excepted, expiredExceptions: expired });
  }

  const decision: ReleaseDecision =
    blockingReasons.length > 0 ? "block" : gates.some((g) => g.excepted.length > 0) ? "pass-with-exceptions" : "pass";
  return { gates, decision, blockingReasons, lanes };
}
