import { readFileSync } from "node:fs";
import { ConfigError } from "../util/io.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
export function caseId(c) {
    return `${c.principal}|${c.tenant}|${c.object}|${c.operation}`;
}
export function buildPlan(manifest) {
    const az = manifest.authorization;
    if (!az)
        return null;
    const byId = new Map();
    const dims = [az.principals, az.tenants, az.objects, az.operations];
    if (dims.every((d) => d && d.length > 0)) {
        for (const principal of az.principals)
            for (const tenant of az.tenants)
                for (const object of az.objects)
                    for (const operation of az.operations) {
                        const c = { principal, tenant, object, operation, expected: az.defaultExpected ?? "deny" };
                        byId.set(caseId(c), { ...c, id: caseId(c) });
                    }
    }
    for (const c of az.cases ?? []) {
        const id = c.id ?? caseId(c);
        byId.set(id, { ...c, id });
    }
    return { schema: "anti-rea/authz-plan/v1", target: az.target, cases: [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : 1)) };
}
export function loadAuthzResults(path) {
    let json;
    try {
        json = JSON.parse(readFileSync(path, "utf8"));
    }
    catch (e) {
        throw new ConfigError(path, `cannot read authorization results (${e.message})`);
    }
    const r = json;
    if (!r || r.schema !== "anti-rea/authz-results/v1")
        throw new ConfigError(path, `schema must be "anti-rea/authz-results/v1"`);
    if (typeof r.executor !== "string" || typeof r.executedAt !== "string")
        throw new ConfigError(path, "executor and executedAt are required (results must be attributable)");
    if (!Array.isArray(r.results))
        throw new ConfigError(path, "results must be an array");
    r.results.forEach((x, i) => {
        if (typeof x?.id !== "string" || !["allowed", "denied", "error"].includes(x.observed))
            throw new ConfigError(path, `results[${i}] needs id and observed ∈ {allowed, denied, error}`);
    });
    return r;
}
export function authorizationLane(manifest, releaseId, results, startedAt) {
    const plan = buildPlan(manifest);
    const base = {
        id: "authorization",
        lane: "authorization",
        releaseId,
        tool: TOOL,
        accessGranted: "owner-executed requests against the owner's service, using declared test principals",
        startedAt,
    };
    if (!plan || plan.cases.length === 0) {
        return {
            ...base,
            invocation: {},
            budget: {},
            outcome: "inconclusive",
            coverage: { artifactsConsidered: 0, artifactsSupported: 0, artifactsUnsupported: 0 },
            limitations: ["No authorization matrix declared in the manifest; server-side authorization integrity was not evaluated."],
            findings: [],
            finishedAt: nowIso(),
        };
    }
    if (!results) {
        return {
            ...base,
            invocation: { plannedCases: plan.cases.length, target: plan.target },
            budget: { queries: 0 },
            outcome: "inconclusive",
            coverage: { artifactsConsidered: plan.cases.length, artifactsSupported: 0, artifactsUnsupported: plan.cases.length },
            limitations: [
                "Test plan generated but no executed results were supplied (--authz-results). Run `anti-rea authz-plan`, execute it with your own harness, and re-run.",
            ],
            findings: [],
            finishedAt: nowIso(),
        };
    }
    // Conflicting evidence (the same case reported twice with different outcomes) is not resolvable: treat as an error.
    const counts = new Map();
    for (const r of results.results)
        counts.set(r.id, (counts.get(r.id) ?? new Set()).add(r.observed));
    const conflicting = [...counts].filter(([, s]) => s.size > 1).map(([id]) => id);
    const observed = new Map(results.results.map((r) => [r.id, conflicting.includes(r.id) ? { ...r, observed: "error" } : r]));
    const findings = [];
    const missing = [];
    const errored = [];
    let falseDenials = 0;
    let executed = 0;
    for (const c of plan.cases) {
        const r = observed.get(c.id);
        if (!r) {
            missing.push(c.id);
            continue;
        }
        if (r.observed === "error") {
            errored.push(c.id);
            continue;
        }
        executed++;
        if (c.expected === "deny" && r.observed === "allowed") {
            findings.push({
                id: `authorization/prohibited/${c.id}`,
                title: `Prohibited effect reproduced: ${c.principal} performed ${c.operation} on ${c.object} in tenant ${c.tenant}`,
                severity: "critical",
                confidence: "confirmed",
                gate: "reproducedPrivilegedEffect",
                detail: `Expected deny; observed allowed.${r.evidence ? ` Evidence: ${r.evidence}` : ""} Object-level authorization must be enforced server-side regardless of identifier format or client attestation.`,
            });
        }
        else if (c.expected === "allow" && r.observed === "denied") {
            falseDenials++;
            findings.push({
                id: `authorization/false-denial/${c.id}`,
                title: `False denial: ${c.principal} could not ${c.operation} ${c.object} in tenant ${c.tenant}`,
                severity: "low",
                confidence: "confirmed",
                detail: `Expected allow; observed denied.${r.evidence ? ` Evidence: ${r.evidence}` : ""}`,
            });
        }
    }
    const unknownIds = results.results.filter((r) => !plan.cases.some((c) => c.id === r.id)).map((r) => r.id);
    const prohibited = findings.some((f) => f.gate === "reproducedPrivilegedEffect");
    const gaps = missing.length + errored.length;
    const outcome = prohibited ? "recovered" : gaps > 0 ? "inconclusive" : "not-recovered-within-budget";
    return {
        ...base,
        invocation: { plannedCases: plan.cases.length, target: plan.target ?? results.target, executor: results.executor, executedAt: results.executedAt },
        budget: { queries: executed },
        outcome,
        coverage: {
            artifactsConsidered: plan.cases.length,
            artifactsSupported: executed,
            artifactsUnsupported: gaps,
            notes: [
                ...missing.map((m) => `no result for ${m}`),
                ...errored.map((m) => (conflicting.includes(m) ? `conflicting results for ${m}` : `execution error for ${m}`)),
                ...unknownIds.map((m) => `result ${m} does not correspond to a planned case (ignored)`),
            ],
        },
        limitations: [
            `Results were executed and supplied by "${results.executor}"; Anti-REA evaluated them but did not issue requests.`,
            "Covers only the declared matrix; it does not establish authorization correctness for undeclared principals, objects or operations.",
            ...(falseDenials > 0 ? [`${falseDenials} false denial(s) observed among legitimate cases.`] : []),
        ],
        findings,
        finishedAt: nowIso(),
    };
}
