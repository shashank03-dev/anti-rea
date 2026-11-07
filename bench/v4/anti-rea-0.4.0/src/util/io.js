import { readFileSync } from "node:fs";
import { sha256Hex } from "./hash.js";
import { ALL_GATES, DEFAULT_GATES, KNOWN_LANES } from "../model/policy.js";
export class ConfigError extends Error {
    constructor(file, msg) {
        super(`${file}: ${msg}`);
        this.name = "ConfigError";
    }
}
function readJson(path) {
    let raw;
    try {
        raw = readFileSync(path);
    }
    catch (e) {
        throw new ConfigError(path, `cannot read file (${e.message})`);
    }
    try {
        return { json: JSON.parse(raw.toString("utf8")), sha256: sha256Hex(raw) };
    }
    catch (e) {
        throw new ConfigError(path, `invalid JSON (${e.message})`);
    }
}
const PLACEMENTS = new Set(["server-only", "sensitive-local", "public-by-design"]);
const OBJECTIVES = new Set([
    "secret-extraction",
    "implementation-recovery",
    "behavioral-cloning",
    "authorization-bypass",
    "tampering-or-redistribution",
    "legitimate-client-abuse",
]);
function isObj(x) {
    return typeof x === "object" && x !== null && !Array.isArray(x);
}
function isStrArr(x) {
    return Array.isArray(x) && x.every((s) => typeof s === "string");
}
export function validateManifest(json, file = "<manifest>") {
    const err = (m) => new ConfigError(file, m);
    if (!isObj(json))
        throw err("manifest must be a JSON object");
    if (json.schema !== "anti-rea/manifest/v1")
        throw err(`schema must be "anti-rea/manifest/v1"`);
    const app = json.application;
    if (!isObj(app) || typeof app.name !== "string" || typeof app.version !== "string")
        throw err("application.name and application.version are required strings");
    const rc = json.releaseClosure;
    if (!isObj(rc) || !isStrArr(rc.roots) || rc.roots.length === 0)
        throw err("releaseClosure.roots must be a non-empty string array");
    if (rc.private !== undefined && !isStrArr(rc.private))
        throw err("releaseClosure.private must be a string array");
    const roots = rc.roots;
    const norm = roots.map((r) => r.replace(/\\/g, "/").replace(/\/+$/, "").replace(/^\.\//, ""));
    norm.forEach((a, i) => norm.forEach((b, j) => {
        if (i !== j && (a === b || b.startsWith(`${a}/`)))
            throw err(`releaseClosure.roots "${roots[i]}" and "${roots[j]}" overlap; bytes would be counted twice`);
    }));
    for (const k of ["include", "exclude"]) {
        if (rc[k] !== undefined)
            throw err(`releaseClosure.${k} is not supported: every byte under roots ships; declare non-shippable artifacts in releaseClosure.private`);
    }
    if (!Array.isArray(json.assets))
        throw err("assets must be an array");
    const seen = new Set();
    const fpOwner = new Map();
    json.assets.forEach((a, i) => {
        const at = `assets[${i}]`;
        if (!isObj(a))
            throw err(`${at} must be an object`);
        if (typeof a.id !== "string" || a.id.length === 0)
            throw err(`${at}.id is required`);
        if (seen.has(a.id))
            throw err(`${at}.id "${a.id}" is duplicated`);
        seen.add(a.id);
        if (typeof a.placement !== "string" || !PLACEMENTS.has(a.placement))
            throw err(`${at}.placement must be one of ${[...PLACEMENTS].join(", ")}`);
        if (a.markers !== undefined && (!isStrArr(a.markers) || a.markers.some((m) => m.length < 4)))
            throw err(`${at}.markers must be a string array of literals at least 4 characters long`);
        if (a.fingerprints !== undefined) {
            if (!Array.isArray(a.fingerprints))
                throw err(`${at}.fingerprints must be an array`);
            a.fingerprints.forEach((f, j) => {
                if (!isObj(f) || f.type !== "sha256" || typeof f.value !== "string" || !/^[0-9a-f]{64}$/.test(f.value))
                    throw err(`${at}.fingerprints[${j}] must be {type:"sha256", value:<64 lowercase hex>}`);
                const owner = fpOwner.get(f.value);
                if (owner !== undefined && owner !== a.id)
                    throw err(`${at}.fingerprints[${j}] is also declared by asset "${owner}"; one secret cannot have two placements`);
                fpOwner.set(f.value, a.id);
            });
        }
        if (a.attacker !== undefined) {
            if (!isObj(a.attacker) || typeof a.attacker.objective !== "string" || !OBJECTIVES.has(a.attacker.objective))
                throw err(`${at}.attacker.objective must be one of ${[...OBJECTIVES].join(", ")}`);
            if (typeof a.attacker.success !== "string")
                throw err(`${at}.attacker.success is required`);
        }
        if (a.onConfirmedDistribution !== undefined && a.onConfirmedDistribution !== "block" && a.onConfirmedDistribution !== "warn")
            throw err(`${at}.onConfirmedDistribution must be "block" or "warn"`);
    });
    if (json.authorization !== undefined) {
        const az = json.authorization;
        if (!isObj(az))
            throw err("authorization must be an object");
        for (const k of ["principals", "tenants", "objects", "operations"])
            if (az[k] !== undefined && !isStrArr(az[k]))
                throw err(`authorization.${k} must be a string array`);
        if (az.defaultExpected !== undefined && az.defaultExpected !== "allow" && az.defaultExpected !== "deny")
            throw err(`authorization.defaultExpected must be "allow" or "deny"`);
        if (az.cases !== undefined) {
            if (!Array.isArray(az.cases))
                throw err("authorization.cases must be an array");
            az.cases.forEach((c, i) => {
                if (!isObj(c))
                    throw err(`authorization.cases[${i}] must be an object`);
                for (const k of ["principal", "tenant", "object", "operation"])
                    if (typeof c[k] !== "string")
                        throw err(`authorization.cases[${i}].${k} is required`);
                if (c.id !== undefined && (typeof c.id !== "string" || c.id.length === 0))
                    throw err(`authorization.cases[${i}].id must be a non-empty string`);
                if (c.expected !== "allow" && c.expected !== "deny")
                    throw err(`authorization.cases[${i}].expected must be "allow" or "deny"`);
            });
        }
    }
    return json;
}
export function validatePolicy(json, file = "<policy>") {
    const err = (m) => new ConfigError(file, m);
    if (!isObj(json))
        throw err("policy must be a JSON object");
    if (json.schema !== "anti-rea/policy/v1")
        throw err(`schema must be "anti-rea/policy/v1"`);
    if (typeof json.releaseScope !== "string")
        throw err("releaseScope is required");
    if (!isStrArr(json.requiredLanes))
        throw err("requiredLanes must be a string array");
    for (const l of json.requiredLanes)
        if (!KNOWN_LANES.includes(l))
            throw err(`requiredLanes: unknown lane "${l}" (known: ${KNOWN_LANES.join(", ")})`);
    const gates = {};
    if (json.gates !== undefined) {
        if (!isObj(json.gates))
            throw err("gates must be an object");
        for (const [k, v] of Object.entries(json.gates)) {
            if (!ALL_GATES.includes(k))
                throw err(`unknown gate "${k}"`);
            if (v !== "block" && v !== "warn")
                throw err(`gates.${k} must be "block" or "warn"`);
            gates[k] = v;
        }
    }
    if (json.exceptions !== undefined) {
        if (!Array.isArray(json.exceptions))
            throw err("exceptions must be an array");
        json.exceptions.forEach((x, i) => {
            const at = `exceptions[${i}]`;
            if (!isObj(x))
                throw err(`${at} must be an object`);
            if (typeof x.gate !== "string" || !ALL_GATES.includes(x.gate))
                throw err(`${at}.gate is invalid`);
            for (const k of ["owner", "scope", "rationale", "expiry"])
                if (typeof x[k] !== "string" || x[k].length === 0)
                    throw err(`${at}.${k} is required (exceptions need a named owner, scope, rationale and expiry)`);
            if (!/^\d{4}-\d{2}-\d{2}$/.test(x.expiry))
                throw err(`${at}.expiry must be YYYY-MM-DD`);
            if (x.assetId !== undefined && typeof x.assetId !== "string")
                throw err(`${at}.assetId must be a string`);
            if (x.lane !== undefined && !KNOWN_LANES.includes(x.lane))
                throw err(`${at}.lane must be one of ${KNOWN_LANES.join(", ")}`);
        });
    }
    return { ...json, gates: { ...DEFAULT_GATES, ...gates } };
}
export function loadManifest(path) {
    const { json, sha256 } = readJson(path);
    return { value: validateManifest(json, path), path, sha256 };
}
export function loadPolicy(path) {
    const { json, sha256 } = readJson(path);
    return { value: validatePolicy(json, path), path, sha256 };
}
export function assetById(m, id) {
    return m.assets.find((a) => a.id === id);
}
