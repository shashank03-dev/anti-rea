import { readFileSync } from "node:fs";
import { ConfigError } from "../util/io.js";
import { nowIso } from "../util/clock.js";
import { TOOL } from "../version.js";
import { fingerprintOf, isKnownExample, witnessOf } from "./detectors.js";
export const EXTERNAL_TOOLS = ["gitleaks", "trufflehog"];
/** gitleaks `--report-format json`: an array of {RuleID, Secret, File, StartLine, ...}. */
function parseGitleaks(raw, path) {
    let json;
    try {
        json = JSON.parse(raw.trim() === "" ? "[]" : raw);
    }
    catch (e) {
        throw new ConfigError(path, `not a gitleaks JSON report (${e.message})`);
    }
    if (!Array.isArray(json))
        throw new ConfigError(path, "gitleaks report must be a JSON array");
    return json.map((r, i) => {
        if (typeof r.Secret !== "string" || typeof r.File !== "string")
            throw new ConfigError(path, `finding ${i} lacks Secret/File (was --redact used? Anti-REA needs the value to hash it)`);
        return { rule: String(r.RuleID ?? "unknown"), secret: r.Secret, file: r.File, line: typeof r.StartLine === "number" ? r.StartLine : undefined };
    });
}
/** trufflehog `--json`: one JSON object per line. */
function parseTrufflehog(raw, path) {
    const findings = [];
    let skipped = 0;
    for (const line of raw.split("\n")) {
        if (line.trim() === "")
            continue;
        let r;
        try {
            r = JSON.parse(line);
        }
        catch {
            skipped++;
            continue;
        }
        const secret = typeof r.Raw === "string" && r.Raw !== "" ? r.Raw : typeof r.RawV2 === "string" ? r.RawV2 : null;
        if (!secret || typeof r.DetectorName !== "string") {
            skipped++;
            continue;
        }
        const fs = r.SourceMetadata?.Data?.Filesystem;
        findings.push({
            rule: r.DetectorName,
            secret,
            file: typeof fs?.file === "string" ? fs.file : "(unknown)",
            line: typeof fs?.line === "number" ? fs.line : undefined,
            decoder: typeof r.DecoderName === "string" ? r.DecoderName : undefined,
        });
    }
    if (findings.length === 0 && skipped > 0 && raw.trim() !== "")
        throw new ConfigError(path, "no trufflehog JSON findings could be parsed");
    return { findings, skipped };
}
/** Rules that are generic entropy/keyword heuristics rather than a specific credential format. */
function isGenericRule(tool, rule) {
    return tool === "gitleaks" ? /^generic/i.test(rule) : false;
}
export function externalLane(manifest, imports, releaseId, startedAt) {
    const fpIndex = new Map();
    for (const a of manifest.assets)
        for (const f of a.fingerprints ?? [])
            fpIndex.set(f.value, a);
    return imports.map((imp) => {
        let raw;
        try {
            raw = readFileSync(imp.path, "utf8");
        }
        catch (e) {
            throw new ConfigError(imp.path, `cannot read ${imp.tool} findings (${e.message})`);
        }
        const parsed = imp.tool === "gitleaks" ? { findings: parseGitleaks(raw, imp.path), skipped: 0 } : parseTrufflehog(raw, imp.path);
        const findings = [];
        const seen = new Set();
        let examples = 0;
        for (const f of parsed.findings) {
            const fp = fingerprintOf(f.secret);
            const key = `${f.file}|${f.line ?? ""}|${fp}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            const where = `${f.file}${f.line ? `:${f.line}` : ""}`;
            const via = `${imp.tool}:${f.rule}${f.decoder && f.decoder !== "PLAIN" ? ` (decoded ${f.decoder})` : ""}`;
            const asset = fpIndex.get(fp);
            const witness = witnessOf(f.secret);
            if (asset) {
                const serverOnly = asset.placement === "server-only";
                findings.push({
                    id: `external/confirmed/${asset.id}/${imp.tool}/${where}`,
                    title: serverOnly
                        ? `Declared server-only secret "${asset.id}" is present in the distribution`
                        : `Declared secret "${asset.id}" is present (placement "${asset.placement}" permits local distribution)`,
                    severity: serverOnly ? "critical" : "info",
                    confidence: "confirmed",
                    gate: serverOnly ? "confirmedCriticalSecret" : undefined,
                    assetId: asset.id,
                    reportedPath: f.file,
                    location: f.line ? { line: f.line } : undefined,
                    detector: via,
                    witness,
                    detail: `Reported by ${via}; exact match against an owner-declared fingerprint.`,
                });
                continue;
            }
            if (isKnownExample({ detector: /aws/i.test(f.rule) ? "aws-access-key-id" : "keyed-credential", value: f.secret })) {
                examples++;
                continue;
            }
            const generic = isGenericRule(imp.tool, f.rule);
            findings.push({
                id: `external/lead/${imp.tool}/${f.rule}/${where}`,
                title: `Unconfirmed lead (${imp.tool}): ${f.rule}`,
                severity: generic ? "medium" : "high",
                confidence: generic ? "low" : "high",
                gate: generic ? "lowConfidenceCredentialLead" : "unconfirmedCredentialLead",
                reportedPath: f.file,
                location: f.line ? { line: f.line } : undefined,
                detector: via,
                witness,
                detail: "Not matched to any declared asset. Triage: rotate and remove, or declare it (with its fingerprint) if intentionally shipped.",
            });
        }
        return {
            id: `external/${imp.tool}`,
            lane: "external",
            releaseId,
            tool: TOOL,
            invocation: { importedTool: imp.tool, importedFindings: parsed.findings.length, unparsedLines: parsed.skipped, suppressedKnownExamples: examples },
            accessGranted: `findings produced by ${imp.tool} over the release (Anti-REA did not execute the tool)`,
            budget: { declared: `as configured in the ${imp.tool} run` },
            outcome: findings.length > 0 ? "recovered" : "not-recovered-within-budget",
            coverage: { artifactsConsidered: parsed.findings.length, artifactsSupported: parsed.findings.length, artifactsUnsupported: 0 },
            limitations: [
                `Imported from ${imp.tool}: its coverage of the release (skipped files, unsupported archives) is not visible to Anti-REA and is NOT counted as coverage.`,
                "Imported paths are relative to the scanner's own scan root and are not linked to inventory hashes.",
                ...(parsed.skipped > 0 ? [`${parsed.skipped} line(s) of the import could not be parsed.`] : []),
            ],
            findings,
            startedAt,
            finishedAt: nowIso(),
        };
    });
}
