import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { fingerprintOf } from "../src/lanes/detectors.js";
import type { Manifest } from "../src/model/manifest.js";
import type { Policy } from "../src/model/policy.js";
import { validateManifest, validatePolicy, type Loaded } from "../src/util/io.js";

export function tmp(prefix = "anti-rea-test-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function put(root: string, rel: string, data: Buffer | string): void {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, data);
}

let cachedPem: string | null = null;
/** A synthetic RSA key generated per test run; never used for anything. */
export function syntheticPem(): string {
  cachedPem ??= generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  return cachedPem;
}

export function manifestFor(dir: string, m: Omit<Manifest, "schema" | "application"> & Partial<Pick<Manifest, "application">>): Loaded<Manifest> {
  const value = validateManifest({ schema: "anti-rea/manifest/v1", application: { name: "t", version: "1" }, ...m });
  return { value, path: join(dir, "manifest.json"), sha256: "0".repeat(64) };
}

export function policyOf(p: Partial<Policy> = {}): Loaded<Policy> {
  const value = validatePolicy({
    schema: "anti-rea/policy/v1",
    releaseScope: "test",
    requiredLanes: ["inventory", "exposure", "placement"],
    ...p,
  });
  return { value, path: "policy.json", sha256: "0".repeat(64) };
}

export function fp(secret: string) {
  return { type: "sha256" as const, value: fingerprintOf(secret) };
}
