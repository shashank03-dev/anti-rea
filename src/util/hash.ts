import { createHash } from "node:crypto";

export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Deterministic release identity: sha256 over the sorted (path, sha256, bytes)
 * triples of the inventory. Items that could not be hashed (unreadable,
 * symlinks, oversized) are included by path, so a release whose unknown
 * content changes shape also changes identity. Byte identity only (doc §9.2 —
 * authenticating build *context* additionally requires provenance).
 */
export function releaseId(entries: readonly { path: string; sha256: string; bytes: number }[]): string {
  const canonical = [...entries]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((e) => `${e.path}\t${e.sha256 || "unhashed"}\t${e.bytes}`)
    .join("\n");
  return sha256Hex(canonical);
}
