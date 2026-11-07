import type { Severity } from "../model/result.js";

/**
 * Fixed grading rubric by attack surface (v0.8 exposure, plan "Rubric").
 *
 * An analyzer never invents a grade: it names a rubric row, and the row fixes both the attack surface
 * and the severity. This keeps grading auditable and consistent across the fifteen analyzers, and it
 * means the only way to change how a class of recovery is graded is to change this one table.
 *
 * Severity reuses the repo's `Severity` (critical | high | medium | low | info); the exposure report
 * and `--fail-on` use the MAXIMUM severity, never an aggregate score, so a critical can never be
 * averaged away (research §10.1).
 */

export type Surface = "code" | "symbols" | "metadata" | "tamper" | "mitigations" | "models";

export const SURFACE_TITLE: Record<Surface, string> = {
  code: "Code recoverability",
  symbols: "Symbols & structure",
  metadata: "Build & supply-chain metadata",
  tamper: "Tamper & debug resistance",
  mitigations: "Exploit mitigations",
  models: "Model/asset disclosure",
};

export interface RubricRow {
  readonly surface: Surface;
  readonly severity: Severity;
}

export const RUBRIC = {
  // Code recoverability
  "code/source-text": { surface: "code", severity: "critical" }, // sourcesContent, .py/GDScript, Mono Assembly-CSharp
  "code/near-source-bytecode": { surface: "code", severity: "high" }, // .NET IL, .pyc, DEX without R8

  // Symbols & structure
  "symbols/debug-info": { surface: "symbols", severity: "high" }, // DWARF, dSYM/PDB, stabs, WASM name+DWARF
  "symbols/metadata-clear": { surface: "symbols", severity: "high" }, // IL2CPP global-metadata.dat in the clear
  "symbols/local": { surface: "symbols", severity: "medium" }, // local symbols, ELF .symtab, WASM name only
  "symbols/inherent": { surface: "symbols", severity: "info" }, // ObjC/Swift metadata, Go pclntab

  // Build & supply-chain metadata
  "metadata/build": { surface: "metadata", severity: "low" }, // build paths, Go modules/VCS, cargo-auditable, PDB path, compiler version

  // Tamper & debug resistance
  "tamper/debuggable": { surface: "tamper", severity: "high" }, // android:debuggable, get-task-allow, insecure webPreferences
  "tamper/weak-protection": { surface: "tamper", severity: "medium" }, // unsigned, APK v1-only, fuses off, DevTools

  // Exploit mitigations
  "mitigations/owner-native": { surface: "mitigations", severity: "medium" }, // no PIE/NX/CFG on owner C/C++
  "mitigations/toolchain": { surface: "mitigations", severity: "low" }, // partial RELRO, Go/Rust toolchain defaults

  // Model/asset disclosure
  "models/plaintext": { surface: "models", severity: "medium" }, // plaintext safetensors/GGUF metadata
} as const satisfies Record<string, RubricRow>;

export type RubricId = keyof typeof RUBRIC;

export function rubric(id: RubricId): RubricRow {
  return RUBRIC[id];
}

const ORDER: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function severityRank(s: Severity): number {
  return ORDER[s];
}

/** The maximum of a set of severities (empty ⇒ null). Used by `--fail-on` and the Action's `max-grade`. */
export function maxSeverity(sevs: readonly Severity[]): Severity | null {
  let best: Severity | null = null;
  for (const s of sevs) if (best === null || ORDER[s] > ORDER[best]) best = s;
  return best;
}

/** True when `have` is at least as severe as `threshold`. */
export function meetsThreshold(have: Severity, threshold: Severity): boolean {
  return ORDER[have] >= ORDER[threshold];
}
