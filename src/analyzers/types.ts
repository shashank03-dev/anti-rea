import type { Severity } from "../model/result.js";
import type { Inventory, InventoryItem } from "../lanes/types.js";
import { rubric, type RubricId, type Surface } from "./rubric.js";

/**
 * Analyzer framework (v0.8 exposure, plan "Architecture").
 *
 * An analyzer answers one launcher question: "if someone ran a REA-class tool on this artifact, what
 * would they recover, and what do I change to avoid it?" It reports, never grades freely: it names a
 * rubric row (which fixes surface + severity) and says, for each hit, what is recovered and the
 * toolchain fix. Every analyzer runs in try/catch in the lane; a throw becomes a coverage note.
 */

export type Origin = "owner" | "third-party";
export type Coverage = "full" | "partial" | "detected-only";

/** What a REA-class tool would recover from one artifact, and how to avoid it. */
export interface RecoveryFinding {
  readonly analyzerId: string;
  readonly rubricId: RubricId;
  readonly surface: Surface;
  readonly severity: Severity; // taken from the rubric row; never chosen freely
  readonly title: string;
  /** What a REA-class tool extracts (the launcher's exposure). */
  readonly recovers: string;
  /** The standard toolchain setting that removes or reduces it. */
  readonly remediation: string;
  /** false when the exposure is inherent to the platform and cannot be removed with toolchain settings. */
  readonly avoidable: boolean;
  /** owner code vs a vendored/third-party component. Assigned by the lane via attribution. */
  readonly origin: Origin;
  readonly path: string;
  readonly location?: { readonly line?: number; readonly byteOffset?: number };
  readonly coverage: Coverage;
  /** Redacted by the lane before serialization (never carries secret material). */
  readonly detail?: string;
}

/** What an analyzer emits; the lane fills in `origin` (attribution) and redacts `detail`. */
export type RawFinding = Omit<RecoveryFinding, "origin" | "surface" | "severity"> & {
  readonly origin?: Origin; // an analyzer may pin third-party for a component it is certain about
};

/** Profile tags an analyzer contributes to the product profile. */
export interface ProfileTags {
  readonly platforms?: readonly string[];
  readonly frameworks?: readonly string[];
  readonly languages?: readonly string[];
}

export interface ItemContext {
  readonly scope: "item";
  readonly item: InventoryItem;
  /** The bytes available to the analyzer (full file, or a head/tail slice for a gap item). */
  readonly bytes: Buffer;
  /** True when `bytes` cover the whole artifact; false when only a header/trailer slice was read. */
  readonly complete: boolean;
  readonly inv: Inventory;
}

/** A container (apk/ipa/asar/dmg) with its entries, or the release itself (root ""), for bundle analyzers. */
export interface BundleGroup {
  /** Container virtual path, or "" for the release group (top-level disk files). */
  readonly root: string;
  /**
   * Container bytes, read lazily and memoised (the APK Signing Block sits outside any entry); null for the
   * release group. Lazy so a release with many large containers (app.asar, jars) is never held in memory
   * all at once — only an analyzer that needs the raw bytes pays for them.
   */
  readonly raw: () => Buffer | null;
  readonly entries: readonly InventoryItem[];
}

export interface BundleContext {
  readonly scope: "bundle";
  readonly group: BundleGroup;
  readonly inv: Inventory;
  /** Read one entry's bytes (null when the entry is itself a gap). */
  readonly read: (it: InventoryItem) => Buffer | null;
  /**
   * The first group entry whose path ends at a segment boundary with `suffix` (a file name such as
   * `libapp.so`, or a tail such as `Flutter.framework/Flutter`). `notlibapp.so` never matches `libapp.so`.
   */
  readonly entry: (suffix: string) => InventoryItem | undefined;
}

export type AnalyzerContext = ItemContext | BundleContext;

export interface Analyzer {
  readonly id: string;
  readonly title: string;
  /** The REA capability this mirrors, for the REA → Anti-REA matrix. */
  readonly mirrorsRea: string;
  readonly scope: "item" | "bundle";
  /** Which bytes the lane must provide for an item analyzer. Header-only analyzers (no `full`) also run on gap items. */
  readonly needs: { readonly head?: number; readonly tail?: number; readonly full?: boolean };
  /** Cheap content test; names only corroborate. */
  detect(ctx: AnalyzerContext): boolean;
  analyze(ctx: AnalyzerContext): RawFinding[];
  /** Optional profile contribution when this analyzer applies. */
  profile?(ctx: AnalyzerContext): ProfileTags | null;
}

/** Fill surface and severity from the rubric row named by the raw finding. */
export function graded(raw: RawFinding, origin: Origin): RecoveryFinding {
  const row = rubric(raw.rubricId);
  return { ...raw, surface: row.surface, severity: row.severity, origin };
}
