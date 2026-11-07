import type { AttackObjective, Placement } from "./result.js";

/**
 * Owner-declared asset manifest (research doc §6).
 *
 * Classification is a business decision, proposed by tooling but CONFIRMED by an
 * owner. Names such as `fraudScore` are leads, not proof of value or sensitivity.
 */

export interface SecretFingerprint {
  /** Only sha256 is supported, so plaintext never enters the manifest. */
  readonly type: "sha256";
  /**
   * Lowercase hex sha256 of the CANONICAL form of the secret (compute it with
   * `anti-rea fingerprint`). For PEM keys the canonical form is the base64 body
   * with headers, whitespace and `\n` escapes removed, so the same key matches
   * whether it ships as a .pem file or inside a JS string literal.
   */
  readonly value: string;
  readonly note?: string;
}

export interface AttackerSpec {
  readonly objective: AttackObjective;
  /** Human description of what counts as success for this asset. */
  readonly success: string;
  /**
   * Attack budget (time / queries / compute). The doc requires this be specified
   * BEFORE evaluation for budgeted-resistance assets; the string is recorded verbatim
   * as evidence of that pre-registration.
   */
  readonly budget?: string;
}

export interface AssetDecl {
  readonly id: string;
  readonly description?: string;
  readonly owner?: string;
  readonly placement: Placement;
  readonly rationale?: string;
  /** Online/offline constraint, recorded because it changes the achievable guarantee. */
  readonly offlineRequired?: boolean;

  /**
   * For server-only / sensitive-local *implementations*: literal marker strings
   * (symbol names, resource names, unique literals) whose presence in the
   * distribution is evidence the implementation is locally present.
   * These are leads, not proof of semantic value (see doc §6.2).
   */
  readonly markers?: readonly string[];

  /** For secret assets: fingerprints of forbidden values (sha256 only). */
  readonly fingerprints?: readonly SecretFingerprint[];

  readonly attacker?: AttackerSpec;

  /** Per-asset override of the policy default for a confirmed distribution finding. */
  readonly onConfirmedDistribution?: "block" | "warn";
}

export interface ReleaseClosureDecl {
  /**
   * Directories (relative to the manifest file) that make up the delivered
   * application. EVERY byte under these roots is treated as shipped, including
   * the contents of supported nested containers (zip/jar/apk/ipa, asar, tar, gzip).
   */
  readonly roots: readonly string[];
  /**
   * Globs for artifacts the owner declares PRIVATE (must not ship) — typically
   * source maps and debug symbols kept for support under access control. The tool
   * does not trust the declaration: any matching artifact found in the shipped
   * bytes trips the `declaredPrivateArtifactShipped` gate.
   */
  readonly private?: readonly string[];
}

export interface AuthorizationCase {
  readonly id?: string;
  readonly principal: string;
  readonly tenant: string;
  readonly object: string;
  readonly operation: string;
  /** The server-enforced ground truth for this (principal × tenant × object × operation). */
  readonly expected: "allow" | "deny";
}

export interface AuthorizationDecl {
  readonly target?: string;
  readonly principals?: readonly string[];
  readonly tenants?: readonly string[];
  readonly objects?: readonly string[];
  readonly operations?: readonly string[];
  /** Explicit cases override the cartesian expansion of the dimensions above. */
  readonly cases?: readonly AuthorizationCase[];
  /** Default expected verdict for generated cases when not otherwise specified. */
  readonly defaultExpected?: "allow" | "deny";
}

/**
 * v0.6: owner-declared platform expectations (research §14 stages 2–3). Facts are read from the shipped
 * bytes by the platform lane; any declared expectation they violate trips `platformHardeningViolation`.
 */
export interface PlatformDecl {
  readonly macos?: {
    /** Every Mach-O file must carry a code signature (default true when macos is declared). */
    readonly requireSigned?: boolean;
    /** Signed code must be Developer-ID signed (CMS present), not ad hoc or linker-signed. */
    readonly requireDeveloperId?: boolean;
    /** Executables (MH_EXECUTE) must enable the hardened runtime. */
    readonly requireHardenedRuntime?: boolean;
    /** Developer-signed code must carry this TeamIdentifier. */
    readonly teamId?: string;
    /** Entitlements that must not appear (default: get-task-allow, allow-dyld-environment-variables, disable-executable-page-protection). */
    readonly forbiddenEntitlements?: readonly string[];
    /** Bundle seals (Info.plist, CodeResources, sealed resources, nested code, added files) must be intact (default true). */
    readonly requireIntactSeal?: boolean;
  };
  readonly electron?: {
    /** Required fuse states, e.g. { "RunAsNode": false, "OnlyLoadAppFromAsar": true }. */
    readonly fuses?: Readonly<Record<string, boolean>>;
    /** Every app.asar in a macOS bundle must match its ElectronAsarIntegrity header hash. */
    readonly requireAsarIntegrity?: boolean;
  };
  readonly windows?: {
    /** Every PE file must carry an Authenticode signature (presence only; chains are not validated). */
    readonly requireAuthenticode?: boolean;
  };
}

/**
 * v0.6: build provenance to verify against the shipped bytes (research §9.2, §14 stage 4). An in-toto
 * Statement (bare or in a DSSE envelope) whose subjects must cover the release's top-level artifacts.
 */
export interface ProvenanceDecl {
  /** Path (relative to the manifest) of the provenance file: a DSSE envelope or a bare in-toto Statement, JSON or JSON Lines. */
  readonly statement: string;
  /** PEM public key(s) (relative paths) that must have signed the DSSE envelope. Unsigned provenance fails when set. */
  readonly publicKeys?: readonly string[];
  /** Expected builder id (SLSA v1 runDetails.builder.id or v0.2 builder.id). */
  readonly builderId?: string;
  /** Globs (relative to each root) of the artifacts that must be provenance subjects. Default: every top-level file. */
  readonly subjects?: readonly string[];
}

export interface Manifest {
  readonly schema: "anti-rea/manifest/v1";
  readonly application: { readonly name: string; readonly version: string };
  readonly releaseClosure: ReleaseClosureDecl;
  readonly assets: readonly AssetDecl[];
  readonly authorization?: AuthorizationDecl;
  readonly platform?: PlatformDecl;
  readonly provenance?: ProvenanceDecl;
}
