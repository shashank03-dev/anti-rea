import type { Manifest, PlatformDecl, ReAidsDecl } from "../model/manifest.js";
import type { Policy } from "../model/policy.js";
import type { Inventory } from "../lanes/types.js";
import type { PlatformFacts } from "../lanes/platform.js";

/**
 * `anti-rea init`: scaffold a manifest + policy for a build directory, so `assure` can run on day one.
 *
 * The scaffold is DERIVED from what the build actually contains, never guessed: a platform expectation is
 * declared only when the release holds something it applies to. That matters because the platform lane
 * treats an expectation with nothing to apply to as inconclusive, and an inconclusive required lane blocks
 * — a scaffold that declared `macos` for a Windows build would block every release for a reason that has
 * nothing to do with the release.
 *
 * What the scaffold can NOT know is the owner's asset model: which values are server-only secrets and which
 * code must stay on the server. `assets` starts empty and `nextSteps` says how to fill it; the asset model
 * is a business decision (research §6), so the tool proposes nothing there.
 */

/** Fuses whose secure state hardens a shipped Electron app against tampering and code lifting. */
const SECURE_FUSES: Readonly<Record<string, boolean>> = {
  RunAsNode: false,
  EnableNodeOptionsEnvironmentVariable: false,
  EnableNodeCliInspectArguments: false,
  EnableEmbeddedAsarIntegrityValidation: true,
  OnlyLoadAppFromAsar: true,
  GrantFileProtocolExtraPrivileges: false,
};

export interface InitInput {
  /** Path of the release directory relative to the directory the manifest is written to (posix or native). */
  readonly root: string;
  readonly app: { readonly name: string; readonly version: string };
  readonly inventory: Inventory;
  readonly facts: PlatformFacts;
  /** True when the exposure profile found Electron (an app.asar or Electron runtime). */
  readonly electron: boolean;
}

export interface InitResult {
  readonly manifest: Manifest;
  readonly policy: Policy;
  /** One line per declared expectation and the fact that justified it. */
  readonly declared: readonly string[];
  readonly nextSteps: readonly string[];
}

export function scaffold(input: InitInput): InitResult {
  const { facts, inventory } = input;
  const root = input.root.replace(/\\/g, "/").replace(/\/+$/, "") || ".";
  const declared: string[] = [];

  const reAids: { -readonly [K in keyof ReAidsDecl]: ReAidsDecl[K] } = {};
  declared.push("reAids: native debug info, debug maps and local symbols; PDB/dSYM/source-map files; original source files");
  if (input.electron) {
    reAids.electron = {};
    declared.push("reAids.electron: insecure webPreferences and openDevTools() (Electron found)");
  }

  const platform: { -readonly [K in keyof PlatformDecl]: PlatformDecl[K] } = {};
  if (facts.machO.length > 0) {
    const slices = facts.machO.flatMap((f) => f.slices);
    const executables = slices.filter((s) => s.filetype === "execute").length;
    const appBundles = facts.bundles.filter((b) => b.kind === "app").length;
    platform.macos = {
      requireSigned: true,
      requireDeveloperId: true,
      ...(executables > 0 ? { requireHardenedRuntime: true } : {}),
      requireIntactSeal: true,
    };
    declared.push(
      `platform.macos: every Mach-O signed with a Developer ID certificate${executables > 0 ? `, hardened runtime on ${executables} executable slice(s)` : ""}, intact bundle seals (${facts.machO.length} Mach-O file(s), ${appBundles} app bundle(s))`,
    );
  }

  const electronPlatform: { fuses?: Record<string, boolean>; requireAsarIntegrity?: boolean } = {};
  if (facts.fuses.length > 0) {
    // Only fuses every shipped wire knows: an older Electron's wire has no slot for a newer fuse, and an
    // expectation on an absent fuse is a violation, not a hardening gap the owner can close by configuration.
    const fuses: Record<string, boolean> = {};
    for (const [name, want] of Object.entries(SECURE_FUSES)) if (facts.fuses.every((w) => w.fuses[name] !== undefined)) fuses[name] = want;
    if (Object.keys(fuses).length > 0) {
      electronPlatform.fuses = fuses;
      declared.push(`platform.electron.fuses: ${Object.entries(fuses).map(([k, v]) => `${k}=${v ? "on" : "off"}`).join(", ")} (${facts.fuses.length} fuse wire(s) found)`);
    }
  }
  const macAsars = inventory.items.filter((i) => /\.app\/Contents\/Resources\/[^/]+\.asar$/.test(i.ref.path) && !/\.app\/Contents\/Frameworks\//.test(i.ref.path));
  if (macAsars.length > 0 && facts.bundles.some((b) => b.kind === "app")) {
    electronPlatform.requireAsarIntegrity = true;
    declared.push(`platform.electron.requireAsarIntegrity: ${macAsars.length} app.asar file(s) inside a macOS app bundle`);
  }
  if (Object.keys(electronPlatform).length > 0) platform.electron = electronPlatform;

  if (facts.pe.length > 0) {
    platform.windows = { requireAuthenticode: true };
    declared.push(`platform.windows: an Authenticode signature on every PE file (${facts.pe.length} found; vendored DLLs count too)`);
  }

  const hasPlatform = Object.keys(platform).length > 0;
  const manifest: Manifest = {
    schema: "anti-rea/manifest/v1",
    application: { name: input.app.name, version: input.app.version },
    releaseClosure: {
      roots: [root],
      private: ["**/*.map", "**/*.pdb", "**/*.dSYM/**"],
    },
    assets: [],
    ...(hasPlatform ? { platform } : {}),
    reAids,
  } as Manifest;

  const requiredLanes = ["inventory", "exposure", "placement", "aids", ...(hasPlatform ? ["platform"] : [])];
  const policy: Policy = {
    schema: "anti-rea/policy/v1",
    releaseScope: `Every byte under ${root} as the build produces it, including nested archives; excludes anything downloaded at runtime`,
    requiredLanes,
    gates: {},
    exceptions: [],
  };

  const nextSteps = [
    "Declare what must never ship. For each server-only secret (signing keys, live API secrets), run `anti-rea fingerprint --file <secret>` — it prints a sha256 and never the secret — and add it under \"assets\" with \"placement\": \"server-only\" and \"fingerprints\": [{ \"type\": \"sha256\", \"value\": \"<sha256>\" }].",
    "For proprietary logic that must stay on your server, add an asset with \"placement\": \"server-only\" and \"markers\": unique function or table names (4+ characters) that only that code contains.",
    "Values that are public by design (a publishable key, a public client id) go in as \"placement\": \"public-by-design\" so they are not flagged.",
  ];
  return { manifest, policy, declared, nextSteps };
}
