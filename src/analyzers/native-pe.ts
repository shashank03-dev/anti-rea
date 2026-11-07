import { looksLikePe, readPe } from "../codecs/pe.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * native-pe (item scope): what a REA tool recovers from a Windows PE — the CodeView PDB build path, the
 * exploit-mitigation state in `DllCharacteristics` (ASLR / DEP / CFG), and whether it is Authenticode
 * signed. Managed .NET assemblies (a CLR data directory) are left to the `dotnet` analyzer.
 *
 * Language-aware (plan item 6): Go and Rust are memory-safe, and Go's toolchain cannot emit Control Flow
 * Guard at all, so a Go/Rust PE's mitigation gaps are graded as toolchain defaults (low), not as owner
 * C/C++ gaps (medium).
 */

const GO_BUILDINFO = Buffer.from("\xff Go buildinf:", "latin1");
const RUSTC_PATH = Buffer.from("/rustc/", "latin1");

function peLanguage(b: Buffer): "go" | "rust" | null {
  if (b.indexOf(GO_BUILDINFO) >= 0) return "go";
  if (b.indexOf(RUSTC_PATH) >= 0) return "rust";
  return null;
}

export const nativePe: Analyzer = {
  id: "native-pe",
  title: "PE debug directory, hardening and signing",
  mirrorsRea: "PE header / PDB-path and checksec recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item" || !looksLikePe(ctx.bytes)) return false;
    try {
      return !readPe(ctx.bytes).clr; // managed assemblies go to the dotnet analyzer
    } catch {
      return false;
    }
  },

  profile(): ProfileTags {
    // A native PE's source language is not determinable from its headers; the go/rust analyzers tag it.
    return { platforms: ["Windows"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];
    const pe = readPe(bytes);
    const lang = peLanguage(bytes);
    const where = `${path} (${pe.machineName}${lang ? `, ${lang === "go" ? "Go" : "Rust"}` : ""})`;

    for (const d of pe.debug)
      if (d.pdbPath)
        out.push({ analyzerId: this.id, rubricId: "metadata/build", title: "CodeView debug directory names a PDB build path", recovers: `the PDB path recorded at link time (${d.pdbPath}), which leaks the build-machine layout, user name and project name`, remediation: "link with `/PDBALTPATH:%_PDB%` (file name only) or build in a neutral directory; keep the .pdb on your symbol server", avoidable: true, path, coverage: "full", detail: `${where}: RSDS guid ${d.guid ?? "?"} age ${d.age ?? "?"}` });

    const gap = (what: string, title: string, nativeFix: string, recovers: string) => {
      if (lang === "go")
        out.push({ analyzerId: this.id, rubricId: "mitigations/toolchain", title: `${title} (Go toolchain default)`, recovers: `${recovers}; Go is memory-safe and its linker ${what === "cfg" ? "cannot emit Control Flow Guard" : "sets this by default on current versions"}`, remediation: what === "cfg" ? "not available in the Go toolchain; inherent" : "rebuild with a current Go toolchain", avoidable: what !== "cfg", path, coverage: "full", detail: where });
      else if (lang === "rust")
        out.push({ analyzerId: this.id, rubricId: "mitigations/toolchain", title: `${title} (Rust toolchain default)`, recovers: `${recovers}; Rust is memory-safe, so this is a defence-in-depth gap`, remediation: what === "cfg" ? "build with `-C control-flow-guard` (MSVC targets)" : nativeFix, avoidable: true, path, coverage: "full", detail: where });
      else out.push({ analyzerId: this.id, rubricId: "mitigations/owner-native", title, recovers, remediation: nativeFix, avoidable: true, path, coverage: "full", detail: where });
    };
    if (!pe.aslr) gap("aslr", "No ASLR (DYNAMIC_BASE not set)", "link with `/DYNAMICBASE` (and `/HIGHENTROPYVA` for 64-bit)", "a fixed preferred base address, easing exploitation");
    if (!pe.nxCompat) gap("dep", "No DEP (NX_COMPAT not set)", "link with `/NXCOMPAT`", "data pages may be executable");
    if (!pe.guardCf) gap("cfg", "No Control Flow Guard", "compile and link with `/guard:cf`", "indirect calls are unguarded");

    if (!pe.dll && !pe.authenticode)
      out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: "Unsigned PE (no Authenticode)", recovers: "the binary can be modified and re-run with no signature to invalidate, and SmartScreen has no publisher to vouch for it", remediation: "sign the release with `signtool sign /fd sha256` and a code-signing certificate", avoidable: true, path, coverage: "full", detail: where });
    return out;
  },
};
