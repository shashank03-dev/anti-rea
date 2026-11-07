import { looksLikeMachO, machOSlices, machoHardening, readMachO } from "../codecs/macho.js";
import { readNativeSymbols } from "../codecs/symbols.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * native-macho (item scope): what a REA tool recovers from a Mach-O binary — embedded DWARF, a stabs
 * debug map (build paths, source files, function names), local symbols, inherent ObjC/Swift metadata,
 * missing ASLR (MH_PIE), an iOS slice shipped without FairPlay encryption, the `get-task-allow`
 * debugging entitlement, and whether the code is signed. Adapts the v0.7 symbol reader and the signing
 * reader; it never re-implements their parsing.
 */

const SWIFT_OBJC = /__swift5_|__objc_classlist|__objc_classname|__objc_methname/;

/**
 * Whether each slice carries ObjC/Swift runtime sections. Section names live in the slice's own load
 * commands (its first few KB), so each slice is tested on its own head — not the fat file's first bytes,
 * which only cover the first slice.
 */
function runtimeMetadataPerSlice(b: Buffer): boolean[] {
  try {
    return machOSlices(b).map(({ buf }) => SWIFT_OBJC.test(buf.toString("latin1", 0, Math.min(buf.length, 256 * 1024))));
  } catch {
    return [];
  }
}

export const nativeMachO: Analyzer = {
  id: "native-macho",
  title: "Mach-O debug info, symbols and hardening",
  mirrorsRea: "Mach-O / dSYM symbol and DWARF recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    return ctx.scope === "item" && looksLikeMachO(ctx.bytes);
  },

  profile(ctx: AnalyzerContext): ProfileTags {
    const h = (ctx as ItemContext).bytes;
    const plats = new Set<string>();
    for (const s of machoHardening(h)) if (s.platform) plats.add(s.platform.replace(/-simulator$/, ""));
    return { platforms: plats.size ? [...plats] : ["macOS"], languages: runtimeMetadataPerSlice(h).some(Boolean) ? ["Swift/Objective-C"] : [] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];
    const slices = readNativeSymbols(bytes);
    const hard = machoHardening(bytes);
    const sign = (() => {
      try {
        return readMachO(bytes);
      } catch {
        return null;
      }
    })();
    const runtimeMeta = runtimeMetadataPerSlice(bytes);

    for (const s of slices) {
      if (s.error) continue;
      const where = `${path} (${s.arch})`;
      if (s.filetype === "dsym") {
        out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "dSYM debug companion shipped", recovers: "the complete DWARF for its binary: function names, types, variables and source line mappings", remediation: "do not ship the .dSYM bundle; upload it to your symbol server for crash symbolication instead", avoidable: true, path, coverage: "full", detail: `${where}: Mach-O MH_DSYM file.` });
        continue;
      }
      if (s.debugSections.length > 0)
        out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "Embedded DWARF debug information", recovers: `source-level names, types and line numbers (${s.debugSections.length} debug section(s): ${s.debugSections.slice(0, 4).join(", ")})`, remediation: "link with `-Wl,-S` or run `strip -S`; keep a separate dSYM for symbolication", avoidable: true, path, coverage: "full", detail: where });
      // A stripped binary keeps a leftover N_SO stab with no objects/sources (seen on /bin/ls); only a
      // debug map that actually names object or source files is a recovery aid (v0.8 calibration).
      if (s.stabs > 0 && (s.debugMapObjects.length > 0 || s.sourceFiles.length > 0))
        out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "Debug map (stabs): build paths, source and object files", recovers: `${s.debugMapObjects.length} object file path(s) and ${s.sourceFiles.length} source file name(s), usually including a build-machine user name${s.debugMapObjects[0] ? `, e.g. ${s.debugMapObjects[0]}` : ""}`, remediation: "`strip -S` removes the debug map (keep a dSYM for symbolication)", avoidable: true, path, coverage: "full", detail: `${where}: ${s.stabs} stab entries.` });
      if (s.localSymbols > 0)
        out.push({ analyzerId: this.id, rubricId: "symbols/local", title: "Unstripped local symbol names", recovers: `${s.localSymbols} non-exported function/data name(s)${s.localSample.length ? `, e.g. ${s.localSample.slice(0, 3).join(", ")}` : ""}`, remediation: "`strip -x` removes non-exported local symbols", avoidable: true, path, coverage: "full", detail: where });
    }

    hard.forEach((h, i) => {
      if (h.error) return;
      const where = `${path} (${h.arch})`;
      if (h.filetype === "execute" && !h.pie)
        out.push({ analyzerId: this.id, rubricId: "mitigations/owner-native", title: "Executable without position independence (no ASLR)", recovers: "a fixed image base, which makes exploitation easier; it is not itself a disclosure", remediation: "link with `-Wl,-pie` (the modern clang default)", avoidable: true, path, coverage: "full", detail: where });
      if (h.execStack)
        out.push({ analyzerId: this.id, rubricId: "mitigations/owner-native", title: "Executable stack (MH_ALLOW_STACK_EXECUTION)", recovers: "an executable stack weakens W^X", remediation: "do not link with `-Wl,-allow_stack_execute`", avoidable: true, path, coverage: "full", detail: where });
      if (h.platform === "iOS" && h.filetype === "execute" && h.cryptid === 0)
        out.push({ analyzerId: this.id, rubricId: "symbols/inherent", title: "iOS binary ships without FairPlay encryption", recovers: "the Mach-O loads directly: strings, symbols and ObjC/Swift metadata are readable without decryption", remediation: "App Store distribution re-encrypts the main binary; for in-house/enterprise builds this is inherent and cannot be set by the toolchain", avoidable: false, path, coverage: "full", detail: `${where}: LC_ENCRYPTION_INFO cryptid=0.` });
      if (runtimeMeta[i] && (h.filetype === "execute" || h.filetype === "dylib"))
        out.push({ analyzerId: this.id, rubricId: "symbols/inherent", title: "Objective-C / Swift runtime metadata", recovers: "class, method, protocol and property names required by the Objective-C/Swift runtime at load time", remediation: "inherent to the runtime; not removable by stripping. Swift name mangling and access control reduce, but do not eliminate, the exposed surface", avoidable: false, path, coverage: "full", detail: where });
    });

    // Tamper resistance, via the signing reader.
    for (const s of sign?.slices ?? []) {
      const cd = s.codeDirectories[0];
      const where = `${path} (${s.arch})`;
      const ents = Object.entries(s.entitlements ?? {}).filter(([, v]) => v !== false).map(([k]) => k);
      if (ents.includes("com.apple.security.get-task-allow"))
        out.push({ analyzerId: this.id, rubricId: "tamper/debuggable", title: "Debugging entitlement get-task-allow", recovers: "any local process can attach a debugger and read the running process's memory, keys and decrypted state", remediation: "sign the release build without `com.apple.security.get-task-allow` (it is a development-signing entitlement)", avoidable: true, path, coverage: "full", detail: where });
      if (s.filetype === "execute" && (!s.signed || !cd))
        out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: "Unsigned Mach-O executable", recovers: "the binary can be modified and re-run with no signature to invalidate; no Team ID binds it to you", remediation: "sign with a Developer ID certificate and enable the hardened runtime (`codesign -o runtime`)", avoidable: true, path, coverage: "full", detail: where });
      else if (s.filetype === "execute" && cd && (cd.flags & 0x2) !== 0 && !s.hasCmsSignature)
        out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: "Ad-hoc signed executable (no Developer ID)", recovers: "the signature is ad hoc: it has no certificate chain, so it does not bind the binary to you or trip Gatekeeper on modification by another signer", remediation: "re-sign with a Developer ID certificate", avoidable: true, path, coverage: "full", detail: where });
    }
    return out;
  },
};
