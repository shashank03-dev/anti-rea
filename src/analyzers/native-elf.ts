import { EM, elfHardening, elfSection, looksLikeElf, readElf, type ElfInfo } from "../codecs/elf.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * native-elf (item scope): what a REA tool recovers from an ELF binary — embedded DWARF, a `.symtab`
 * with local and source-file names, exploit-mitigation state (PIE, NX, RELRO) and RUNPATH build paths.
 *
 * Language-aware (plan item 6). Go and Rust are memory-safe, so no stack-canary or FORTIFY findings are
 * raised for them, and Go's `linux/amd64` default (non-PIE, no RELRO) is graded low and inherent to the
 * toolchain rather than as an owner C/C++ mitigation gap. Go `pclntab` function names are reported as
 * inherent. The Go buildinfo and the Rust cargo-auditable graph are left to the `go`/`rust` analyzers.
 * GPU and BPF images (CUDA cubins, AMDGPU code objects, eBPF) are not CPU executables: CPU mitigations
 * do not apply to them, so they are left to the `gpu` analyzer.
 */

const NON_CPU = new Set<number>([EM.CUDA, EM.AMDGPU, 247 /* EM_BPF */]);

type Lang = "go" | "rust" | null;

function detectLang(b: Buffer, e: ElfInfo): Lang {
  if (e.sections.some((s) => s.name === ".go.buildinfo" || s.name === ".gopclntab")) return "go";
  if (b.includes(Buffer.from("\xff Go buildinf:", "latin1"))) return "go";
  if (e.sections.some((s) => s.name === ".dep-v0")) return "rust";
  const comment = elfSection(b, e, ".comment");
  if (comment && comment.includes(Buffer.from("rustc", "latin1"))) return "rust";
  if (e.symtab.some((s) => s.name === "rust_begin_unwind" || s.name.startsWith("_ZN4core")) || e.dynsym.some((s) => s.name === "rust_eh_personality")) return "rust";
  return null;
}

const STRIP_DEBUG: Record<"go" | "rust" | "c", string> = {
  go: "build with `-ldflags=\"-s -w\"` (drops the symbol table and DWARF)",
  rust: "set `strip = \"debuginfo\"` (or `true`) and `debug = false` in the release profile",
  c: "strip debug sections with `strip --strip-debug` (keep a copy via `objcopy --only-keep-debug` for symbolication)",
};
const STRIP_SYMTAB: Record<"go" | "rust" | "c", string> = {
  go: "build with `-ldflags=\"-s -w\"`",
  rust: "set `strip = true` in the release profile",
  c: "`strip --strip-unneeded` removes `.symtab` (dynamic exports in `.dynsym` are kept)",
};

export const nativeElf: Analyzer = {
  id: "native-elf",
  title: "ELF debug info, symbols and hardening",
  mirrorsRea: "ELF symbol / DWARF recovery and checksec",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item" || !looksLikeElf(ctx.bytes)) return false;
    try {
      const e = readElf(ctx.bytes);
      return !NON_CPU.has(e.machine) && e.type !== 1 && e.type !== 4; // not relocatable objects or core dumps
    } catch {
      return false;
    }
  },

  profile(ctx: AnalyzerContext): ProfileTags | null {
    try {
      const b = (ctx as ItemContext).bytes;
      const lang = detectLang(b, readElf(b));
      return { platforms: ["Linux"], languages: lang === "go" ? ["Go"] : lang === "rust" ? ["Rust"] : ["C/C++"] };
    } catch {
      return { platforms: ["Linux"] };
    }
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];
    const e = readElf(bytes);
    const lang = detectLang(bytes, e);
    const memSafe = lang === "go" || lang === "rust";
    const tool = lang ?? "c";
    const h = elfHardening(e);
    const where = `${path} (${e.machineName}${lang ? `, ${lang === "go" ? "Go" : "Rust"}` : ""})`;

    // Counts defined to agree with symbols.ts / llvm-objdump: defined STB_LOCAL functions and objects.
    const debugSections = e.sections.filter((s) => /^\.z?debug_/.test(s.name)).map((s) => s.name);
    const localSyms = e.symtab.filter((s) => s.bind === 0 && (s.type === 1 || s.type === 2) && s.defined && s.name).length;
    const files = e.symtab.filter((s) => s.type === 4 && s.name).map((s) => s.name);

    if (debugSections.length > 0)
      out.push({ analyzerId: this.id, rubricId: "symbols/debug-info", title: "Embedded DWARF debug information", recovers: `source-level names, types and line numbers (${debugSections.length} section(s): ${debugSections.slice(0, 4).join(", ")})`, remediation: STRIP_DEBUG[tool], avoidable: true, path, coverage: "full", detail: where });
    if (!h.stripped && localSyms > 0)
      out.push({ analyzerId: this.id, rubricId: "symbols/local", title: "Unstripped .symtab with local symbols", recovers: `${localSyms} non-exported symbol name(s)${files.length ? ` and ${files.length} source file name(s), e.g. ${files[0]}` : ""}`, remediation: STRIP_SYMTAB[tool], avoidable: true, path, coverage: "full", detail: where });

    if (lang === "go")
      out.push({ analyzerId: this.id, rubricId: "symbols/inherent", title: "Go pclntab function names", recovers: "Go embeds a function-name table (pclntab) for panics and stack traces; function and package names survive `-s -w`", remediation: "inherent to the Go runtime; third-party `garble` can rename them, at the cost of debuggability and some reflection/plugin breakage", avoidable: false, path, coverage: "full", detail: where });

    // Exploit mitigations. Memory-safe toolchains: no canary/FORTIFY findings; PIE/RELRO defaults graded low.
    if (h.pie === "no-pie") {
      if (memSafe)
        out.push({ analyzerId: this.id, rubricId: "mitigations/toolchain", title: `Non-PIE ${lang === "go" ? "Go" : "Rust"} binary (toolchain default)`, recovers: "a fixed load address (no ASLR for the main image); this target's toolchain default", remediation: lang === "go" ? "Go `linux/amd64` builds non-PIE by default; build with `-buildmode=pie` if ASLR is required" : "build for a PIE target (the default on most Rust targets) or `-C relocation-model=pie`", avoidable: true, path, coverage: "full", detail: where });
      else
        out.push({ analyzerId: this.id, rubricId: "mitigations/owner-native", title: "Executable without position independence (no ASLR)", recovers: "a fixed image base, easing exploitation (not a disclosure in itself)", remediation: "compile and link with `-fPIE -pie`", avoidable: true, path, coverage: "full", detail: where });
    }
    if (h.nx === "disabled")
      out.push({ analyzerId: this.id, rubricId: "mitigations/owner-native", title: "Executable stack (NX disabled)", recovers: "an executable stack weakens DEP/NX", remediation: "remove executable-stack markers (`-Wl,-z,noexecstack`; check assembly objects for a missing `.note.GNU-stack`)", avoidable: true, path, coverage: "full", detail: `${where}: PT_GNU_STACK is executable` });
    if (h.relro === "partial")
      out.push({ analyzerId: this.id, rubricId: "mitigations/toolchain", title: "Partial RELRO", recovers: "the GOT is not fully read-only after relocation", remediation: "link with `-Wl,-z,relro,-z,now` for full RELRO", avoidable: true, path, coverage: "full", detail: where });
    else if (h.relro === "none" && e.hasDynamic && !memSafe)
      out.push({ analyzerId: this.id, rubricId: "mitigations/owner-native", title: "No RELRO", recovers: "the GOT stays writable, a classic exploitation target", remediation: "link with `-Wl,-z,relro,-z,now`", avoidable: true, path, coverage: "full", detail: where });

    for (const rp of [...e.runpath, ...e.rpath])
      if (/^\/(?:home|Users)\/[^/]+\//.test(rp) || rp.includes("/build/"))
        out.push({ analyzerId: this.id, rubricId: "metadata/build", title: "RUNPATH/RPATH leaks a build path", recovers: `a build-machine directory layout (${rp})`, remediation: "use an `$ORIGIN`-relative rpath at link time instead of an absolute build path", avoidable: true, path, coverage: "full", detail: where });
    return out;
  },
};
