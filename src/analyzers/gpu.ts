import { looksLikeElf, readElf, EM } from "../codecs/elf.js";
import { isBinary } from "../lanes/types.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/** PTX source: a TEXT file whose `.version`, `.target sm_NN` and `.entry` directives start lines. */
function looksLikePtx(b: Buffer): boolean {
  if (b.indexOf(".target") < 0 || b.indexOf(".entry") < 0 || b.indexOf(".version") < 0) return false; // cheap probes first
  if (isBinary(b)) return false;
  const head = b.toString("latin1", 0, Math.min(b.length, 256 * 1024));
  return /^\s*\.version\s+\d+\.\d+/m.test(head) && /^\s*\.target\s+sm_\d+/m.test(head) && /\.entry\s+[\w$]+/.test(head);
}

/**
 * gpu (item scope): GPU compute payloads. PTX is human-readable virtual ISA (kernel names and source-
 * level assembly); a CUDA fatbin (magic 0xBA55ED50) bundles PTX and/or SASS; a CUBIN is an ELF with
 * machine 190 and `.nv.info`. PTX is required to show all three of `.version`, `.target` and `.entry`
 * so prose is not mistaken for a kernel.
 */

const FATBIN = 0xba55ed50;

export const gpu: Analyzer = {
  id: "gpu",
  title: "GPU kernels (PTX, CUDA fatbin, CUBIN)",
  mirrorsRea: "CUDA PTX / fatbin / cubin recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    const b = ctx.bytes;
    if (b.length >= 4 && b.readUInt32LE(0) === FATBIN) return true;
    if (looksLikeElf(b)) {
      try {
        if (readElf(b).machine === EM.CUDA) return true;
      } catch {
        /* ignore */
      }
    }
    return looksLikePtx(b);
  },

  profile(): ProfileTags {
    return { platforms: ["GPU/CUDA"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    if (bytes.length >= 4 && bytes.readUInt32LE(0) === FATBIN)
      return [{ analyzerId: this.id, rubricId: "symbols/local", title: "CUDA fatbin", recovers: "a CUDA fatbinary bundling PTX and/or SASS; cuobjdump extracts the PTX virtual-ISA source and kernel names", remediation: "ship SASS-only cubins (not PTX) where possible; PTX is readable virtual assembly", avoidable: true, path, coverage: "full", detail: path }];
    if (looksLikeElf(bytes)) {
      try {
        if (readElf(bytes).machine === EM.CUDA)
          return [{ analyzerId: this.id, rubricId: "symbols/local", title: "CUDA cubin (SASS)", recovers: "a CUDA device ELF (cubin); nvdisasm disassembles the SASS and `.nv.info` names the kernels", remediation: "inherent to shipping GPU code; strip extra symbols if present", avoidable: false, path, coverage: "full", detail: path }];
      } catch {
        /* ignore */
      }
    }
    return [{ analyzerId: this.id, rubricId: "symbols/local", title: "PTX GPU kernel source", recovers: "PTX virtual-ISA source: kernel entry names and readable assembly", remediation: "ship compiled cubins instead of PTX where the target GPU is known; PTX is human-readable", avoidable: true, path, coverage: "full", detail: path }];
  },
};
