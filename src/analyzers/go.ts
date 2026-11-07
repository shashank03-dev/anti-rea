import { looksLikeElf } from "../codecs/elf.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * go (item scope): Go binaries embed a buildinfo blob (`go version -m`): the module path, the full
 * dependency graph with versions, the VCS revision and the build settings — including `-ldflags`, which
 * is why a `-X importpath.key=<secret>` would otherwise land in the report verbatim (the lane redacts it,
 * plan item 7). Go function names in the pclntab survive `-s -w` and are reported as inherent (ELF Go is
 * covered by native-elf; this analyzer adds the pclntab note for Go Mach-O/PE).
 *
 * Format (Go's debug/buildinfo): the 14-byte magic, pointer size, a flags byte, padding to 32 bytes; with
 * flag 0x2 (Go ≥ 1.18) the runtime version and the modinfo follow inline as uvarint-length strings, the
 * modinfo wrapped in 16-byte sentinels. Older binaries store pointers instead and are reported as
 * detected, not decoded.
 */

const MAGIC = Buffer.from("\xff Go buildinf:", "latin1");

function uvarint(b: Buffer, o: number): [number, number] {
  let x = 0;
  let shift = 0;
  let p = o;
  for (let i = 0; i < 9 && p < b.length; i++) {
    const c = b[p++]!;
    x += (c & 0x7f) * 2 ** shift;
    if ((c & 0x80) === 0) break;
    shift += 7;
  }
  return [x, p];
}

interface GoBuildInfo {
  /** Runtime version ("go1.22.3"); "" for the undecoded pre-1.18 format. */
  version: string;
  modInfo: string;
  inline: boolean;
}

/** Read one uvarint-length byte string at `p`. */
function readBytes(b: Buffer, p: number): { bytes: Buffer; next: number } | null {
  const [len, np] = uvarint(b, p);
  if (len > 16 * 1024 * 1024 || np + len > b.length) return null;
  return { bytes: b.subarray(np, np + len), next: np + len };
}

export function readGoBuildInfo(b: Buffer): GoBuildInfo | null {
  let pre118: GoBuildInfo | null = null;
  // The magic can also occur as a plain string (a binary that imports debug/buildinfo carries it as a
  // constant), so try each occurrence and keep the first that decodes as a real header.
  for (let idx = b.indexOf(MAGIC), n = 0; idx >= 0 && n < 64; idx = b.indexOf(MAGIC, idx + 1), n++) {
    if (idx + 32 > b.length) break;
    const ptrSize = b[idx + 14]!;
    const flags = b[idx + 15]!;
    if (ptrSize !== 4 && ptrSize !== 8) continue;
    if ((flags & 0x2) === 0) {
      pre118 ??= { version: "", modInfo: "", inline: false };
      continue;
    }
    const v = readBytes(b, idx + 32);
    if (!v) continue;
    const version = v.bytes.toString("utf8");
    if (!/^(?:go\d|devel)/.test(version)) continue;
    const m = readBytes(b, v.next);
    // The modinfo is bracketed by 16-byte sentinels; strip them on BYTES, then decode.
    const mod = m && m.bytes.length >= 33 ? m.bytes.subarray(16, m.bytes.length - 16).toString("utf8") : "";
    return { version, modInfo: mod, inline: true };
  }
  return pre118;
}

export const go: Analyzer = {
  id: "go",
  title: "Go buildinfo (module, deps, VCS, ldflags)",
  mirrorsRea: "`go version -m` buildinfo recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    return ctx.scope === "item" && ctx.bytes.indexOf(MAGIC) >= 0 && readGoBuildInfo(ctx.bytes) !== null;
  },

  profile(): ProfileTags {
    return { languages: ["Go"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];
    const info = readGoBuildInfo(bytes);
    if (!info) return out;

    if (!info.inline) {
      out.push({ analyzerId: this.id, rubricId: "metadata/build", title: "Go buildinfo (pre-1.18 format, not decoded)", recovers: "a Go binary built before Go 1.18; `go version -m` still prints its module path and dependencies, but this version does not decode the pointer-based layout", remediation: "module and dependency info is inherent to Go binaries; keep secrets out of `-ldflags -X`", avoidable: false, path, coverage: "detected-only", detail: path });
    } else {
      const lines = info.modInfo.split("\n");
      const modPath = lines.find((l) => l.startsWith("path\t"))?.slice(5) ?? lines.find((l) => l.startsWith("mod\t"))?.split("\t")[1];
      const deps = lines.filter((l) => l.startsWith("dep\t")).length;
      const settings = lines.filter((l) => l.startsWith("build\t")).map((l) => l.slice(6));
      const vcs = settings.find((s) => s.startsWith("vcs.revision="));
      const ldflags = settings.filter((s) => s.startsWith("-ldflags="));
      const detailParts = [`runtime ${info.version}`, modPath ? `module ${modPath}` : "", `${deps} dependency/ies`, vcs ?? "", ldflags.length ? `recorded ${ldflags.join(" ")}` : ""].filter(Boolean);
      out.push({
        analyzerId: this.id,
        rubricId: "metadata/build",
        title: "Go buildinfo: module, dependencies and build settings",
        recovers: `the module path, ${deps} dependency/ies with versions, the VCS revision and the build settings via \`go version -m\`${ldflags.length ? "; the recorded -ldflags are listed here with any assigned values redacted" : ""}`,
        remediation: "VCS stamping can be disabled with `-buildvcs=false`; module and dependency info is inherent to Go binaries. Keep secrets out of `-ldflags -X`: anything set there is readable by anyone",
        avoidable: false,
        path,
        coverage: "full",
        detail: `${path}: ${detailParts.join("; ")}`,
      });
    }

    // Go function names (pclntab) are inherent; native-elf already reports them for ELF Go binaries.
    if (!looksLikeElf(bytes))
      out.push({ analyzerId: this.id, rubricId: "symbols/inherent", title: "Go pclntab function names", recovers: "Go embeds a function-name table (pclntab); function and package names survive `-s -w`", remediation: "inherent to the Go runtime; third-party `garble` renames them at the cost of debuggability", avoidable: false, path, coverage: "full", detail: path });
    return out;
  },
};
