import { inflateSync } from "node:zlib";
import { elfSection, looksLikeElf, readElf } from "../codecs/elf.js";
import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * rust (item scope): the cargo-auditable crate graph (the ELF `.dep-v0` section: zlib-compressed JSON
 * of every crate and version), the exact rustc commit (std's panic locations embed
 * `/rustc/<commit>/library/…`), and panic/source paths that embed an absolute build path
 * (`/Users/<name>/…`, `/home/<name>/…`, including `~/.cargo/registry`). Rust is memory-safe, so no
 * canary/FORTIFY findings (native-elf honours this). Everything is found with bounded buffer scans: the
 * binary is never decoded into one string.
 */

const RUSTC = Buffer.from("/rustc/", "latin1");
const HEX40 = /^[0-9a-f]{40}\//;

/** The rustc commit hash from the first `/rustc/<40 hex>/` path, if any (bounded number of probes). */
function rustcCommit(b: Buffer): string | null {
  for (let at = b.indexOf(RUSTC), n = 0; at >= 0 && n < 256; at = b.indexOf(RUSTC, at + 1), n++) {
    const tail = b.toString("latin1", at + 7, Math.min(b.length, at + 48));
    if (HEX40.test(tail)) return tail.slice(0, 40);
  }
  return null;
}

function depGraph(b: Buffer): { crates: number; sample: string[] } | null {
  if (!looksLikeElf(b)) return null;
  try {
    const sec = elfSection(b, readElf(b), ".dep-v0");
    if (!sec) return null;
    const json = JSON.parse(inflateSync(sec, { maxOutputLength: 32 * 1024 * 1024 }).toString("utf8")) as { packages?: { name?: string; version?: string }[] };
    const pkgs = Array.isArray(json.packages) ? json.packages : [];
    return { crates: pkgs.length, sample: pkgs.slice(0, 5).map((p) => `${p.name ?? "?"}@${p.version ?? "?"}`) };
  } catch {
    return null;
  }
}

const BUILD_PATH = /^\/(?:Users|home)\/[^/\0\s"']{1,64}\/[^\0"'\s]{0,240}?\.rs/;

/** Up to `max` distinct absolute build paths ending in `.rs`, found by probing each `/Users/` and `/home/`. */
function buildPaths(b: Buffer, max = 5): string[] {
  const found = new Set<string>();
  for (const needle of ["/Users/", "/home/"]) {
    const nb = Buffer.from(needle, "latin1");
    for (let at = b.indexOf(nb), n = 0; at >= 0 && n < 20_000 && found.size < max; at = b.indexOf(nb, at + 1), n++) {
      const m = BUILD_PATH.exec(b.toString("latin1", at, Math.min(b.length, at + 320)));
      if (m) found.add(m[0]);
    }
  }
  return [...found];
}

export const rust: Analyzer = {
  id: "rust",
  title: "Rust cargo-auditable graph, rustc commit and build paths",
  mirrorsRea: "cargo-auditable / Rust panic-path recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    const b = ctx.bytes;
    if (b.indexOf(RUSTC) < 0 && !looksLikeElf(b)) return false;
    if (looksLikeElf(b)) {
      try {
        if (readElf(b).sections.some((s) => s.name === ".dep-v0")) return true;
      } catch {
        /* fall through */
      }
    }
    return rustcCommit(b) !== null;
  },

  profile(): ProfileTags {
    return { languages: ["Rust"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const out: RawFinding[] = [];

    const dep = depGraph(bytes);
    if (dep)
      out.push({ analyzerId: this.id, rubricId: "metadata/build", title: "cargo-auditable crate dependency graph", recovers: `the full crate dependency graph with versions (${dep.crates} crate(s)${dep.sample.length ? `, e.g. ${dep.sample.join(", ")}` : ""}) from the .dep-v0 section`, remediation: "cargo-auditable records this on purpose for SBOMs; remove it only if the dependency inventory must stay private (build without the cargo-auditable wrapper)", avoidable: true, path, coverage: "full", detail: path });

    let version = "";
    if (looksLikeElf(bytes)) {
      try {
        const c = elfSection(bytes, readElf(bytes), ".comment");
        version = (c && /rustc version (\d+\.\d+\.\d+[^\0)]*\)?)/.exec(c.toString("latin1"))?.[1]) || "";
      } catch {
        /* ignore */
      }
    }
    const commit = rustcCommit(bytes);
    if (version || commit)
      out.push({ analyzerId: this.id, rubricId: "metadata/build", title: "Rust toolchain identifiable", recovers: `the exact compiler (${[version && `rustc ${version}`, commit && `commit ${commit.slice(0, 12)}`].filter(Boolean).join(", ")}), from std's embedded panic paths`, remediation: "inherent to linking std; not sensitive on its own (it narrows which std a reverse engineer should load symbols for)", avoidable: false, path, coverage: "full", detail: path });

    const paths = buildPaths(bytes);
    if (paths.length > 0)
      out.push({ analyzerId: this.id, rubricId: "metadata/build", title: "Absolute build paths in panic/source references", recovers: `build-machine source paths embedded for panics, which name the build user (${paths[0]})`, remediation: 'build with `RUSTFLAGS="--remap-path-prefix=$HOME=~"` (and for $CARGO_HOME) to strip absolute paths', avoidable: true, path, coverage: "full", detail: path });
    return out;
  },
};
