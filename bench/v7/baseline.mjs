// BL — the "careful release-engineer checklist" baseline (PREREGISTRATION.md §2.2). It uses only standard
// tools a release engineer already has (unzip, tar, @electron/asar, llvm-objdump, llvm-nm, find, grep-style
// regexes), and it EXPANDS archives first, so packaging alone cannot make it lose:
//   dwarf     `objdump -h` lists a section named .debug_* / .zdebug_* / __debug_* / __zdebug_*
//   locals    `nm` (llvm-nm) prints a defined symbol with a lowercase (local) type letter t/d/b/s/r
//   debugmap  `nm -a` prints an OSO or SO stab whose name is not a directory
//   dsym      a directory named *.dSYM exists
//   map       a *.map file exists, or a script contains "sourceMappingURL=data:"
//   webprefs  a script matches nodeIntegration*: true | contextIsolation: false | sandbox: false |
//             webSecurity: false | allowRunningInsecureContent: true (whitespace-tolerant)
//   devtools  a script matches openDevTools(
// Binary checks skip files inside *.dSYM bundles (an engineer checks the binary, not its debug companion).
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ASAR = join(ROOT, "node_modules", "@electron", "asar", "bin", "asar.mjs");

function files(dir) {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else out.push(p);
    }
  };
  walk(dir);
  return out;
}

function dirs(dir) {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) {
        out.push(p);
        walk(p);
      }
    }
  };
  walk(dir);
  return out;
}

/** Expand zip, tar.gz and asar archives in place (beside the archive, as <name>.x/), up to 4 levels. */
function expandAll(root) {
  const done = new Set();
  for (let pass = 0; pass < 4; pass++) {
    let found = false;
    for (const f of files(root)) {
      if (done.has(f)) continue;
      const x = `${f}.x`;
      let r = null;
      if (/\.zip$/i.test(f)) r = spawnSync("unzip", ["-q", "-o", f, "-d", x]);
      else if (/\.(tar\.gz|tgz)$/i.test(f)) {
        mkdirSync(x, { recursive: true });
        r = spawnSync("tar", ["-xzf", f, "-C", x]);
      } else if (/\.asar$/i.test(f)) r = spawnSync(process.execPath, [ASAR, "extract", f, x]);
      if (r) {
        done.add(f);
        found = true;
      }
    }
    if (!found) break;
  }
}

const SCRIPT = /\.(m?js|cjs)$/i;
const WEBPREFS = /nodeIntegration\w*\s*:\s*true|contextIsolation\s*:\s*false|sandbox\s*:\s*false|webSecurity\s*:\s*false|allowRunningInsecureContent\s*:\s*true/;

export function baseline(releaseDir) {
  const work = mkdtempSync(join(tmpdir(), "anti-rea-bl-"));
  try {
    cpSync(releaseDir, join(work, "r"), { recursive: true });
    const root = join(work, "r");
    expandAll(root);
    const all = files(root);
    const inDsym = (p) => /\.dSYM\//.test(p);
    const bins = all.filter((p) => !inDsym(p) && !SCRIPT.test(p) && !/\.(map|json|html|zip|gz|asar)$/i.test(p));
    const d = { dwarf: false, locals: false, debugmap: false, dsym: false, map: false, webprefs: false, devtools: false };
    for (const b of bins) {
      const h = spawnSync("objdump", ["-h", b], { encoding: "utf8", maxBuffer: 1 << 26 });
      if (h.status === 0 && /^\s*\d+\s+(\.z?debug_|__z?debug_)/m.test(h.stdout)) d.dwarf = true;
      const nm = spawnSync("nm", [b], { encoding: "utf8", maxBuffer: 1 << 28 });
      if (nm.status === 0 && /^[0-9a-fA-F]*\s+[tdbsr]\s+\S/m.test(nm.stdout)) d.locals = true;
      const na = spawnSync("nm", ["-a", b], { encoding: "utf8", maxBuffer: 1 << 28 });
      if (na.status === 0 && /\s-\s+[0-9a-f]{2}\s+[0-9a-f]{4}\s+(OSO|SO)\s+.*[^/\s]\s*$/m.test(na.stdout)) d.debugmap = true;
    }
    d.dsym = dirs(root).some((p) => /\.dSYM$/.test(p));
    d.map = all.some((p) => /\.map$/i.test(p)) || all.filter((p) => SCRIPT.test(p) || /\.css$/i.test(p)).some((p) => readFileSync(p, "utf8").includes("sourceMappingURL=data:"));
    const scripts = all.filter((p) => SCRIPT.test(p)).map((p) => readFileSync(p, "utf8"));
    d.webprefs = scripts.some((t) => WEBPREFS.test(t));
    d.devtools = scripts.some((t) => /openDevTools\s*\(/.test(t));
    return d;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url) && existsSync(process.argv[2] ?? "")) console.log(JSON.stringify(baseline(process.argv[2])));
