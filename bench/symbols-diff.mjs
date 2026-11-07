#!/usr/bin/env node
/**
 * v0.7 differential: src/codecs/symbols.ts against `dsymutil -s` (the raw nlist table) on real Mach-O files.
 * `nm -a` is NOT the oracle: it omits N_AST stabs and invents names (`<redacted function N>`, ObjC metadata).
 * Usage: find /Applications/X.app -type f -perm -u+x | node bench/symbols-diff.mjs
 */
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { readNativeSymbols } from "../build/src/codecs/symbols.js";
const files = readFileSync(0, "utf8").split("\n").filter(Boolean).filter((f) => { try { const h = readFileSync(f).subarray(0, 4); return h.readUInt32LE(0) === 0xfeedfacf || h.readUInt32BE(0) === 0xcafebabe; } catch { return false; } });
let agree = 0, dis = 0, n = 0, withAids = 0, totalOso = 0;
for (const f of files) {
  let facts; try { facts = readNativeSymbols(readFileSync(f)); } catch { continue; }
  for (const s of facts) {
    if (s.error) { console.log("ERR", f, s.arch, s.error); continue; }
    let ds; try { ds = execFileSync("dsymutil", ["-s", "-arch", s.arch, f], { encoding: "utf8", maxBuffer: 1 << 30, stdio: ["ignore", "pipe", "ignore"] }); } catch { continue; }
    let stabs = 0, locals = 0, oso = 0;
    for (const l of ds.split("\n")) {
      const m = l.match(/^\[\s*\d+\] [0-9a-f]{8} ([0-9a-f]{2}) \(.*\) [0-9a-f]{2} +[0-9a-f]{4} +[0-9a-f]+(?: '(.*)')?$/); if (!m) continue;
      const t = parseInt(m[1], 16);
      if (t & 0xe0) { stabs++; if (t === 0x66) oso++; } else if (!(t & 1) && (t & 0x0e) === 0x0e && !/^__mh_\w+_header$/.test(m[2] ?? "")) locals++;
    }
    n++; if (s.stabs + s.localSymbols > 0) withAids++; totalOso += s.debugMapObjects.length;
    if (stabs === s.stabs && locals === s.localSymbols && oso >= s.debugMapObjects.length) agree++; else { dis++; console.log("DIS", f, s.arch, { stabs, mine: s.stabs, locals, mineL: s.localSymbols }); }
  }
}
console.log(JSON.stringify({ slices: n, agree, dis, slicesWithStabsOrLocals: withAids, uniqueDebugMapObjects: totalOso }));
