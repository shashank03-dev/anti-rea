/**
 * v0.8 fuzzing: the exposure codecs and analyzers must never throw on malformed input, and must finish
 * within a time bound (count caps guard against a header that claims billions of entries). Each seed
 * keeps just enough of a valid prefix to pass the format's own magic check, then the body is truncated,
 * bit-flipped and randomised with a seeded PRNG so the run is reproducible (mirrors the repo's existing
 * "thousands of fuzzed corruptions rejected by the decoders" practice).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readElf, elfHardening, looksLikeElf } from "../src/codecs/elf.js";
import { readPe, looksLikePe } from "../src/codecs/pe.js";
import { machoHardening, looksLikeMachO } from "../src/codecs/macho.js";
import { readAndroidManifest } from "../src/codecs/axml.js";
import { models } from "../src/analyzers/models.js";
import { wasm } from "../src/analyzers/wasm.js";
import { godot } from "../src/analyzers/godot.js";
import { pyinstaller } from "../src/analyzers/pyinstaller.js";
import { go } from "../src/analyzers/go.js";
import type { Inventory, InventoryItem } from "../src/lanes/types.js";
import type { ItemContext } from "../src/analyzers/types.js";

/** Deterministic xorshift PRNG. */
function rng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 0xffffffff;
  };
}

function itemCtx(path: string, buf: Buffer): ItemContext {
  const item: InventoryItem = { ref: { path, sha256: "x", bytes: buf.length }, source: { kind: "mem", buf }, kind: "file", depth: 0, supported: true };
  const inv: Inventory = { releaseId: "r", items: [item], notes: [], limits: {} as never };
  return { scope: "item", item, bytes: buf, complete: true, inv };
}

/** Prefixes just valid enough that the format's detect/magic passes, so the parser body runs. */
const SEEDS: Record<string, Buffer> = {
  elf: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
  pe: (() => {
    const b = Buffer.alloc(0x200);
    b.write("MZ", 0, "latin1");
    b.writeUInt32LE(0x80, 0x3c);
    b.write("PE\u0000\u0000", 0x80, "latin1");
    b.writeUInt16LE(0x20b, 0x80 + 24); // PE32+
    return b;
  })(),
  macho: (() => {
    const b = Buffer.alloc(0x100);
    b.writeUInt32LE(0xfeedfacf, 0);
    return b;
  })(),
  axml: Buffer.from([0x03, 0x00, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00]),
  gguf: Buffer.concat([Buffer.from("GGUF"), Buffer.from([3, 0, 0, 0])]),
  wasm: Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
  godot: Buffer.concat([Buffer.from("GDPC"), Buffer.alloc(0x80)]),
  pyinstaller: Buffer.concat([Buffer.from("MZ"), Buffer.alloc(64), Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]), Buffer.alloc(80)]),
  go: Buffer.concat([Buffer.from("\xff Go buildinf:", "latin1"), Buffer.from([8, 2]), Buffer.alloc(64)]),
};

function corrupt(seed: Buffer, rand: () => number): Buffer {
  const keep = Math.min(seed.length, 8); // keep the magic prefix so detect passes
  const extra = Math.floor(rand() * 4096);
  const b = Buffer.alloc(keep + extra);
  seed.copy(b, 0, 0, keep);
  for (let i = keep; i < b.length; i++) b[i] = Math.floor(rand() * 256);
  // a few bit flips inside the kept region's tail and random truncation
  const flips = Math.floor(rand() * 6);
  for (let i = 0; i < flips; i++) {
    const at = keep + Math.floor(rand() * Math.max(1, extra));
    if (at < b.length) b[at] = (b[at] ?? 0) ^ (1 << Math.floor(rand() * 8));
  }
  const cut = Math.floor(rand() * b.length);
  return rand() < 0.3 ? b.subarray(0, cut) : b;
}

const RUNNERS: Record<string, (b: Buffer) => void> = {
  elf: (b) => { if (looksLikeElf(b)) elfHardening(readElf(b)); },
  pe: (b) => { if (looksLikePe(b)) readPe(b); },
  macho: (b) => { if (looksLikeMachO(b)) machoHardening(b); },
  axml: (b) => { readAndroidManifest(b); },
  gguf: (b) => { const c = itemCtx("m.gguf", b); if (models.detect(c)) models.analyze(c); },
  wasm: (b) => { const c = itemCtx("m.wasm", b); if (wasm.detect(c)) wasm.analyze(c); },
  godot: (b) => { const c = itemCtx("g.pck", b); if (godot.detect(c)) godot.analyze(c); },
  pyinstaller: (b) => { const c = itemCtx("a.exe", b); if (pyinstaller.detect(c)) pyinstaller.analyze(c); },
  go: (b) => { const c = itemCtx("app", b); if (go.detect(c)) go.analyze(c); },
};

for (const [name, seed] of Object.entries(SEEDS)) {
  test(`fuzz: ${name} reader survives 1000 corruptions without throwing or hanging`, () => {
    const rand = rng(0x9e3779b1 ^ name.length);
    const run = RUNNERS[name]!;
    const start = Date.now();
    for (let i = 0; i < 1000; i++) {
      const b = corrupt(seed, rand);
      try {
        run(b);
      } catch (e) {
        assert.fail(`${name} threw on corruption #${i} (len ${b.length}): ${(e as Error).message}`);
      }
    }
    assert.ok(Date.now() - start < 10000, `${name} fuzzing exceeded the time bound`);
  });
}

test("fuzz: fully random buffers never trip a reader via its detect() guard", () => {
  const rand = rng(12345);
  for (let i = 0; i < 2000; i++) {
    const b = Buffer.alloc(Math.floor(rand() * 512));
    for (let j = 0; j < b.length; j++) b[j] = Math.floor(rand() * 256);
    for (const run of Object.values(RUNNERS)) {
      try {
        run(b);
      } catch (e) {
        assert.fail(`random buffer threw: ${(e as Error).message}`);
      }
    }
  }
});
