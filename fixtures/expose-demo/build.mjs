#!/usr/bin/env node
// Builds a SYNTHETIC multi-format release into fixtures/expose-demo/release/ (gitignored) so
// `npm run expose-demo` can show the exposure report across every format Anti-REA covers.
//
//   npm run build && node fixtures/expose-demo/build.mjs
//
// Hand-made fixtures are deterministic and cite the format they follow. Where a real toolchain is
// present (Go), real binaries are added too, with a planted `-X` secret to demonstrate redaction.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeAsar, writeZip } from "../../build/src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "release");
rmSync(out, { recursive: true, force: true });
const w = (rel, data) => {
  const p = join(out, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, data);
};

const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v >>> 0); return b; };
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };

// ---- models
const gstr = (s) => Buffer.concat([u64(s.length), Buffer.from(s)]);
w("models/llama.gguf", Buffer.concat([Buffer.from("GGUF"), u32(3), u64(226), u64(2), gstr("general.architecture"), u32(8), gstr("llama"), gstr("llama.context_length"), u32(4), u32(4096)]));
const stHdr = JSON.stringify({ __metadata__: { format: "pt", note: "demo" }, "model.embed.weight": { dtype: "F16", shape: [32000, 4096], data_offsets: [0, 1] } });
w("models/model.safetensors", Buffer.concat([u64(stHdr.length), Buffer.from(stHdr), Buffer.alloc(2)]));

// ---- Unity IL2CPP
w("Game_Data/il2cpp_data/Metadata/global-metadata.dat", Buffer.concat([u32(0xfab11baf), u32(29), Buffer.alloc(64)]));

// ---- Godot pack with GDScript source + bytecode
const pckEntry = (p) => { const b = Buffer.from(p); return Buffer.concat([u32(b.length), b, u64(0), u64(0), Buffer.alloc(16), u32(0)]); };
w("game.pck", Buffer.concat([Buffer.from("GDPC"), u32(2), u32(4), u32(2), u32(0), u32(0), u64(0), Buffer.alloc(64), u32(2), pckEntry("res://player.gd"), pckEntry("res://enemy.gdc")]));

// ---- PyInstaller executable (cookie near the end, Python 3.11)
const cookie = Buffer.concat([Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]), Buffer.alloc(12), Buffer.alloc(64)]);
cookie.writeUInt32BE(311, 20);
w("tools/report.exe", Buffer.concat([Buffer.from("MZ"), Buffer.alloc(2048), cookie]));

// ---- WASM with a name custom section
w("web/module.wasm", Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d]), u32(1), Buffer.from([0x00, 0x05, 0x04]), Buffer.from("name")]));

// ---- GPU: PTX + fatbin
w("gpu/kernel.ptx", ".version 8.0\n.target sm_90\n.address_size 64\n\n.visible .entry demoKernel(.param .u64 p) {\n  ret;\n}\n");
w("gpu/kernel.fatbin", Buffer.concat([u32(0xba55ed50), Buffer.alloc(60)]));

// ---- Electron app.asar: preload with insecure webPreferences + wholesale ipc, plus a source map
const preload = `const { contextBridge, ipcRenderer } = require('electron');\nconst win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\nwin.webContents.openDevTools();\ncontextBridge.exposeInMainWorld('api', ipcRenderer);\n`;
const appJs = `console.log("bundle");\n//# sourceMappingURL=app.js.map\n`;
const appMap = JSON.stringify({ version: 3, file: "app.js", sources: ["../src/app.ts"], sourcesContent: ["export const compute = (x: number) => x * 2; // original source"], mappings: "AAAA" });
w("resources/app.asar", writeAsar([
  { path: "package.json", data: Buffer.from(JSON.stringify({ name: "exposedemo-desktop", version: "0.8.0" })) },
  { path: "preload.js", data: Buffer.from(preload) },
  { path: "renderer/app.js", data: Buffer.from(appJs) },
  { path: "renderer/app.js.map", data: Buffer.from(appMap) },
]));

// ---- original source file shipped directly
w("src/app.ts", "export const compute = (x: number) => x * 2;\n");

// ---- third-party (vendored) model, to show the owner/third-party split
w("resources/app.asar.unpacked/node_modules/vendor-ml/weights.gguf", Buffer.concat([Buffer.from("GGUF"), u32(3), u64(10), u64(1), gstr("general.architecture"), u32(8), gstr("bert")]));

// ---- APK: binary AndroidManifest (debuggable=true) + a minimal DEX, zipped
function axmlManifest() {
  const strings = ["android", "package", "com.exposedemo.app", "manifest", "application", "debuggable"];
  const offs = [], data = [];
  let off = 0;
  for (const s of strings) { offs.push(u32(off)); const sb = Buffer.from(s); const rec = Buffer.concat([Buffer.from([sb.length, sb.length]), sb, Buffer.from([0])]); data.push(rec); off += rec.length; }
  let pool = Buffer.concat(data); if (pool.length % 4) pool = Buffer.concat([pool, Buffer.alloc(4 - (pool.length % 4))]);
  const stringsStart = 28 + strings.length * 4;
  const poolBody = Buffer.concat([u32(strings.length), u32(0), u32(0x100), u32(stringsStart), u32(0), ...offs, pool]);
  const poolChunk = Buffer.concat([Buffer.from([0x01, 0x00, 0x1c, 0x00]), u32(poolBody.length + 8), poolBody]);
  const idx = (s) => strings.indexOf(s);
  const startEl = (name, attrs) => {
    const attrBuf = Buffer.concat(attrs.map((a) => Buffer.concat([u32(0xffffffff), u32(a.name), u32(a.dataType === 0x03 ? a.data : 0xffffffff), Buffer.from([0x08, 0x00, 0x00, a.dataType]), u32(a.data)])));
    const body = Buffer.concat([u32(1), u32(0xffffffff), u32(0xffffffff), u32(name), Buffer.from([0x14, 0x00, 0x14, 0x00]), Buffer.from([attrs.length & 0xff, (attrs.length >> 8) & 0xff, 0, 0, 0, 0, 0, 0]), attrBuf]);
    return Buffer.concat([Buffer.from([0x02, 0x01, 0x10, 0x00]), u32(body.length + 8), body]);
  };
  const endEl = (name) => Buffer.concat([Buffer.from([0x03, 0x01, 0x10, 0x00]), u32(24), u32(1), u32(0xffffffff), u32(0xffffffff), u32(name)]);
  const body = Buffer.concat([poolChunk, startEl(idx("manifest"), [{ name: idx("package"), dataType: 0x03, data: idx("com.exposedemo.app") }]), startEl(idx("application"), [{ name: idx("debuggable"), dataType: 0x12, data: 1 }]), endEl(idx("application")), endEl(idx("manifest"))]);
  return Buffer.concat([Buffer.from([0x03, 0x00, 0x08, 0x00]), u32(body.length + 8), body]);
}
const dex = Buffer.alloc(0x70);
Buffer.from("dex\n035\0", "latin1").copy(dex, 0);
dex.writeUInt32LE(0x12345678, 0x28);
w("mobile/app.apk", writeZip([{ path: "AndroidManifest.xml", data: axmlManifest() }, { path: "classes.dex", data: dex }, { path: "resources.arsc", data: Buffer.alloc(16) }]));

// ---- real Go binaries (ELF/PE/WASM) with a planted -X secret, when the Go toolchain is present
if (spawnSync("/usr/bin/which", ["go"]).status === 0) {
  const gdir = join(out, ".gosrc");
  mkdirSync(gdir, { recursive: true });
  writeFileSync(join(gdir, "go.mod"), "module example.com/exposedemo\n\ngo 1.20\n");
  writeFileSync(join(gdir, "main.go"), 'package main\nimport "fmt"\nvar apiKey = "default"\nfunc main() { fmt.Println(apiKey) }\n');
  const SECRET = "sk-live-EXPOSE-DEMO-SECRET-0123456789abcdef";
  const build = (goos, goarch, outName) => {
    try {
      execFileSync("go", ["build", "-ldflags", `-X main.apiKey=${SECRET}`, "-o", join(out, outName), "."], { cwd: gdir, env: { ...process.env, GOOS: goos, GOARCH: goarch } });
    } catch (e) {
      console.warn(`go build ${goos}/${goarch} skipped: ${e.message.split("\n")[0]}`);
    }
  };
  build("linux", "amd64", "native/app-linux");
  build("windows", "amd64", "native/app.exe");
  build("js", "wasm", "web/app.wasm");
  rmSync(gdir, { recursive: true, force: true });
}

console.log(`built expose demo release -> ${out}`);
