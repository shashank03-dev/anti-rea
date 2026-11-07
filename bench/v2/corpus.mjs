#!/usr/bin/env node
// Anti-REA benchmark corpus generator, v2 (pre-registered in bench/PREREGISTRATION.md).
// The v1 generator, as it ran, is kept in bench/v1/corpus.mjs.
//
//   node bench/corpus.mjs --set dev|eval --out <dir>
//
// The eval seed is NOT chosen by hand: it is the first 32 bits of the frozen
// tool+harness hash (bench/freeze.mjs), so it is fixed by the code being evaluated.
//
// Each scenario is an Electron-style release built from REAL third-party bytes
// (TypeScript compiler libs, @types/node, undici-types, @electron/asar, a real
// package-lock.json, slices of Homebrew's libnode Mach-O) with zero or more
// planted "needles". Every random choice is seeded; EC private keys are derived
// from seeded scalars, so plain/asar/zip corpora are byte-reproducible.
//
// All secrets are SYNTHETIC values in the shape of real formats. None is valid.
import { createECDH, createHash, createPrivateKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { fingerprintOf, writeAsar, writeTar, writeZip } from "../build/src/index.js";
import { frozenHash } from "./freeze.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const sha1 = (s) => createHash("sha1").update(s).digest("hex");
const SEEDS = { dev: 0x5eed0002, eval: null /* derived from the frozen hash at generation time */ };
const seedFor = (set) => (set === "eval" ? parseInt(frozenHash().slice(0, 8), 16) : SEEDS[set]);
const K = { dev: 4, eval: 20 };

export const FAMILIES = [
  { id: "CLEAN", truth: "pass" },
  { id: "LEAK-DECLARED", truth: "block" },
  { id: "PUBLIC-DECLARED", truth: "pass" },
  { id: "SERVER-IMPL", truth: "block" },
  { id: "PRIVATE-ARTIFACT", truth: "block" },
  { id: "UNDECLARED-LEAK", truth: "block" },
  { id: "UNVERIFIABLE", truth: "block" },
  { id: "UNVERIFIABLE-CLEAN", truth: "pass" },
  { id: "EXAMPLE-DOCS", truth: "pass" },
  { id: "COMPRESSED-CLEAN", truth: "pass" },
];

// ------------------------------------------------------------------ PRNG
function mulberry32(a) {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
class Rng {
  constructor(seed) { this.r = mulberry32(seed); }
  int(n) { return Math.floor(this.r() * n); }
  pick(a) { return a[this.int(a.length)]; }
  str(n, alphabet) { let s = ""; for (let i = 0; i < n; i++) s += alphabet[this.int(alphabet.length)]; return s; }
  bytes(n) { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = this.int(256); return b; }
  shuffle(a) { const c = [...a]; for (let i = c.length - 1; i > 0; i--) { const j = this.int(i + 1); [c[i], c[j]] = [c[j], c[i]]; } return c; }
}
const AN = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX = "0123456789abcdef";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64 = AN + "+/";
const URLSAFE = AN + "-_";

// ------------------------------------------------------------------ synthetic credentials
function ecPem(rng, sec1) {
  const d = rng.bytes(32);
  d[0] = (d[0] % 0x7f) + 1; // keep scalar below the curve order
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  const b64u = (b) => b.toString("base64url");
  const key = createPrivateKey({ key: { kty: "EC", crv: "P-256", d: b64u(d), x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) }, format: "jwk" });
  return key.export({ type: sec1 ? "sec1" : "pkcs8", format: "pem" });
}

// Each credential kind: [generator, variable name used when it is rendered into source].
/** Stratum INSIDE: formats Anti-REA v0.1 already detected. */
const INSIDE = {
  pem: [(r) => ecPem(r, r.int(2) === 1), "SIGNING_KEY"],
  github: [(r) => "ghp_" + r.str(36, AN), "GITHUB_TOKEN"],
  slack: [(r) => `xoxb-${r.str(12, "0123456789")}-${r.str(13, "0123456789")}-${r.str(24, AN)}`, "SLACK_BOT_TOKEN"],
  stripe: [(r) => "sk_live_" + r.str(24, AN), "STRIPE_SECRET_KEY"],
  aws: [(r) => ({ id: "AKIA" + r.str(16, B32), secret: r.str(40, B64) }), "AWS"],
};
/** Stratum NAMED-V2: v1's "outside" formats. v0.2 added named detectors for them AFTER seeing v1, so they are NOT held out. */
const NAMED_V2 = {
  gitlab: [(r) => "glpat-" + r.str(20, URLSAFE), "GITLAB_TOKEN"],
  npm: [(r) => "npm_" + r.str(36, AN), "NPM_TOKEN"],
  sendgrid: [(r) => `SG.${r.str(22, URLSAFE)}.${r.str(43, URLSAFE)}`, "SENDGRID_API_KEY"],
  huggingface: [(r) => "hf_" + r.str(34, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"), "HF_TOKEN"],
  shopify: [(r) => "shpat_" + r.str(32, HEX), "SHOPIFY_ACCESS_TOKEN"],
  digitalocean: [(r) => "dop_v1_" + r.str(64, HEX), "DIGITALOCEAN_TOKEN"],
  anthropic: [(r) => "sk-ant-api03-" + r.str(93, URLSAFE) + "AA", "ANTHROPIC_API_KEY"],
  openai: [(r) => `sk-proj-${r.str(74, URLSAFE)}T3BlbkFJ${r.str(74, URLSAFE)}`, "OPENAI_API_KEY"],
};
/** Stratum HELDOUT-PREFIXED: real prefixed formats with NO named Anti-REA detector (shapes from each provider's docs). */
const HELDOUT_PREFIXED = {
  groq: [(r) => "gsk_" + r.str(52, AN), "GROQ_API_KEY"],
  replicate: [(r) => "r8_" + r.str(37, AN), "REPLICATE_API_TOKEN"],
  fly: [(r) => "fo1_" + r.str(43, URLSAFE), "FLY_API_TOKEN"],
  planetscale: [(r) => "pscale_tkn_" + r.str(43, AN + "_"), "PLANETSCALE_SERVICE_TOKEN"],
  notion: [(r) => "secret_" + r.str(43, AN), "NOTION_TOKEN"],
  supabase: [(r) => "sbp_" + r.str(40, HEX), "SUPABASE_ACCESS_TOKEN"],
  resend: [(r) => `re_${r.str(8, AN)}_${r.str(24, AN)}`, "RESEND_API_KEY"],
  figma: [(r) => "figd_" + r.str(40, URLSAFE), "FIGMA_TOKEN"],
};
/** Stratum HELDOUT-UNPREFIXED: real formats with no distinctive prefix (keyword context only). */
const HELDOUT_UNPREFIXED = {
  mailchimp: [(r) => `${r.str(32, HEX)}-us${1 + r.int(20)}`, "MAILCHIMP_API_KEY"],
  datadog: [(r) => r.str(32, HEX), "DATADOG_API_KEY"],
  cloudflare: [(r) => r.str(40, URLSAFE), "CLOUDFLARE_API_TOKEN"],
  heroku: [(r) => `${r.str(8, HEX)}-${r.str(4, HEX)}-4${r.str(3, HEX)}-a${r.str(3, HEX)}-${r.str(12, HEX)}`, "HEROKU_API_KEY"],
  algolia: [(r) => r.str(32, HEX), "ALGOLIA_ADMIN_API_KEY"],
  twilio: [(r) => r.str(32, HEX), "TWILIO_AUTH_TOKEN"],
  vercel: [(r) => r.str(24, AN), "VERCEL_TOKEN"],
};
const STRATA = { INSIDE, "NAMED-V2": NAMED_V2, "HELDOUT-PREFIXED": HELDOUT_PREFIXED, "HELDOUT-UNPREFIXED": HELDOUT_UNPREFIXED };
/** An internal credential format no public scanner knows; owners know its shape. */
const CUSTOM = { corpsvc: [(r) => "corp-svc-" + r.str(32, AN), "CORP_SERVICE_TOKEN"] };
const CUSTOM_REGEX = "corp-svc-[A-Za-z0-9]{32}";

const PUBLIC = {
  googleBrowserKey: (r) => "AIza" + r.str(35, URLSAFE),
  stripePublishable: (r) => "pk_live_" + r.str(24, AN),
  sentryDsn: (r) => `https://${r.str(32, HEX)}@o${r.str(6, "0123456789")}.ingest.sentry.io/${r.str(7, "0123456789")}`,
};
const DOC_EXAMPLES = [
  "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "const stripe = require('stripe')('sk_test_4eC39HqLyjWDarjtT1zdp7dc'); // Stripe documentation test key",
];

/** How a credential value appears in source. Returns {text, values[]} — values are what must be fingerprinted. */
function render(kind, v, style, varName) {
  if (kind === "aws") {
    const t = style === "json" ? `{"aws_access_key_id":"${v.id}","aws_secret_access_key":"${v.secret}"}` : `const AWS_KEY_ID = "${v.id}";\nconst AWS_SECRET = "${v.secret}";`;
    return { text: t, values: [v.id, v.secret] };
  }
  if (kind === "pem") {
    const esc = v.trimEnd().replace(/\n/g, "\\n");
    const t = style === "file" ? v : style === "json" ? `{"signingKey":"${esc}"}` : `const SIGNING_KEY = "${esc}";`;
    return { text: t, values: [v] };
  }
  const t = style === "json" ? `{"${varName.toLowerCase()}":"${v}"}` : style === "file" ? `${varName}=${v}\n` : `const ${varName} = "${v}";`;
  return { text: t, values: [v] };
}

// ------------------------------------------------------------------ background (real third-party bytes)
function backgroundPool() {
  const roots = ["node_modules/typescript/lib", "node_modules/@types/node", "node_modules/undici-types", "node_modules/@electron/asar", "node_modules/minimatch", "node_modules/glob"];
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (/\.(js|cjs|mjs|d\.ts|json)$/.test(n) && st.size > 2048 && st.size < 1_500_000) out.push(relative(ROOT, p));
    }
  };
  for (const r of roots) if (existsSync(join(ROOT, r))) walk(join(ROOT, r));
  return out;
}
const LIBNODE = "/opt/homebrew/Cellar/node/26.11.1/lib/libnode.147.dylib";

function nativeSlice(rng, needleUtf16) {
  const src = existsSync(LIBNODE) ? readFileSync(LIBNODE) : rng.bytes(4 << 20);
  const len = 1 << 20;
  const start = rng.int(Math.max(1, src.length - len - 4096)) & ~0xfff;
  const buf = Buffer.from(src.subarray(0, 4096).toString("latin1") + src.subarray(start, start + len).toString("latin1"), "latin1"); // real Mach-O header + real body slice
  if (needleUtf16) {
    const s = Buffer.from(needleUtf16, "utf16le");
    const at = 8192 + rng.int(buf.length - 16384 - s.length) & ~1;
    buf.fill(0, at - 16, at + s.length + 16);
    s.copy(buf, at);
  }
  return buf;
}

const DATA_URI_PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAPklEQVR4nGNgGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwCkbBKBgFowAAi4QLAVF2pT8AAAAASUVORK5CYII=";

function appJs(rng, extra = "", sourcemap = "external") {
  const id = () => `${rng.str(8, HEX)}-${rng.str(4, HEX)}-4${rng.str(3, HEX)}-a${rng.str(3, HEX)}-${rng.str(12, HEX)}`;
  const lines = [
    '"use strict";',
    `const BUILD_ID = "${id()}";`,
    `const COMMIT = "${rng.str(40, HEX)}";`,
    `const LOGO = "${DATA_URI_PNG}";`,
    `const ASSET_INTEGRITY = { "vendor.js": "sha384-${rng.str(64, B64)}" };`,
    "export function render(root) { root.textContent = `Build ${BUILD_ID}`; }",
    extra,
  ];
  if (sourcemap === "external") lines.push(`//# sourceMappingURL=https://symbols.example.invalid/app/${rng.str(12, HEX)}/app.js.map`);
  if (sourcemap === "inline") lines.push("//# sourceMappingURL=data:application/json;base64," + Buffer.from(JSON.stringify({ version: 3, sources: ["src/app.ts"], sourcesContent: ["export const secretSauce = 1;"], mappings: "AAAA;AACA" })).toString("base64"));
  return lines.join("\n") + "\n";
}

const ARCHIVE_NAME = { xz: "legacy.tar.xz", bz2: "legacy.tar.bz2", zst: "legacy.tar.zst", deb: "legacy-assets_1.0_all.deb", "enc-zip": "legacy-encrypted.zip", lz4: "legacy.tar.lz4" };
/** Synthetic archive password for W13; the archive is only meant to be unreadable without it. */
const ZIP_PASSWORD = "bench-not-a-secret";

/** Pack files into an archive with real tools (bsdtar, ar, Info-ZIP, lz4). */
function packArchive(dir, out, format, files) {
  const stage = join(dir, ".stage");
  rmSync(stage, { recursive: true, force: true });
  for (const f of files) {
    mkdirSync(dirname(join(stage, f.path)), { recursive: true });
    writeFileSync(join(stage, f.path), f.data);
    utimesSync(join(stage, f.path), 1_700_000_000, 1_700_000_000);
  }
  const tar = (flags, file) => execFileSync("tar", ["--format", "ustar", "--no-mac-metadata", ...flags, file, "legacy"], { cwd: stage });
  if (format === "xz") tar(["-cJf"], out);
  else if (format === "bz2") tar(["-cjf"], out);
  else if (format === "zst") tar(["--zstd", "-cf"], out);
  else if (format === "lz4") {
    tar(["-cf"], join(stage, "p.tar"));
    execFileSync("lz4", ["-q", "-f", join(stage, "p.tar"), out]);
  } else if (format === "enc-zip") {
    execFileSync("zip", ["-q", "-r", "-X", "-P", ZIP_PASSWORD, out, "legacy"], { cwd: stage });
  } else if (format === "deb") {
    tar(["-cJf"], join(stage, "data.tar.xz"));
    mkdirSync(join(stage, "ctl"), { recursive: true });
    writeFileSync(join(stage, "ctl", "control"), "Package: legacy-assets\nVersion: 1.0\nArchitecture: all\nDescription: legacy assets\n");
    execFileSync("tar", ["--format", "ustar", "--no-mac-metadata", "-cJf", join(stage, "control.tar.xz"), "control"], { cwd: join(stage, "ctl") });
    writeFileSync(join(stage, "debian-binary"), "2.0\n");
    for (const n of ["debian-binary", "control.tar.xz", "data.tar.xz"]) utimesSync(join(stage, n), 1_700_000_000, 1_700_000_000);
    execFileSync("ar", ["-S", "-q", "-c", out, "debian-binary", "control.tar.xz", "data.tar.xz"], { cwd: stage });
  } else throw new Error(format);
  rmSync(stage, { recursive: true, force: true });
}

const MARKER_WORDS = ["Risk", "Fraud", "Pricing", "Ranking", "Payout", "Eligibility"];

// ------------------------------------------------------------------ scenario builder
function buildScenario(dir, id, family, rng, pool) {
  const rel = join(dir, "release", "App");
  mkdirSync(rel, { recursive: true });
  const needles = [];
  const assets = [{ id: "ui", placement: "public-by-design", description: "visible UI and displayed content" }];
  const decoySecret = "corp-svc-" + rng.str(32, AN); // declared server-only secret that never ships (negative control)
  const markerWord = rng.pick(MARKER_WORDS);
  const markers = [`compute${markerWord}ScoreV${2 + rng.int(7)}`, `${markerWord.toUpperCase()}_RULES_TABLE_${rng.str(4, "ABCDEFGHJKLMNPQRSTUVWXYZ")}`];
  const declaredServer = [{ id: "server-credential", placement: "server-only", fingerprints: [{ type: "sha256", value: fingerprintOf(decoySecret) }] }];
  assets.push({ id: "server-rules", placement: "server-only", markers, description: "server-only decision rules" });
  const publicValues = [];
  const customRegexes = [CUSTOM_REGEX];

  // Real background bytes spread across the layout.
  const bg = rng.shuffle(pool).slice(0, 6).map((p) => ({ name: p.replace(/^node_modules\//, "").replace(/\//g, "__"), data: readFileSync(join(ROOT, p)) }));
  const asarFiles = [
    { path: "package.json", data: Buffer.from(JSON.stringify({ name: `app-${id}`, version: "1.0.0", main: "main.js" })) },
    { path: "main.js", data: Buffer.from('const { app, BrowserWindow } = require("electron");\napp.whenReady().then(() => new BrowserWindow().loadFile("renderer/index.html"));\n') },
    { path: "renderer/index.html", data: Buffer.from('<!doctype html><script src="app.js"></script>') },
    ...bg.slice(0, 3).map((b) => ({ path: `renderer/vendor/${b.name}`, data: b.data })),
  ];
  let appExtra = "";
  let sourcemap = "external";
  const pluginFiles = [{ path: "plugin.js", data: Buffer.from("exports.activate = () => true;\n") }, { path: `types/${bg[3].name}`, data: bg[3].data }];
  const plain = [{ path: `docs/${bg[4].name}`, data: bg[4].data }, { path: "LICENSES.txt", data: Buffer.from("Third-party notices.\n") }];
  const lockfile = readFileSync(join(ROOT, "package-lock.json"));
  plain.push({ path: "resources/package-lock.json", data: lockfile });
  let nativeNeedle = null;
  const archives = []; // { format, files } packed into updates/ by packArchive()
  let zipInAsar = null;
  let tgz = null;

  /** Place rendered text with a given wrapper; returns the virtual path for the truth file. */
  const place = (wrapper, text, kind) => {
    switch (wrapper) {
      case "W1-plain": {
        const p = kind === "pem" ? "config/signing.pem" : "config/settings.json";
        plain.push({ path: p, data: Buffer.from(text) });
        return `release/App/${p}`;
      }
      case "W2-asar":
        appExtra += text + "\n";
        return "release/App/resources/app.asar!/renderer/app.js";
      case "W3-zip":
        pluginFiles.push({ path: "lib/service.js", data: Buffer.from(text + "\n") });
        return "release/App/updates/plugin-2.1.0.zip!/lib/service.js";
      case "W4-zip-in-asar":
        zipInAsar = writeZip([{ path: "ext/background.js", data: Buffer.from(text + "\n") }, { path: `ext/${bg[5].name}`, data: bg[5].data }]);
        return "release/App/resources/app.asar!/extensions/helper.zip!/ext/background.js";
      case "W5-tgz":
        tgz = gzipSync(writeTar([{ path: "assets/config.js", data: Buffer.from(text + "\n") }, { path: `assets/${bg[5].name}`, data: bg[5].data }]));
        return "release/App/updates/assets.tar.gz!/assets/config.js";
      case "W6-utf16-binary":
        nativeNeedle = text;
        return "release/App/resources/app.asar.unpacked/native/addon.node";
      case "W7-base64":
        plain.push({ path: "config/bootstrap.json", data: Buffer.from(JSON.stringify({ bootstrap: Buffer.from(text).toString("base64") })) });
        return "release/App/config/bootstrap.json";
      case "W8-xz":
      case "W9-bz2":
      case "W10-zst":
      case "W11-deb":
      case "W13-enc-zip":
      case "W14-lz4": {
        const format = wrapper.split("-").slice(1).join("-");
        archives.push({ format, files: [{ path: "legacy/config.js", data: Buffer.from(text + "\n") }, { path: `legacy/${bg[5].name}`, data: bg[5].data }] });
        return `release/App/updates/${ARCHIVE_NAME[format]}`;
      }
      case "W12-percent":
        plain.push({ path: "config/endpoints.json", data: Buffer.from(JSON.stringify({ callback: "https://hooks.example.invalid/cb?state=" + encodeURIComponent(text) })) });
        return "release/App/config/endpoints.json";
      default:
        throw new Error(wrapper);
    }
  };
  const credential = (pool) => {
    const kind = rng.pick(Object.keys(pool));
    return { kind, value: pool[kind][0](rng), varName: pool[kind][1] };
  };
  const plant = (cred, wrapper, declared) => {
    const style = wrapper === "W1-plain" ? (cred.kind === "pem" ? "file" : "json") : wrapper === "W6-utf16-binary" ? "bare" : "js";
    const r = style === "bare" ? { text: cred.kind === "aws" ? cred.value.id + " " + cred.value.secret : cred.kind === "pem" ? cred.value : cred.value, values: cred.kind === "aws" ? [cred.value.id, cred.value.secret] : [cred.value] } : render(cred.kind, cred.value, style, cred.varName);
    const path = place(wrapper, r.text, cred.kind);
    if (declared) declaredServer.push({ id: `leaked-${cred.kind}`, placement: "server-only", fingerprints: r.values.map((v) => ({ type: "sha256", value: fingerprintOf(v) })) });
    needles.push({ kind: "secret", format: cred.kind, declared, wrapper, path, fingerprints: r.values.map((v) => fingerprintOf(v)), sha1: r.values.map(sha1) });
  };

  const k = needles.length; // eslint quiet
  void k;
  switch (family) {
    case "CLEAN":
      break;
    case "LEAK-DECLARED": {
      const wrappers = ["W1-plain", "W2-asar", "W3-zip", "W4-zip-in-asar", "W5-tgz", "W6-utf16-binary", "W7-base64", "W8-xz", "W9-bz2", "W10-zst", "W11-deb", "W12-percent"];
      const wrapper = wrappers[rng.int(wrappers.length)];
      plant(credential({ ...INSIDE, ...CUSTOM }), wrapper, true);
      break;
    }
    case "PUBLIC-DECLARED": {
      for (const name of rng.shuffle(Object.keys(PUBLIC)).slice(0, 2)) {
        const v = PUBLIC[name](rng);
        const wrapper = rng.pick(["W1-plain", "W2-asar"]);
        const path = place(wrapper, wrapper === "W1-plain" ? `{"${name}":"${v}"}` : `const ${name.toUpperCase()} = "${v}";`, name);
        assets.push({ id: `public-${name}`, placement: "public-by-design", fingerprints: [{ type: "sha256", value: fingerprintOf(v) }] });
        publicValues.push(v);
        needles.push({ kind: "public", format: name, declared: true, wrapper, path, fingerprints: [fingerprintOf(v)], sha1: [sha1(v)] });
      }
      break;
    }
    case "SERVER-IMPL": {
      const code = `const ${markers[1]} = [{ f: "velocity", gt: ${rng.int(9)} }];\nexports.${markers[0]} = (tx) => ${markers[1]}.reduce((s, r) => s + (tx[r.f] > r.gt ? 1 : 0), 0);`;
      const wrapper = rng.pick(["W2-asar", "W3-zip", "W5-tgz", "W8-xz", "W9-bz2"]);
      const path = place(wrapper, code, "impl");
      needles.push({ kind: "marker", format: "server-impl", declared: true, wrapper, path, markers });
      break;
    }
    case "PRIVATE-ARTIFACT": {
      const variant = rng.pick(["map-in-asar", "map-plain", "inline-map"]);
      const map = Buffer.from(JSON.stringify({ version: 3, file: "app.js", sources: ["../src/app.ts"], sourcesContent: ["// original source\nexport const x = 1;\n"], mappings: "AAAA;AACA" }));
      let path;
      if (variant === "map-in-asar") {
        asarFiles.push({ path: "renderer/app.js.map", data: map });
        sourcemap = "relative";
        path = "release/App/resources/app.asar!/renderer/app.js.map";
      } else if (variant === "map-plain") {
        plain.push({ path: "resources/app.js.map", data: map });
        path = "release/App/resources/app.js.map";
      } else {
        sourcemap = "inline";
        path = "release/App/resources/app.asar!/renderer/app.js";
      }
      needles.push({ kind: "private-artifact", format: variant, declared: true, wrapper: variant, path });
      break;
    }
    case "UNDECLARED-LEAK": {
      const stratum = rng.pick(Object.keys(STRATA));
      plant(credential(STRATA[stratum]), rng.pick(["W1-plain", "W2-asar", "W3-zip"]), false);
      needles[needles.length - 1].stratum = stratum;
      break;
    }
    case "UNVERIFIABLE":
      plant(credential({ ...INSIDE, ...CUSTOM }), rng.pick(["W13-enc-zip", "W14-lz4"]), true);
      break;
    case "UNVERIFIABLE-CLEAN": {
      const format = rng.pick(["enc-zip", "lz4"]);
      archives.push({ format, files: [{ path: `legacy/${bg[5].name}`, data: bg[5].data }] });
      needles.push({ kind: "clean-archive", format, declared: false, wrapper: `clean-${format}`, path: `release/App/updates/${ARCHIVE_NAME[format]}` });
      break;
    }
    case "COMPRESSED-CLEAN": {
      for (const format of rng.shuffle(["xz", "bz2", "zst", "deb"]).slice(0, 2)) {
        archives.push({ format, files: [{ path: `legacy/${bg[5].name}`, data: bg[5].data }, { path: "legacy/README.txt", data: Buffer.from("Legacy assets.\n") }] });
        needles.push({ kind: "clean-archive", format, declared: false, wrapper: `clean-${format}`, path: `release/App/updates/${ARCHIVE_NAME[format]}` });
      }
      break;
    }
    case "EXAMPLE-DOCS": {
      const t = rng.pick(DOC_EXAMPLES);
      plain.push({ path: "docs/QUICKSTART.md", data: Buffer.from(`# Quick start\n\n\`\`\`\n${t}\n\`\`\`\n`) });
      needles.push({ kind: "doc-example", format: "documented-example", declared: false, wrapper: "W1-plain", path: "release/App/docs/QUICKSTART.md" });
      break;
    }
  }

  // ---- write the release
  asarFiles.push({ path: "renderer/app.js", data: Buffer.from(appJs(rng, appExtra, sourcemap)) });
  if (zipInAsar) asarFiles.push({ path: "extensions/helper.zip", data: zipInAsar });
  const res = join(rel, "resources");
  mkdirSync(join(res, "app.asar.unpacked", "native"), { recursive: true });
  writeFileSync(join(res, "app.asar"), writeAsar(asarFiles));
  writeFileSync(join(res, "app.asar.unpacked", "native", "addon.node"), nativeSlice(rng, nativeNeedle));
  mkdirSync(join(rel, "updates"), { recursive: true });
  writeFileSync(join(rel, "updates", "plugin-2.1.0.zip"), writeZip(pluginFiles));
  if (tgz) writeFileSync(join(rel, "updates", "assets.tar.gz"), tgz);
  for (const f of plain) {
    mkdirSync(dirname(join(rel, f.path)), { recursive: true });
    writeFileSync(join(rel, f.path), f.data);
  }
  for (const a of archives) packArchive(dir, join(rel, "updates", ARCHIVE_NAME[a.format]), a.format, a.files);

  // ---- owner knowledge: manifest (Anti-REA) and equivalent tuned configs for the baselines
  const manifest = {
    schema: "anti-rea/manifest/v1",
    application: { name: `bench-${id}`, version: "1.0.0" },
    releaseClosure: { roots: ["release"], private: ["**/*.map"] },
    assets: [...assets, ...declaredServer],
  };
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  writeFileSync(join(dir, "manifest.noknowledge.json"), JSON.stringify({ ...manifest, releaseClosure: { roots: ["release"] }, assets: [assets[0]] }, null, 2));

  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const gl = [
    "# Tuned gitleaks config: the same owner knowledge Anti-REA receives in manifest.json.",
    "[extend]",
    "useDefault = true",
    "",
    "[[rules]]",
    'id = "declared-server-only-implementation"',
    'description = "Owner-declared markers of server-only code"',
    `regex = '''(?:${markers.map(esc).join("|")})'''`,
    `keywords = [${markers.map((m) => `"${m.toLowerCase()}"`).join(", ")}]`,
    "",
    "[[rules]]",
    'id = "declared-private-artifact"',
    'description = "Source maps are declared private"',
    "path = '''\\.map$'''",
    "",
    "[[rules]]",
    'id = "inline-source-map"',
    'description = "Inline source maps ship original sources"',
    "regex = '''sourceMappingURL=data:application/json[^\\s]{20,}'''",
    'keywords = ["sourcemappingurl"]',
    "",
    "[[rules]]",
    'id = "internal-service-credential"',
    'description = "Owner-known internal credential format"',
    `regex = '''${CUSTOM_REGEX}'''`,
    'keywords = ["corp-svc-"]',
  ];
  if (publicValues.length > 0)
    gl.push("", "[[allowlists]]", 'description = "Owner-declared public-by-design values"', `regexes = [${publicValues.map((v) => `'''^${esc(v)}$'''`).join(", ")}]`);
  writeFileSync(join(dir, "gitleaks.toml"), gl.join("\n") + "\n");

  const th = [
    "# Tuned trufflehog custom detectors: the same owner knowledge (no value allowlist exists in trufflehog).",
    "detectors:",
    "  - name: DeclaredServerOnlyImplementation",
    `    keywords: [${markers.map((m) => `"${m}"`).join(", ")}]`,
    "    regex:",
    `      marker: '(${markers.map(esc).join("|")})'`,
    "  - name: InternalServiceCredential",
    '    keywords: ["corp-svc-"]',
    "    regex:",
    `      key: '(${CUSTOM_REGEX})'`,
    "  - name: InlineSourceMap",
    '    keywords: ["sourceMappingURL"]',
    "    regex:",
    "      map: '(sourceMappingURL=data:application/json[^\\s]{20,})'",
    "  - name: SourceMapFile",
    '    keywords: ["\\"mappings\\""]',
    "    regex:",
    `      map: '("mappings"\\s*:\\s*"[A-Za-z0-9+/,;]+")'`,
  ];
  writeFileSync(join(dir, "trufflehog.yaml"), th.join("\n") + "\n");

  const truth = { id, family: family, truth: FAMILIES.find((f) => f.id === family).truth, needles };
  writeFileSync(join(dir, "truth.json"), JSON.stringify(truth, null, 2));
  return truth;
}

// ------------------------------------------------------------------ main
function main() {
  const args = process.argv.slice(2);
  const set = args[args.indexOf("--set") + 1];
  const out = args.indexOf("--out") === -1 ? "" : resolve(args[args.indexOf("--out") + 1]);
  if (!(set in SEEDS) || !out || args.indexOf("--out") === -1) {
    console.error("usage: corpus.mjs --set dev|eval --out <dir>");
    process.exit(1);
  }
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const seed = seedFor(set);
  const rng = new Rng(seed);
  const pool = backgroundPool();
  const index = [];
  let n = 0;
  for (const fam of FAMILIES) {
    for (let i = 0; i < K[set]; i++) {
      const id = `S${String(++n).padStart(3, "0")}`;
      const t = buildScenario(join(out, id), id, fam.id, new Rng(Math.floor(rng.r() * 2 ** 31)), pool);
      index.push({ id, family: t.family, truth: t.truth });
    }
  }
  const h = createHash("sha256").update(JSON.stringify(index)).digest("hex");
  writeFileSync(join(out, "index.json"), JSON.stringify({ set, seed, perFamily: K[set], backgroundPoolSize: pool.length, scenarios: index, indexSha256: h }, null, 2));
  console.log(`generated ${index.length} scenarios (${set}, seed 0x${seed.toString(16)}, background pool ${pool.length} real files) -> ${out}`);
}
main();
