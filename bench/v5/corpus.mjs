#!/usr/bin/env node
// Anti-REA benchmark corpus generator, v5 (pre-registered in bench/PREREGISTRATION.md).
// The v1–v4 generators, as they ran, are kept in bench/v1/ … bench/v4/.
//
//   node bench/corpus.mjs --set dev|eval --out <dir>
//
// The eval seed is NOT chosen by hand: it is the first 32 bits of the frozen
// tool+harness hash (bench/freeze.mjs), so it is fixed by the code being evaluated.
//
// Each scenario is an Electron-style release built from REAL third-party bytes
// (v5: the Zen browser's toolkit JavaScript from Contents/Resources/omni.ja, bash-completion
// scripts, slices of Homebrew's libx265 Mach-O) with zero or more planted "needles". Every random choice is seeded; EC private keys are derived
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
const SEEDS = { dev: 0x5eed0005, eval: null /* derived from the frozen hash at generation time */ };
const seedFor = (set) => (set === "eval" ? parseInt(frozenHash().slice(0, 8), 16) : SEEDS[set]);
const K = { dev: 4, eval: 20 };
/** v4: UNDECLARED-LEAK is a forced factorial (stratum × render style), with this many scenarios per cell. */
const CELL_REPS = { dev: 1, eval: 4 };

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

// Each credential kind: { gen, env, cfg, ctor, factory }:
//   env      provider-named constant / env var (env style),
//   cfg      the SDK option name in a JSON config (config style),
//   ctor     the SDK's client class (ctor style: `new <ctor>("…")`),
//   factory  the SDK's factory function (bare style: `<factory>("…")`).
// Names follow each provider's public SDK conventions as the author recalls them; they are
// not verified per provider, and they are listed in the pre-registration before any eval run.
const cred = (gen, env, cfg, ctor, factory) => ({ gen, env, cfg, ctor, factory });
/** Stratum INSIDE: formats Anti-REA v0.1 already detected. */
const INSIDE = {
  pem: cred((r) => ecPem(r, r.int(2) === 1), "SIGNING_KEY", "signingKey", "Signer", "createSigner"),
  github: cred((r) => "ghp_" + r.str(36, AN), "GITHUB_TOKEN", "auth", "Octokit", "octokit"),
  slack: cred((r) => `xoxb-${r.str(12, "0123456789")}-${r.str(13, "0123456789")}-${r.str(24, AN)}`, "SLACK_BOT_TOKEN", "token", "WebClient", "slack"),
  stripe: cred((r) => "sk_live_" + r.str(24, AN), "STRIPE_SECRET_KEY", "apiKey", "Stripe", "Stripe"),
  aws: cred((r) => ({ id: "AKIA" + r.str(16, B32), secret: r.str(40, B64) }), "AWS", "credentials", "S3Client", "s3"),
};
/** Stratum NAMED: formats with named detectors since v0.2. Not held out. */
const NAMED = {
  gitlab: cred((r) => "glpat-" + r.str(20, URLSAFE), "GITLAB_TOKEN", "token", "Gitlab", "gitlab"),
  npm: cred((r) => "npm_" + r.str(36, AN), "NPM_TOKEN", "token", "RegistryClient", "npmFetch"),
  sendgrid: cred((r) => `SG.${r.str(22, URLSAFE)}.${r.str(43, URLSAFE)}`, "SENDGRID_API_KEY", "apiKey", "MailService", "sgMail"),
  huggingface: cred((r) => "hf_" + r.str(34, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"), "HF_TOKEN", "accessToken", "HfInference", "hfInference"),
  shopify: cred((r) => "shpat_" + r.str(32, HEX), "SHOPIFY_ACCESS_TOKEN", "accessToken", "Shopify", "shopifyApi"),
  digitalocean: cred((r) => "dop_v1_" + r.str(64, HEX), "DIGITALOCEAN_TOKEN", "token", "DigitalOcean", "createApiClient"),
  anthropic: cred((r) => "sk-ant-api03-" + r.str(93, URLSAFE) + "AA", "ANTHROPIC_API_KEY", "apiKey", "Anthropic", "anthropic"),
  openai: cred((r) => `sk-proj-${r.str(74, URLSAFE)}T3BlbkFJ${r.str(74, URLSAFE)}`, "OPENAI_API_KEY", "apiKey", "OpenAI", "createOpenAI"),
};
const LOWER_AN = "abcdefghijklmnopqrstuvwxyz0123456789";
/**
 * DEV held-out pools (v5): v4's eval held-out formats, already exposed by the v4 run. Used only by the
 * dev set, which validates the harness.
 */
const DEV_PREFIXED = {
  langsmith: cred((r) => `lsv2_sk_${r.str(32, HEX)}_${r.str(10, HEX)}`, "LANGSMITH_API_KEY", "apiKey", "Client", "createClient"),
  openrouter: cred((r) => "sk-or-v1-" + r.str(64, HEX), "OPENROUTER_API_KEY", "apiKey", "OpenRouter", "createOpenRouter"),
  cerebras: cred((r) => "csk-" + r.str(48, LOWER_AN), "CEREBRAS_API_KEY", "apiKey", "Cerebras", "cerebras"),
  firecrawl: cred((r) => "fc-" + r.str(32, HEX), "FIRECRAWL_API_KEY", "apiKey", "FirecrawlApp", "firecrawl"),
  jina: cred((r) => "jina_" + r.str(60, AN), "JINA_API_KEY", "apiKey", "JinaClient", "jina"),
  brevo: cred((r) => `xkeysib-${r.str(64, HEX)}-${r.str(16, AN)}`, "BREVO_API_KEY", "apiKey", "TransactionalEmailsApi", "brevo"),
  render: cred((r) => "rnd_" + r.str(32, AN), "RENDER_API_KEY", "apiKey", "RenderApi", "render"),
  resend: cred((r) => `re_${r.str(8, AN)}_${r.str(24, AN)}`, "RESEND_API_KEY", "apiKey", "Resend", "resend"),
};
const DEV_UNPREFIXED = {
  datadog: cred((r) => r.str(32, HEX), "DD_API_KEY", "apiKey", "ApiClient", "datadogClient"),
  assemblyai: cred((r) => r.str(32, HEX), "ASSEMBLYAI_API_KEY", "apiKey", "AssemblyAI", "assemblyai"),
  wandb: cred((r) => r.str(40, HEX), "WANDB_API_KEY", "key", "Api", "wandbLogin"),
  exa: cred((r) => `${r.str(8, HEX)}-${r.str(4, HEX)}-4${r.str(3, HEX)}-a${r.str(3, HEX)}-${r.str(12, HEX)}`, "EXA_API_KEY", "apiKey", "Exa", "exa"),
  ably: cred((r) => `${r.str(6, URLSAFE)}.${r.str(6, URLSAFE)}:${r.str(43, URLSAFE)}`, "ABLY_API_KEY", "key", "Ably.Realtime", "ably"),
  upstash: cred((r) => "A" + r.str(3, "XYZ") + r.str(56, AN) + "=", "UPSTASH_REDIS_REST_TOKEN", "token", "Redis", "upstash"),
  mux: cred((r) => r.str(75, B64), "MUX_TOKEN_SECRET", "tokenSecret", "Mux", "mux"),
  mailjet: cred((r) => r.str(32, HEX), "MJ_APIKEY_PRIVATE", "apiSecret", "Mailjet.Client", "mailjetConnect"),
};
/**
 * EVAL held-out pools (v5): formats used in no earlier benchmark and in no detector development or
 * calibration. Shapes follow each provider's documented key format as the author recalls it;
 * every value is synthetic. Klaviyo's PRIVATE keys start `pk_`, a prefix most issuers use for
 * PUBLIC keys: a deliberate counter-example to Anti-REA's public-prefix rule.
 */
const EVAL_PREFIXED = {
  deepseek: cred((r) => "sk-" + r.str(32, HEX), "DEEPSEEK_API_KEY", "apiKey", "DeepSeek", "createDeepSeek"),
  langfuse: cred((r) => `sk-lf-${r.str(8, HEX)}-${r.str(4, HEX)}-4${r.str(3, HEX)}-8${r.str(3, HEX)}-${r.str(12, HEX)}`, "LANGFUSE_SECRET_KEY", "secretKey", "Langfuse", "langfuse"),
  anyscale: cred((r) => "esecret_" + r.str(26, LOWER_AN), "ANYSCALE_API_KEY", "apiKey", "Anyscale", "anyscale"),
  fireworks: cred((r) => "fw_" + r.str(24, AN), "FIREWORKS_API_KEY", "apiKey", "Fireworks", "createFireworks"),
  together: cred((r) => "tgp_v1_" + r.str(43, URLSAFE), "TOGETHER_API_KEY", "apiKey", "Together", "createTogetherAI"),
  notion: cred((r) => "ntn_" + r.str(11, "0123456789") + r.str(35, AN), "NOTION_TOKEN", "auth", "Client", "notion"),
  airtable: cred((r) => `pat${r.str(14, AN)}.${r.str(64, HEX)}`, "AIRTABLE_PAT", "apiKey", "Airtable", "airtable"),
  klaviyo: cred((r) => "pk_" + r.str(34, HEX), "KLAVIYO_PRIVATE_API_KEY", "apiKey", "ApiKeySession", "klaviyo"),
};
const EVAL_UNPREFIXED = {
  fal: cred((r) => `${r.str(8, HEX)}-${r.str(4, HEX)}-4${r.str(3, HEX)}-9${r.str(3, HEX)}-${r.str(12, HEX)}:${r.str(32, HEX)}`, "FAL_KEY", "credentials", "FalClient", "createFalClient"),
  railway: cred((r) => `${r.str(8, HEX)}-${r.str(4, HEX)}-4${r.str(3, HEX)}-b${r.str(3, HEX)}-${r.str(12, HEX)}`, "RAILWAY_TOKEN", "token", "RailwayClient", "railway"),
  algolia: cred((r) => r.str(32, HEX), "ALGOLIA_ADMIN_API_KEY", "apiKey", "SearchClient", "algoliasearch"),
  pusher: cred((r) => r.str(20, HEX), "PUSHER_APP_SECRET", "secret", "Pusher", "pusher"),
  cloudinary: cred((r) => r.str(27, URLSAFE), "CLOUDINARY_API_SECRET", "api_secret", "Cloudinary", "cloudinary"),
  zendesk: cred((r) => r.str(40, AN), "ZENDESK_API_TOKEN", "token", "ZendeskClient", "createZendeskClient"),
  mixpanel: cred((r) => r.str(32, HEX), "MIXPANEL_API_SECRET", "secret", "Mixpanel", "mixpanelInit"),
  bitly: cred((r) => r.str(40, HEX), "BITLY_ACCESS_TOKEN", "accessToken", "BitlyClient", "bitly"),
};
const strataFor = (set) => ({
  INSIDE,
  NAMED,
  "HELDOUT-PREFIXED": set === "eval" ? EVAL_PREFIXED : DEV_PREFIXED,
  "HELDOUT-UNPREFIXED": set === "eval" ? EVAL_UNPREFIXED : DEV_UNPREFIXED,
});
/**
 * v4 render styles for undeclared credentials, each forced (every stratum × style cell is filled):
 *  - env:    a provider-named constant / env var (`DD_API_KEY = "…"`),
 *  - config: the SDK option in a JSON config (`{"provider": "…", "<cfg>": "…"}`),
 *  - ctor:   passed to the SDK client class (`new <ctor>("…")`),
 *  - method: passed to a method; the method rotates over METHODS, half of them credential-named,
 *  - bare:   passed to the SDK factory function (`<factory>("…")`): no credential signal at all.
 */
const STYLES = ["env", "config", "ctor", "method", "bare"];
/**
 * v5: method-style calls are drawn (seeded) from 12 credential-passing calls from real SDK usage. v4
 * rotated 4 fixed methods, and v0.5's configuration-verb list was written after seeing v4's misses,
 * so a fixed short list would test the rules against their own design.
 */
const METHODS = [
  ["analytics", "load"], ["Bugsnag", "start"], ["client", "login"], ["api", "setKey"],
  ["Purchases", "configure"], ["posthog", "init"], ["amplitude", "init"], ["sgMail", "setApiKey"],
  ["twitter", "setBearerToken"], ["octokit", "auth"], ["sdk", "useKey"], ["crisp", "authenticate"],
];
/** An internal credential format no public scanner knows; owners know its shape. */
const CUSTOM = { corpsvc: cred((r) => "corp-svc-" + r.str(32, AN), "CORP_SERVICE_TOKEN", "token", "CorpServiceClient", "corpService") };
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

/** How a credential value appears in source. Returns {text, values[]}: values are what must be fingerprinted. */
function render(c, style, methodIdx = 0) {
  const { kind, value: v } = c;
  if (kind === "aws") {
    const t = style === "json" ? `{"aws_access_key_id":"${v.id}","aws_secret_access_key":"${v.secret}"}` : `const AWS_KEY_ID = "${v.id}";\nconst AWS_SECRET = "${v.secret}";`;
    return { text: t, values: [v.id, v.secret] };
  }
  if (kind === "pem") {
    const esc = v.trimEnd().replace(/\n/g, "\\n");
    const t = style === "file" ? v : style === "json" ? `{"signingKey":"${esc}"}` : `const SIGNING_KEY = "${esc}";`;
    return { text: t, values: [v] };
  }
  const call = (expr) => ({ text: `const client = ${expr};`, values: [v] });
  if (style === "config") return { text: JSON.stringify({ provider: kind.toLowerCase(), [c.cfg]: v }), values: [v] };
  if (style === "ctor") return call(`new ${c.ctor}("${v}")`);
  if (style === "bare") return call(`${c.factory}("${v}")`);
  if (style === "method") {
    const [obj, m] = METHODS[methodIdx % METHODS.length];
    return { text: `${obj}.${m}("${v}");`, values: [v] };
  }
  const t = style === "json" ? `{"${c.env.toLowerCase()}":"${v}"}` : style === "file" ? `${c.env}=${v}\n` : `const ${c.env} = "${v}";`;
  return { text: t, values: [v] };
}

// ------------------------------------------------------------------ background (real third-party bytes)
// v5 background: real third-party bytes never scanned during v0.5 development or calibration and never
// used in v1–v4: the Zen browser's toolkit JavaScript/JSON (Contents/Resources/omni.ja, not the
// browser/omni.ja used by v4) and bash-completion scripts, plus slices of Homebrew's libx265 as the
// native addon. Paths are machine-specific; index.json records the sha256 of every pool file.
const ZEN_OMNI = "/Applications/Zen.app/Contents/Resources/omni.ja";
const ZEN_CACHE = join(ROOT, "bench", ".background", "v5-zen-toolkit-omni");
const BASH_COMPLETION = "/opt/homebrew/Cellar/bash-completion@2/2.18.0/share/bash-completion/completions";
function backgroundPool() {
  if (!existsSync(join(ZEN_CACHE, ".complete"))) {
    rmSync(ZEN_CACHE, { recursive: true, force: true });
    mkdirSync(ZEN_CACHE, { recursive: true });
    // omni.ja is an "optimized" zip; Info-ZIP extracts it but may exit non-zero with a warning about its layout.
    try { execFileSync("unzip", ["-qq", "-o", ZEN_OMNI, "-d", ZEN_CACHE], { stdio: "ignore" }); } catch {}
    writeFileSync(join(ZEN_CACHE, ".complete"), createHash("sha256").update(readFileSync(ZEN_OMNI)).digest("hex"));
  }
  const out = [];
  const walk = (d, re) => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const st = statSync(p);
      if (st.isDirectory()) walk(p, re);
      else if (re.test(n) && st.size > 2048 && st.size < 1_500_000) out.push(p);
    }
  };
  walk(ZEN_CACHE, /\.(js|mjs|json)$/);
  walk(BASH_COMPLETION, /^[^.]/);
  return out;
}
const LIBNODE = "/opt/homebrew/Cellar/x265/4.3/lib/libx265.217.dylib";

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

const ARCHIVE_NAME = { xz: "legacy.tar.xz", bz2: "legacy.tar.bz2", zst: "legacy.tar.zst", deb: "legacy-assets_1.0_all.deb", "enc-zip": "legacy-encrypted.zip", lz4: "legacy.tar.lz4", "zip-bzip2": "legacy-assets.zip", dmg: "LegacyAssets.dmg", "enc-dmg": "LegacyAssets-encrypted.dmg" };
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
  } else if (format === "zip-bzip2") {
    // macOS Info-ZIP is built without bzip2; Python's zipfile writes method 12.
    const py = "import os, sys, zipfile\nz = zipfile.ZipFile(sys.argv[1], 'w', compression=zipfile.ZIP_BZIP2)\nfor d, _, fs in sorted(os.walk('legacy')):\n    for f in sorted(fs): z.write(os.path.join(d, f))\nz.close()";
    execFileSync("python3", ["-I", "-c", py, out], { cwd: stage });
  } else if (format === "dmg") {
    execFileSync("hdiutil", ["create", "-quiet", "-format", "UDZO", "-fs", "HFS+", "-srcfolder", join(stage, "legacy"), "-volname", "LegacyAssets", "-ov", out]);
  } else if (format === "enc-dmg") {
    // AES-256 encrypted image: unreadable without the passphrase, by any tool.
    execFileSync("hdiutil", ["create", "-quiet", "-format", "UDZO", "-fs", "HFS+", "-encryption", "AES-256", "-stdinpass", "-srcfolder", join(stage, "legacy"), "-volname", "LegacyAssets", "-ov", out], { input: ZIP_PASSWORD });
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
function buildScenario(dir, id, family, rng, pool, cell = null) {
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
  const bg = rng.shuffle(pool).slice(0, 7).map((p) => ({ name: p.replace(/^.*\/(v5-zen-toolkit-omni|share\/bash-completion\/completions)\//, "").replace(/\//g, "__"), data: readFileSync(p) }));
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
  plain.push({ path: `resources/${bg[6].name}`, data: bg[6].data });
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
      case "W14-lz4":
      case "W15-zip-bzip2":
      case "W16-dmg":
      case "W17-enc-dmg": {
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
  const credential = (pool, kind = rng.pick(Object.keys(pool))) => ({ kind, value: pool[kind].gen(rng), ...pool[kind] });
  const plant = (cred, wrapper, declared, renderStyle, methodIdx) => {
    const style = renderStyle ?? (wrapper === "W1-plain" ? (cred.kind === "pem" ? "file" : "json") : wrapper === "W6-utf16-binary" ? "raw" : "js");
    const r = style === "raw" ? { text: cred.kind === "aws" ? cred.value.id + " " + cred.value.secret : cred.value, values: cred.kind === "aws" ? [cred.value.id, cred.value.secret] : [cred.value] } : render(cred, style, methodIdx);
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
      const wrappers = ["W1-plain", "W2-asar", "W3-zip", "W4-zip-in-asar", "W5-tgz", "W6-utf16-binary", "W7-base64", "W8-xz", "W9-bz2", "W10-zst", "W11-deb", "W12-percent", "W14-lz4", "W15-zip-bzip2", "W16-dmg"];
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
      // v4: the cell (stratum, style, provider, method rotation) is assigned by main(), not drawn.
      const { stratum, style, kind, methodIdx, pool: cellPool } = cell;
      const wrapper = rng.pick(["W1-plain", "W2-asar", "W3-zip"]);
      // env style keeps each wrapper's own source form (JSON / JS const / env file); the other styles are explicit.
      plant(credential(cellPool, kind), wrapper, false, style === "env" ? undefined : style, methodIdx);
      Object.assign(needles[needles.length - 1], { stratum, style, ...(style === "method" ? { method: METHODS[methodIdx % METHODS.length][1] } : {}) });
      break;
    }
    case "UNVERIFIABLE":
      plant(credential({ ...INSIDE, ...CUSTOM }), rng.pick(["W13-enc-zip", "W17-enc-dmg"]), true);
      break;
    case "UNVERIFIABLE-CLEAN": {
      const format = rng.pick(["enc-zip", "enc-dmg"]);
      archives.push({ format, files: [{ path: `legacy/${bg[5].name}`, data: bg[5].data }] });
      needles.push({ kind: "clean-archive", format, declared: false, wrapper: `clean-${format}`, path: `release/App/updates/${ARCHIVE_NAME[format]}` });
      break;
    }
    case "COMPRESSED-CLEAN": {
      for (const format of rng.shuffle(["xz", "bz2", "zst", "deb", "lz4", "zip-bzip2", "dmg"]).slice(0, 2)) {
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
    // Amendment A1 (v3): anchored to a real comment line, as Anti-REA's own rule is; the unanchored form
    // flagged bundler code that builds such comments as strings (a false positive of the author's config).
    "regex = '''(?m)^[ \\t]*//[#@][ \\t]*sourceMappingURL=data:application/json\\S{20,}'''",
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
    "      map: '(?m)^[ \\t]*//[#@][ \\t]*(sourceMappingURL=data:application/json\\S{20,})'",
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
  const strata = strataFor(set);
  for (const fam of FAMILIES) {
    // UNDECLARED-LEAK: every stratum × style cell gets CELL_REPS scenarios; providers rotate within a
    // stratum (in table order, from a seeded offset) so each held-out format appears about equally often.
    const cells = [];
    if (fam.id === "UNDECLARED-LEAK") {
      for (const stratum of Object.keys(strata)) {
        const kinds = Object.keys(strata[stratum]);
        let next = rng.int(kinds.length);
        for (const style of STYLES)
          for (let i = 0; i < CELL_REPS[set]; i++) cells.push({ stratum, style, kind: kinds[next++ % kinds.length], methodIdx: style === "method" ? rng.int(METHODS.length) : 0, pool: strata[stratum] });
      }
    }
    const count = fam.id === "UNDECLARED-LEAK" ? cells.length : K[set];
    for (let i = 0; i < count; i++) {
      const id = `S${String(++n).padStart(3, "0")}`;
      const t = buildScenario(join(out, id), id, fam.id, new Rng(Math.floor(rng.r() * 2 ** 31)), pool, cells[i] ?? null);
      index.push({ id, family: t.family, truth: t.truth });
    }
  }
  const h = createHash("sha256").update(JSON.stringify(index)).digest("hex");
  const poolHashes = pool.map((p) => ({ path: p, sha256: createHash("sha256").update(readFileSync(p)).digest("hex") }));
  const nativeSha256 = createHash("sha256").update(readFileSync(LIBNODE)).digest("hex");
  const omniSha256 = readFileSync(join(ZEN_CACHE, ".complete"), "utf8");
  writeFileSync(join(out, "index.json"), JSON.stringify({ set, seed, perFamily: K[set], undeclaredCellReps: CELL_REPS[set], backgroundPoolSize: pool.length, backgroundPool: poolHashes, nativeSource: { path: LIBNODE, sha256: nativeSha256 }, zenOmniJa: { path: ZEN_OMNI, sha256: omniSha256 }, scenarios: index, indexSha256: h }, null, 2));
  console.log(`generated ${index.length} scenarios (${set}, seed 0x${seed.toString(16)}, background pool ${pool.length} real files) -> ${out}`);
}
main();
