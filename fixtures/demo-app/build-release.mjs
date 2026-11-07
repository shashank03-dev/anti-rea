#!/usr/bin/env node
// Builds the SYNTHETIC demo release into fixtures/demo-app/release/.
//
//   node fixtures/demo-app/build-release.mjs vulnerable   # positive controls planted
//   node fixtures/demo-app/build-release.mjs fixed        # remediated build
//
// Requires `npm run build` first (uses the container writers from build/src).
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeAsar, writeZip } from "../../build/src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const variant = process.argv[2] ?? "vulnerable";
if (!["vulnerable", "fixed"].includes(variant)) {
  console.error("usage: build-release.mjs vulnerable|fixed");
  process.exit(1);
}
const vulnerable = variant === "vulnerable";
const src = (p) => readFileSync(join(here, p));
const text = (p) => readFileSync(join(here, p), "utf8");

// Public-by-design decoy: fake browser key value (declared in the manifest).
const MAPS_BROWSER_KEY = "AIzaSyD-SYNTHETIC-public-browser-key-01";

const signingKeyPem = text("server-secrets/synthetic-signing-key.pem");
const escapedPem = signingKeyPem.trimEnd().replace(/\n/g, "\\n");

const appJs = text("app-src/renderer/app.template.js")
  .replace("__MAPS_BROWSER_KEY__", MAPS_BROWSER_KEY)
  .replace(
    "__SOURCEMAP_COMMENT__",
    vulnerable
      ? "//# sourceMappingURL=app.js.map"
      : "//# sourceMappingURL=https://symbols.internal.acme-ledger.example/desktop/4.2.0/app.js.map",
  );

const appMap = JSON.stringify({
  version: 3,
  file: "app.js",
  sources: ["../../src/renderer/ranking.ts", "../../src/renderer/app.tsx"],
  sourcesContent: ["// original TypeScript sources would be here", "// ..."],
  mappings: "AAAA",
});

const licensing = vulnerable
  ? text("app-src/licensing/license-client.vulnerable.js").replace("__SIGNING_KEY_ESCAPED__", escapedPem)
  : text("app-src/licensing/license-client.fixed.js");

const asarFiles = [
  { path: "package.json", data: src("app-src/package.json") },
  { path: "main.js", data: src("app-src/main.js") },
  { path: "preload.js", data: src("app-src/preload.js") },
  { path: "renderer/index.html", data: src("app-src/renderer/index.html") },
  { path: "renderer/app.js", data: Buffer.from(appJs) },
  { path: "licensing/license-client.js", data: Buffer.from(licensing) },
];
if (vulnerable) {
  asarFiles.push({ path: "renderer/app.js.map", data: Buffer.from(appMap) });
  // Undeclared staging token left in a config file: should surface as an unconfirmed lead.
  asarFiles.push({
    path: "config/dev-session.json",
    data: Buffer.from(
      JSON.stringify(
        { env: "staging", token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJxYS1ib3QiLCJlbnYiOiJzdGFnaW5nIn0.U1lOVEhFVElDLXNpZ25hdHVyZQ" },
        null,
        2,
      ),
    ),
  });
}

const plugin = writeZip([
  { path: "manifest.json", data: Buffer.from(JSON.stringify({ name: "risk-plugin", version: "3.1.0" })) },
  { path: "risk-plugin.js", data: src(`plugin-src/risk-plugin.${variant}.js`) },
]);

const out = join(here, "release");
rmSync(out, { recursive: true, force: true });
const app = join(out, "AcmeLedger");
mkdirSync(join(app, "resources", "app.asar.unpacked", "native"), { recursive: true });
mkdirSync(join(app, "updates"), { recursive: true });
writeFileSync(join(app, "resources", "app.asar"), writeAsar(asarFiles));
writeFileSync(join(app, "resources", "app.asar.unpacked", "native", "fastmath.node"), Buffer.from("\x7fELF synthetic native addon placeholder\n", "latin1"));
writeFileSync(join(app, "updates", "risk-plugin-3.1.0.zip"), plugin);
writeFileSync(join(app, "LICENSES.txt"), "Third-party licenses (synthetic demo).\n");
console.log(`built ${variant} release -> ${out}`);
