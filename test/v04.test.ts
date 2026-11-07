/**
 * v0.4 changes (see docs/research/V04-CHANGES.md):
 * - CONSTANT_CASE `*_KEY` names and more credential nouns (write_key, sdk_key, admin_key, credentials);
 * - credentials passed to credential-named functions and API client constructors (v3's untested "call" blind spot);
 * - hex bodies behind a strong secret marker (`sk_<hex>`, `sk-or-v1-<hex>`);
 * - false-lead guards found on validation sets C and D.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { assure } from "../src/engine/evaluate.js";
import { generatedValue, runDetectors } from "../src/lanes/detectors.js";
import { manifestFor, policyOf, put, tmp } from "./helpers.js";

const V = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY";
const leads = (s: string) => runDetectors(s).map((h) => `${h.detector}:${h.value}`);

test("CONSTANT_CASE *_KEY names and the added nouns are keyed leads", () => {
  for (const src of [
    `const SEGMENT_WRITE_KEY = "${V}";`,
    `DD_APP_KEY=${V}\n`,
    `ALGOLIA_ADMIN_KEY: "${V}"`,
    `{"writeKey":"${V}"}`,
    `{"sdkKey":"${V}"}`,
    `{"credentials":"${V}"}`,
  ])
    assert.equal(runDetectors(src).filter((h) => h.kind === "keyed" && h.value === V).length, 1, src);
  // camelCase *Key is not generic (cacheKey, storageKey); words never pass generatedValue.
  assert.deepEqual(leads(`const cacheKey = "${V}";`), []);
  assert.deepEqual(leads('const STORAGE_KEY = "user-preferences-v2-settings";'), []);
});

test("credentials passed to credential-named functions and client constructors are leads", () => {
  const cases: [string, string][] = [
    [`sgMail.setApiKey("${V}");`, "credential-call-argument"],
    [`client.setAccessToken('${V}')`, "credential-call-argument"],
    [`api.withToken(\`${V}\`)`, "credential-call-argument"],
    [`const c = new postmark.ServerClient("0f8fad5b-d9cb-469f-a165-70867728950e");`, "client-constructor-argument"],
    [`const c = new MistralClient("${V}");`, "client-constructor-argument"],
    [`const c = new FooApi("${V}")`, "client-constructor-argument"],
    [`const c = new BarSDK("${V}")`, "client-constructor-argument"],
    [`const c = new Client("${V}")`, "client-constructor-argument"], // langsmith, pg, discord.js style
  ];
  for (const [src, id] of cases) assert.deepEqual(runDetectors(src).map((h) => h.detector), [id], src);
});

test("reading and validating calls are not leads", () => {
  // v0.4 also asserted that bare calls (`Stripe("…")`, `connect("…")`) and unsuffixed constructors were
  // not leads; v0.5 detects them by design (test/v05.test.ts).
  for (const src of [
    `localStorage.getToken("${V}")`, // getters/validators read, they do not configure
    `verifyToken("${V}")`,
    `client.setApiKey(process.env.API_KEY)`,
    'client.setToken("not-a-generated-value-at-all")',
  ])
    assert.deepEqual(leads(src), [], src);
});

test("hex bodies behind a strong secret marker are structural leads; digests still are not", () => {
  const hex48 = "3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e3f9a1c7e5b2d8f4a";
  const hex64 = hex48 + "6c0e9b1d7f3a5c2e";
  assert.deepEqual(leads(`x = "sk_${hex48}";`), [`prefixed-secret-token:sk_${hex48}`]);
  assert.deepEqual(leads(`x = "sk-or-v1-${hex64}";`), [`prefixed-secret-token:sk-or-v1-${hex64}`]);
  assert.deepEqual(leads(`diff-${hex64}`), []); // unmarked prefix: a digest (calibration set A)
  assert.deepEqual(leads(`err33_${hex48}`), []);
  assert.deepEqual(leads(`build_${hex64}`), []);
});

test("false-lead guards from validation sets: public-marked values, snake_case symbols, repeated patterns, published dev keys", () => {
  assert.deepEqual(leads('{sdkKey:"client-9tXkOSkQo8QzXLl8WPknmesgLodGqAAS"}'), []); // Statsig client key (public by name)
  assert.deepEqual(leads("\x00\x01cipher_list_from_ssl_ctx_QUICv1Method_tls_with_key\x00"), []); // BoringSSL-style symbol
  assert.deepEqual(leads('udp6PWD="AAAAAaaaAaaaAaaaAaaaAaaaAaaaAaaa"'), []);
  assert.equal(generatedValue("AAAAAaaaAaaaAaaaAaaaAaaaAaaaAaaa"), false);
  assert.equal(generatedValue("UDPSrcPortDstAddrHostSpanTimeLinkFlagMaskNodeItemData8"), false); // CamelCase identifier
  assert.equal(generatedValue(V), true);
  const dev = "sb_secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"; // Supabase CLI local-dev default (documented)
  const dir = tmp();
  put(dir, "rel/cli.js", `const LOCAL = "${dev}";\n`);
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [{ id: "rules", placement: "server-only" as const, markers: ["computeRiskScoreV9"] }] });
  assert.equal(assure({ manifest: m, policy: policyOf() }).decision, "pass");
});

test("keyed leads in test fixtures warn instead of blocking; elsewhere they block", () => {
  const hex = "7d7d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5";
  const assets = [{ id: "rules", placement: "server-only" as const, markers: ["computeRiskScoreV9"] }];
  const run = (path: string) => {
    const dir = tmp();
    put(dir, `rel/${path}`, `{"PrivateKey": "${hex}"}\n`);
    return assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets }), policy: policyOf() });
  };
  for (const p of ["crypto/ecdh/ecdh_test.go", "vendor/pkg/testdata/vectors.json", "lib/__tests__/keys.json", "src/keys.spec.ts"]) {
    const rep = run(p);
    assert.equal(rep.decision, "pass", p);
    assert.equal(rep.gates.find((g) => g.gate === "lowConfidenceCredentialLead")!.warnings.length, 1, p);
  }
  for (const p of ["config/settings.json", "lib/contest.js", "attestation/keys.json"]) assert.equal(run(p).decision, "block", p);
});

test("a credential passed to a client constructor blocks by default and passes once declared", async () => {
  const dir = tmp();
  put(dir, "rel/app.js", `const c = new CohereClient("${V}");\n`);
  const assets = [{ id: "rules", placement: "server-only" as const, markers: ["computeRiskScoreV9"] }];
  const rep = assure({ manifest: manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets }), policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.equal(rep.gates.find((g) => g.gate === "keyedCredentialLead")!.blocking.length, 1);
  const { fp } = await import("./helpers.js");
  const declared = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [...assets, { id: "co", placement: "public-by-design" as const, fingerprints: [fp(V)] }] });
  assert.equal(assure({ manifest: declared, policy: policyOf() }).decision, "pass");
});
