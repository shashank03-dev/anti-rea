/**
 * v0.3 changes (see docs/research/V03-CHANGES.md): the keyed-credential
 * detector for unprefixed credentials, its false-positive guards from
 * calibration, and removal of the noisy warn-only rules.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { assure } from "../src/engine/evaluate.js";
import { generatedValue, runDetectors } from "../src/lanes/detectors.js";
import { manifestFor, policyOf, put, tmp } from "./helpers.js";

const keyed = (s: string) => runDetectors(s).filter((h) => h.kind === "keyed").map((h) => h.value);

test("unprefixed credentials assigned to credential-named keys are keyed leads", () => {
  const cases: [string, string][] = [
    ['const TWILIO_AUTH_TOKEN = "0f3c9a7e21b84d6fa5c39e0d7b12a8c4";', "0f3c9a7e21b84d6fa5c39e0d7b12a8c4"],
    ['{"cloudflare_api_token":"Xk2-pQ9_wL4mZ7rT1vB8nC3hJ6sD0fG5aE2yU9iO"}', "Xk2-pQ9_wL4mZ7rT1vB8nC3hJ6sD0fG5aE2yU9iO"],
    ["MAILCHIMP_API_KEY=3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e-us14\n", "3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c2e-us14"],
    ['heroku: { apiKey: "0f8fad5b-d9cb-469f-a165-70867728950e" }', "0f8fad5b-d9cb-469f-a165-70867728950e"],
    ["clientSecret => 'aB3dE5fG7hJ9kL1mN3pQ5rS7'", "aB3dE5fG7hJ9kL1mN3pQ5rS7"],
    ['AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCY9a8Kd2LmQz"', "wJalrXUtnFEMI/K7MDENG/bPxRfiCY9a8Kd2LmQz"],
  ];
  for (const [src, v] of cases) assert.deepEqual(keyed(src), [v], src);
});

test("keyed detector ignores the shapes calibration found under credential-named keys", () => {
  for (const src of [
    '{token:"markup.bold.markdown",fontStyle:"bold"}', // editor theme scopes (hundreds in Postman/ChatGPT)
    '{token:"a{9,9}|aa|aaaaaaaa"}',
    'TPP_BROWSER_AUTH_PROVIDER_ONEPASSWORD="BROWSER_AUTH_PROVIDER_ONEPASSWORD_ENABLED"', // enum names
    "password: 'bm90IG15IHJlYWwgcGFzc3dvcmQ='", // base64 of "not my real password" (npm docs)
    'apiKey: "YOUR_API_KEY_HERE_123456"',
    'token = "xxxxxxxxxxxxxxxxxxxxxxxx"',
    'tokenizer = "abcdefgh12345678ABCD"', // the noun must end the key
    'password = "${process.env.DB_PASSWORD}"',
    'secret: "createSourceFileFromScratch"',
  ])
    assert.deepEqual(keyed(src), [], src);
  assert.equal(generatedValue("1234567890abcdef1234567890abcdef"), true);
  assert.equal(generatedValue("ffffffffffffffffffffffffffffffff"), false);
});

test("the v0.2 warn-only noise sources are gone: credential-named words and unmarked prefixes", () => {
  assert.deepEqual(runDetectors('{token:"markup.heading.markdown"} client-9tXkOSkQo8QzXLl8WPknmesgLodGqAAS app_EMoamEEZ73f0CkXaXp7hrann'), []);
});

test("a keyed lead blocks by default, warns when the gate is relaxed, and passes once declared", async () => {
  const value = "0f3c9a7e21b84d6fa5c39e0d7b12a8c4";
  const dir = tmp();
  put(dir, "rel/config.js", `const DATADOG_API_KEY = "${value}";\n`);
  const assets = [{ id: "rules", placement: "server-only" as const, markers: ["computeRiskScoreV9"] }];
  const m = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets });
  const rep = assure({ manifest: m, policy: policyOf() });
  assert.equal(rep.decision, "block");
  assert.equal(rep.gates.find((g) => g.gate === "keyedCredentialLead")!.blocking.length, 1);
  assert.equal(assure({ manifest: m, policy: policyOf({ gates: { keyedCredentialLead: "warn" } }) }).decision, "pass");
  const { fp } = await import("./helpers.js");
  const declared = manifestFor(dir, { releaseClosure: { roots: ["rel"] }, assets: [...assets, { id: "dd", placement: "public-by-design" as const, fingerprints: [fp(value)] }] });
  assert.equal(assure({ manifest: declared, policy: policyOf() }).decision, "pass");
});
