// SYNTHETIC demo app — VULNERABLE licensing client.
// Anti-pattern under test: the license-signing private key was bundled into the
// client so licenses could be minted "offline". Anyone with the installer holds it.
const crypto = require("node:crypto");

const LICENSE_SIGNING_KEY = "__SIGNING_KEY_ESCAPED__";

exports.activate = function activate(code) {
  const sig = crypto.sign("sha256", Buffer.from(code), LICENSE_SIGNING_KEY);
  return { ok: true, license: `${code}.${sig.toString("base64url")}` };
};
