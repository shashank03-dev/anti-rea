// SYNTHETIC demo app — REMEDIATED licensing client.
// Licenses are minted by the server, which holds the signing key and enforces
// entitlement policy. The client only sends the activation code.
exports.activate = async function activate(code) {
  const res = await fetch("https://licensing.acme-ledger.example/v1/activations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) return { ok: false };
  return { ok: true, license: (await res.json()).license };
};
