// SYNTHETIC demo app — REMEDIATED update plugin: risk decisions are made server-side.
// The response carries only the decision the UI needs, not scores or rule details.
exports.requestRiskDecision = async function requestRiskDecision(txId, session) {
  const res = await fetch(`https://api.acme-ledger.example/v1/transactions/${encodeURIComponent(txId)}/risk-decision`, {
    headers: { authorization: `Bearer ${session.accessToken}` },
  });
  return res.ok ? (await res.json()).decision : "review";
};
