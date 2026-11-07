// SYNTHETIC demo app — VULNERABLE update plugin.
// Anti-pattern under test: proprietary server-only fraud rules shipped to clients
// inside an auto-update bundle "for latency".
const FRAUD_RULES_TABLE_V3 = [
  { field: "velocity_1h", op: ">", value: 7, weight: 0.42 },
  { field: "geo_mismatch", op: "==", value: 1, weight: 0.31 },
  { field: "amount_z", op: ">", value: 3.1, weight: 0.27 },
];

exports.scoreTransactionRiskV3 = function scoreTransactionRiskV3(tx) {
  return FRAUD_RULES_TABLE_V3.reduce((s, r) => {
    const v = tx[r.field];
    const hit = r.op === ">" ? v > r.value : v === r.value;
    return s + (hit ? r.weight : 0);
  }, 0);
};
