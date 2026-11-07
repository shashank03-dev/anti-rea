// SYNTHETIC demo app — renderer bundle (template; build-release.mjs fills placeholders).
"use strict";

// Public-by-design: a browser maps key restricted by referrer/API on the provider side.
// Declared in the manifest as public-by-design so it is NOT treated as a leak.
const MAPS_BROWSER_KEY = "__MAPS_BROWSER_KEY__";

// Sensitive-local by business requirement: ranking must work offline.
function rankCandidatesOffline(candidates, weights) {
  return candidates
    .map((c) => ({ c, s: c.recency * weights.recency + c.amount * weights.amount }))
    .sort((a, b) => b.s - a.s)
    .map((x) => x.c);
}

async function onActivate(code) {
  const result = await window.ledger.activateLicense(code);
  document.getElementById("root").textContent = result.ok ? "Activated" : "Activation failed";
}

window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("root").textContent = "Ready";
  void MAPS_BROWSER_KEY;
  void rankCandidatesOffline;
  void onActivate;
});
__SOURCEMAP_COMMENT__
