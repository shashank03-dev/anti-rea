/**
 * Redaction invariant for the exposure report (v0.8, plan item 7).
 *
 * The exposure report names what a REA-class tool recovers, but it must never become the leak itself.
 * Analyzers already print metadata KEYS only (GGUF/safetensors) and keep secret values out of what they
 * say, but build metadata is a live hazard: Go `buildinfo` records the exact `-ldflags`, so a
 * `-X main.apiKey=sk-live-…` would otherwise land verbatim in `exposure.json`. The lane runs `redact()`
 * over every finding's `recovers` and `detail` before serialization, as the final safety net.
 *
 * It masks the VALUE of:
 *  - linker `-X importpath.name=VALUE` assignments (`-X name=v`, `-X=name=v`, quoted forms),
 *  - `KEY=VALUE` / `KEY: VALUE` pairs whose key names a credential, or whose value looks like one,
 * keeping the key, the structure and a short, non-reconstructible preview in the repo's witness style.
 * Values under keys that name public identifiers (a VCS revision, a build id, a GUID) are kept.
 * Tests (test/v08.test.ts, test/v08-differential.test.ts): planted secrets never appear in the report.
 */

/** First few characters and the length — never enough to reconstruct the value. */
function mask(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return "…[redacted]";
  return `${v.slice(0, Math.min(4, Math.floor(v.length / 4)))}…[redacted ${v.length} chars]`;
}

const CREDENTIAL_KEY = /(key|token|secret|passw(or)?d|pwd|credential|auth|signature|private|access|session|cookie|bearer|dsn)/i;
const PUBLIC_KEY = /(revision|commit|vcs|hash|sha\d*|build[._-]?id|guid|uuid|version|modified|time)$/i;

/** Does this value look like a credential or opaque token, rather than a word, path or version? */
function secretish(raw: string): boolean {
  const s = raw.trim();
  if (s.length < 12) return false;
  if (/^v?\d+(?:\.\d+)+/.test(s)) return false; // version
  if (s.includes("/") && !/[A-Za-z0-9+]{32,}/.test(s)) return false; // a path, not a blob
  if (/^[A-Za-z][\w.-]*$/.test(s) && !/\d{3,}/.test(s) && s.length < 24) return false; // identifier
  const blob = /^[A-Za-z0-9_\-+/=]{20,}$/.test(s);
  const mixed = /[A-Z]/.test(s) && /[a-z]/.test(s) && /\d/.test(s) && s.length >= 16;
  const separated = /[-_]/.test(s) && /\d/.test(s) && s.length >= 20;
  return blob || mixed || separated;
}

export function redact(text: string): string {
  // Linker -X assignments: always masked, whatever the value looks like.
  let out = text.replace(/(-X(?:\s+|=)["']?[\w./-]+=)([^\s"']+)/g, (_m, k: string, v: string) => `${k}${mask(v)}`);
  // KEY=VALUE / KEY: VALUE.
  out = out.replace(/([A-Za-z_][\w.-]*)(\s*[:=]\s*)(["']?)([A-Za-z0-9_\-+/=.]{12,})(\3)/g, (m, key: string, sep: string, q: string, v: string) => {
    if (CREDENTIAL_KEY.test(key)) return `${key}${sep}${q}${mask(v)}${q}`;
    if (PUBLIC_KEY.test(key)) return m;
    return secretish(v) ? `${key}${sep}${q}${mask(v)}${q}` : m;
  });
  return out;
}
