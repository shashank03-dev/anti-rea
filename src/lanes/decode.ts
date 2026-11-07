/**
 * Decoding of text-level encodings that hide credentials from pattern
 * matching: base64 (standard and URL-safe), hex, and percent-encoding.
 *
 * A run is decoded only if the result is valid UTF-8 that is mostly
 * printable. Random bytes, images and hashes decode to binary noise and are
 * dropped, so this adds candidates without adding noise. Decoding recurses
 * (base64 of percent-encoded text, and so on) up to `maxDepth` layers.
 */

export type Encoding = "base64" | "hex" | "percent";

export interface DecodedSpan {
  /** Decoded text. */
  readonly text: string;
  /** Character index of the encoded run in the text it was found in (outermost layer). */
  readonly index: number;
  /** Outermost encoding first. */
  readonly chain: readonly Encoding[];
}

export interface DecodeOptions {
  readonly maxDepth: number;
  /** Encoded runs longer than this are skipped (large data URIs are images, not secrets). */
  readonly maxRunChars: number;
  /** Stop after this many decoded spans per text (bounds work on pathological input). */
  readonly maxSpans: number;
}

export const DEFAULT_DECODE: DecodeOptions = { maxDepth: 2, maxRunChars: 1 << 20, maxSpans: 20_000 };

const B64_RUN = /[A-Za-z0-9+/_-]{20,}={0,2}/g;
const HEX_RUN = /(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])/g;
const PCT_ESCAPE = /%[0-9A-Fa-f]{2}/g;
/** Characters that can appear inside a percent-encoded token (URL / form value). */
const PCT_BODY = /[A-Za-z0-9%._~!$&'()*+,;=:@/?-]/;

/**
 * Percent-encoded runs, found in linear time: locate escapes, then grow each
 * run over URL characters. (A single regex for this backtracks quadratically
 * on long binary runs.)
 */
function* percentRuns(t: string): Generator<{ run: string; index: number }> {
  let coveredTo = -1;
  for (const m of t.matchAll(PCT_ESCAPE)) {
    const at = m.index ?? 0;
    if (at < coveredTo) continue;
    let a = at;
    while (a > 0 && a > coveredTo && PCT_BODY.test(t[a - 1]!)) a--;
    let b = at;
    while (b < t.length && PCT_BODY.test(t[b]!)) b++;
    coveredTo = b;
    const run = t.slice(a, b);
    let escapes = 0;
    for (let i = run.indexOf("%"); i !== -1; i = run.indexOf("%", i + 1)) if (/^[0-9A-Fa-f]{2}$/.test(run.slice(i + 1, i + 3))) escapes++;
    if (escapes >= 3) yield { run, index: a };
  }
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

/** Valid UTF-8, at least 12 characters, and at least 90% printable. */
function readable(bytes: Buffer): string | null {
  if (bytes.length < 12) return null;
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    return null;
  }
  let bad = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x7f || c === 0xfffd) bad++;
  }
  return bad <= text.length * 0.1 ? text : null;
}

function decodeBase64(run: string): Buffer | null {
  const body = run.replace(/=+$/, "");
  const std = /[+/]/.test(body);
  const url = /[-_]/.test(body);
  if (std && url) return null; // mixed alphabets: an identifier or path, not base64
  if (body.length % 4 === 1) return null;
  if (!/[0-9+/_-]/.test(body) && !/[A-Z]/.test(body)) return null; // plain lowercase words
  return Buffer.from(body, url ? "base64url" : "base64");
}

function decodePercent(run: string): Buffer | null {
  const out: number[] = [];
  for (let i = 0; i < run.length; i++) {
    if (run[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(run.slice(i + 1, i + 3))) {
      out.push(parseInt(run.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      const code = run.charCodeAt(i);
      if (code > 0x7f) return null;
      out.push(code === 0x2b ? 0x20 : code); // '+' is a space in form encoding
    }
  }
  return Buffer.from(out);
}

export function decodeLayers(text: string, opts: DecodeOptions = DEFAULT_DECODE): DecodedSpan[] {
  const out: DecodedSpan[] = [];
  const visit = (t: string, outerIndex: number | null, chain: readonly Encoding[]) => {
    if (chain.length >= opts.maxDepth) return;
    const emit = (enc: Encoding, index: number, bytes: Buffer | null) => {
      if (out.length >= opts.maxSpans || !bytes) return;
      const decoded = readable(bytes);
      if (decoded === null || decoded === t) return;
      const span: DecodedSpan = { text: decoded, index: outerIndex ?? index, chain: [...chain, enc] };
      out.push(span);
      visit(decoded, span.index, span.chain);
    };
    for (const m of t.matchAll(B64_RUN)) {
      if (m[0].length > opts.maxRunChars) continue;
      emit("base64", m.index ?? 0, decodeBase64(m[0]));
    }
    for (const m of t.matchAll(HEX_RUN)) {
      if (m[0].length % 2 === 1 || m[0].length > opts.maxRunChars) continue;
      emit("hex", m.index ?? 0, Buffer.from(m[0], "hex"));
    }
    if (t.includes("%")) {
      for (const { run, index } of percentRuns(t)) {
        if (run.length > opts.maxRunChars) continue;
        emit("percent", index, decodePercent(run));
      }
    }
  };
  visit(text, null, []);
  return out;
}
