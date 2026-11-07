import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * models (item scope, header-only): GGUF, safetensors and TFLite model files. These disclose model
 * structure — architecture, tensor names, shapes and dtypes — in the clear. The report prints metadata
 * KEYS and the architecture name only, never metadata VALUES (plan item 7), and the lane redacts the
 * detail as a backstop. Header-only (`needs.head`), so a multi-GB model that is a size-limit gap still
 * gets a header verdict with `coverage: partial`.
 */

const GGUF = Buffer.from("GGUF", "latin1");

/** GGUF metadata value sizes/skippers. Returns the offset after the value, or -1 on overrun. */
function skipGgufValue(b: Buffer, o: number, type: number, depth = 0): number {
  const fixed: Record<number, number> = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };
  if (type in fixed) return o + fixed[type]! <= b.length ? o + fixed[type]! : -1;
  if (type === 8) {
    if (o + 8 > b.length) return -1;
    const len = Number(b.readBigUInt64LE(o));
    return o + 8 + len <= b.length && len >= 0 ? o + 8 + len : -1;
  }
  if (type === 9 && depth < 4) {
    if (o + 12 > b.length) return -1;
    const elemType = b.readUInt32LE(o);
    const count = Number(b.readBigUInt64LE(o + 4));
    let p = o + 12;
    for (let i = 0; i < count; i++) {
      p = skipGgufValue(b, p, elemType, depth + 1);
      if (p < 0) return -1;
    }
    return p;
  }
  return -1;
}

function readGgufString(b: Buffer, o: number): [string, number] {
  if (o + 8 > b.length) return ["", -1];
  const len = Number(b.readBigUInt64LE(o));
  if (len < 0 || o + 8 + len > b.length) return ["", -1];
  return [b.toString("utf8", o + 8, o + 8 + len), o + 8 + len];
}

function analyzeGguf(b: Buffer, path: string, complete: boolean): RawFinding {
  const version = b.length >= 8 ? b.readUInt32LE(4) : 0;
  const kvCount = b.length >= 24 ? Number(b.readBigUInt64LE(16)) : 0;
  const tensorCount = b.length >= 16 ? Number(b.readBigUInt64LE(8)) : 0;
  const keys: string[] = [];
  let arch = "";
  let p = 24;
  let truncated = false;
  for (let i = 0; i < Math.min(kvCount, 100000); i++) {
    const [key, p2] = readGgufString(b, p);
    if (p2 < 0) {
      truncated = true;
      break;
    }
    if (p2 + 4 > b.length) {
      truncated = true;
      break;
    }
    const type = b.readUInt32LE(p2);
    const valOff = p2 + 4;
    if (key === "general.architecture" && type === 8) {
      const [v] = readGgufString(b, valOff);
      arch = v;
    }
    keys.push(key);
    const np = skipGgufValue(b, valOff, type);
    if (np < 0) {
      truncated = true;
      break;
    }
    p = np;
  }
  return {
    analyzerId: "models",
    rubricId: "models/plaintext",
    title: "GGUF model ships metadata in the clear",
    recovers: `the model architecture${arch ? ` (${arch})` : ""}, ${tensorCount} tensor(s) and ${keys.length}${truncated ? "+" : ""} metadata key(s) — names and architecture only`,
    remediation: "GGUF stores architecture and hyperparameters in the clear by design; if the model itself is the asset, gate it behind a license/server rather than shipping it in the client",
    avoidable: false,
    path,
    coverage: complete && !truncated ? "full" : "partial",
    detail: `${path}: GGUF v${version}; metadata key names — ${keys.slice(0, 20).join(", ")}${keys.length > 20 ? ", …" : ""}`,
  };
}

function analyzeSafetensors(b: Buffer, path: string, totalBytes: number): RawFinding {
  const headerLen = Number(b.readBigUInt64LE(0));
  if (headerLen <= 0 || 8 + headerLen > b.length) {
    return { analyzerId: "models", rubricId: "models/plaintext", title: "safetensors model (header beyond the read window)", recovers: "a safetensors model; its JSON header is larger than the bytes read here, so the tensor list was not enumerated", remediation: "if the model is the asset, gate it behind a license/server rather than shipping it", avoidable: false, path, coverage: "partial", detail: `${path}: header ${headerLen} bytes` };
  }
  let tensors = 0;
  const dtypes = new Set<string>();
  const metaKeys: string[] = [];
  const names: string[] = [];
  try {
    const hdr = JSON.parse(b.toString("utf8", 8, 8 + headerLen)) as Record<string, unknown>;
    for (const [k, v] of Object.entries(hdr)) {
      if (k === "__metadata__") {
        if (v && typeof v === "object") metaKeys.push(...Object.keys(v as object));
        continue;
      }
      tensors++;
      if (names.length < 8) names.push(k);
      const dt = (v as { dtype?: unknown }).dtype;
      if (typeof dt === "string") dtypes.add(dt);
    }
  } catch {
    /* header not JSON */
  }
  return {
    analyzerId: "models",
    rubricId: "models/plaintext",
    title: "safetensors model ships its tensor layout in the clear",
    recovers: `${tensors} tensor(s) with names and dtypes (${[...dtypes].join(", ") || "?"})${metaKeys.length ? `, plus __metadata__ keys (${metaKeys.join(", ")})` : ""}`,
    remediation: "safetensors stores the tensor layout in the clear by design; if the weights are the asset, gate them behind a license/server rather than shipping them in the client",
    avoidable: false,
    path,
    coverage: 8 + headerLen <= totalBytes ? "full" : "partial",
    detail: `${path}: ${tensors} tensors; e.g. ${names.slice(0, 4).join(", ")}`,
  };
}

export const models: Analyzer = {
  id: "models",
  title: "Model files (GGUF, safetensors, TFLite)",
  mirrorsRea: "ML model container inspection",
  scope: "item",
  needs: { head: 1 << 20 },

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "item") return false;
    const b = ctx.bytes;
    if (b.length < 12) return false;
    if (b.subarray(0, 4).equals(GGUF)) return true;
    if (b.length >= 8 && b.toString("latin1", 4, 8) === "TFL3") return true;
    // safetensors: 8-byte LE header length, then a JSON object
    const len = Number(b.readBigUInt64LE(0));
    const total = (ctx as ItemContext).item.ref.bytes;
    return len > 0 && len < Math.max(total, b.length) && 8 < b.length && b[8] === 0x7b; // '{'
  },

  profile(): ProfileTags {
    return { frameworks: ["ML model"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes, complete } = ctx as ItemContext;
    const path = item.ref.path;
    if (bytes.subarray(0, 4).equals(GGUF)) return [analyzeGguf(bytes, path, complete)];
    if (bytes.length >= 8 && bytes.toString("latin1", 4, 8) === "TFL3")
      return [{ analyzerId: "models", rubricId: "models/plaintext", title: "TFLite model ships in the clear", recovers: "the TFLite graph: operators, tensor shapes and (often) quantization params are readable with the TFLite/Netron tooling", remediation: "TFLite is a readable container by design; gate the model behind a license/server if it is the asset", avoidable: false, path, coverage: complete ? "full" : "partial", detail: path }];
    return [analyzeSafetensors(bytes, path, item.ref.bytes)];
  },
};
