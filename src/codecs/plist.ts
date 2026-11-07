import { DecodeError } from "./xz.js";

/**
 * Zero-dependency property-list reader (Apple XML and binary `bplist00`).
 * Used for Info.plist, entitlements and CodeResources. Read-only; values map
 * to JS: dict → object, array → array, string → string, data → Buffer,
 * integer/real → number, true/false → boolean, date → ISO string.
 */

export type PlistValue = string | number | boolean | Buffer | PlistValue[] | { [k: string]: PlistValue };

export function parsePlist(buf: Buffer): PlistValue {
  if (buf.length >= 8 && buf.toString("latin1", 0, 8) === "bplist00") return parseBinary(buf);
  return parseXml(buf.toString("utf8"));
}

// ---------------------------------------------------------------- XML

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
const unescape = (s: string) =>
  s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_, e: string) =>
    e[0] === "#" ? String.fromCodePoint(e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : ENTITIES[e.toLowerCase()]!,
  );

function parseXml(xml: string): PlistValue {
  const start = xml.indexOf("<plist");
  if (start === -1) throw new DecodeError("not a property list");
  const re = /<(\/?)([a-zA-Z]+)(\s[^>]*?)?(\/?)>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>/g;
  re.lastIndex = xml.indexOf(">", start) + 1;
  type Frame = { kind: "dict"; obj: Record<string, PlistValue>; key: string | null } | { kind: "array"; arr: PlistValue[] };
  const stack: Frame[] = [];
  let root: PlistValue | undefined;
  const emit = (v: PlistValue) => {
    const top = stack[stack.length - 1];
    if (!top) {
      if (root !== undefined) throw new DecodeError("plist has more than one root value");
      root = v;
    } else if (top.kind === "array") top.arr.push(v);
    else {
      if (top.key === null) throw new DecodeError("plist dict value without a key");
      top.obj[top.key] = v;
      top.key = null;
    }
  };
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    if (!m[2]) continue; // comment, PI, doctype
    const [, close, tag, , selfClose] = m;
    if (tag === "plist") {
      if (close) break;
      continue;
    }
    if (close) {
      const f = stack.pop();
      if (!f || f.kind !== tag) throw new DecodeError(`plist: unexpected </${tag}>`);
      emit(f.kind === "dict" ? f.obj : f.arr);
      continue;
    }
    if (tag === "dict" || tag === "array") {
      if (selfClose) emit(tag === "dict" ? {} : []);
      else stack.push(tag === "dict" ? { kind: "dict", obj: {}, key: null } : { kind: "array", arr: [] });
      continue;
    }
    if (tag === "true" || tag === "false") {
      emit(tag === "true");
      continue;
    }
    // leaf with text content
    const end = xml.indexOf(`</${tag}>`, re.lastIndex);
    const text = selfClose ? "" : end === -1 ? (() => { throw new DecodeError(`plist: unterminated <${tag}>`); })() : xml.slice(re.lastIndex, end);
    if (!selfClose) re.lastIndex = end + tag!.length + 3;
    if (tag === "key") {
      const top = stack[stack.length - 1];
      if (!top || top.kind !== "dict") throw new DecodeError("plist <key> outside a dict");
      top.key = unescape(text);
    } else if (tag === "string") emit(unescape(text));
    else if (tag === "data") emit(Buffer.from(text.replace(/\s+/g, ""), "base64"));
    else if (tag === "integer" || tag === "real") emit(Number(text.trim()));
    else if (tag === "date") emit(text.trim());
    else throw new DecodeError(`plist: unsupported element <${tag}>`);
  }
  if (root === undefined || stack.length > 0) throw new DecodeError("plist is incomplete");
  return root;
}

// ---------------------------------------------------------------- binary

function parseBinary(b: Buffer): PlistValue {
  if (b.length < 40) throw new DecodeError("binary plist too short");
  const t = b.length - 32;
  const offSize = b[t + 6]!;
  const refSize = b[t + 7]!;
  const numObjects = Number(b.readBigUInt64BE(t + 8));
  const topObject = Number(b.readBigUInt64BE(t + 16));
  const tableOffset = Number(b.readBigUInt64BE(t + 24));
  if (offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || tableOffset + numObjects * offSize > t || topObject >= numObjects)
    throw new DecodeError("binary plist trailer is corrupt");
  const uint = (at: number, n: number) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + b[at + i]!;
    return v;
  };
  const offsetOf = (i: number) => uint(tableOffset + i * offSize, offSize);
  const depth = new Set<number>();
  const obj = (i: number): PlistValue => {
    if (i >= numObjects || depth.has(i)) throw new DecodeError("binary plist object reference is invalid or cyclic");
    depth.add(i);
    try {
      let p = offsetOf(i);
      if (p >= t) throw new DecodeError("binary plist offset out of range");
      const marker = b[p]!;
      const hi = marker >> 4;
      const lo = marker & 0x0f;
      p++;
      const count = (): number => {
        if (lo !== 0x0f) return lo;
        const m = b[p]!;
        if (m >> 4 !== 0x1) throw new DecodeError("binary plist count is malformed");
        const n = 1 << (m & 0x0f);
        const v = uint(p + 1, n);
        p += 1 + n;
        return v;
      };
      switch (hi) {
        case 0x0:
          if (marker === 0x08) return false;
          if (marker === 0x09) return true;
          throw new DecodeError("binary plist: unsupported singleton");
        case 0x1: {
          const n = 1 << lo;
          return n === 8 ? Number(b.readBigInt64BE(p)) : uint(p, n);
        }
        case 0x2:
          return lo === 2 ? b.readFloatBE(p) : b.readDoubleBE(p);
        case 0x3:
          return new Date((b.readDoubleBE(p) + 978307200) * 1000).toISOString();
        case 0x4: {
          const n = count();
          return Buffer.from(b.subarray(p, p + n));
        }
        case 0x5: {
          const n = count();
          return b.toString("latin1", p, p + n);
        }
        case 0x6: {
          const n = count();
          let s = "";
          for (let k = 0; k < n; k++) s += String.fromCharCode(b.readUInt16BE(p + 2 * k));
          return s;
        }
        case 0xa: {
          const n = count();
          const out: PlistValue[] = [];
          for (let k = 0; k < n; k++) out.push(obj(uint(p + k * refSize, refSize)));
          return out;
        }
        case 0xd: {
          const n = count();
          const out: Record<string, PlistValue> = {};
          for (let k = 0; k < n; k++) {
            const key = obj(uint(p + k * refSize, refSize));
            if (typeof key !== "string") throw new DecodeError("binary plist dict key is not a string");
            out[key] = obj(uint(p + (n + k) * refSize, refSize));
          }
          return out;
        }
        default:
          throw new DecodeError(`binary plist: unsupported object type 0x${hi.toString(16)}`);
      }
    } finally {
      depth.delete(i);
    }
  };
  return obj(topObject);
}

export const isDict = (v: PlistValue | undefined): v is { [k: string]: PlistValue } =>
  typeof v === "object" && v !== null && !Array.isArray(v) && !Buffer.isBuffer(v);
