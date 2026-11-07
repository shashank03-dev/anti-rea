/**
 * Zero-dependency Android binary-XML (AXML) reader (v0.8, exposure lane), scoped to what the APK
 * analyzer needs from a compiled AndroidManifest.xml: the package name and version, the `<application>`
 * flags (`debuggable`, `allowBackup`, `usesCleartextTraffic`) and the SDK levels.
 *
 * AXML is a chunked format: a string pool, an optional resource map, then the XML node stream. System
 * attributes (the `android:` namespace) are addressed by resource id; aapt2 keeps their names in the
 * pool, so names are matched first, with the stable resource ids as a fallback. Every read goes through
 * a bounds-checked accessor and every loop is capped: malformed input yields partial facts, never an
 * exception (test/v08-fuzz.test.ts corrupts a real manifest to hold this).
 */

export interface AndroidManifestFacts {
  package?: string;
  debuggable?: boolean;
  allowBackup?: boolean;
  usesCleartextTraffic?: boolean;
  minSdk?: number;
  targetSdk?: number;
  versionName?: string;
}

// Stable framework attribute resource ids (fallback when the name string is absent).
const ATTR = { debuggable: 0x0101000f, allowBackup: 0x0101001d, minSdk: 0x0101020c, targetSdk: 0x01010270, usesCleartextTraffic: 0x0101021b, versionName: 0x0101021c } as const;
const TYPE_INT_BOOLEAN = 0x12;
const MAX = 200_000;

export function looksLikeAxml(b: Buffer): boolean {
  return b.length >= 8 && b.readUInt16LE(0) === 0x0003 && b.readUInt32LE(4) <= b.length + 16;
}

function reader(b: Buffer) {
  const ok = (o: number, n: number) => o >= 0 && o + n <= b.length;
  return {
    ok,
    u8: (o: number) => (ok(o, 1) ? b[o]! : 0),
    u16: (o: number) => (ok(o, 2) ? b.readUInt16LE(o) : 0),
    u32: (o: number) => (ok(o, 4) ? b.readUInt32LE(o) : 0),
  };
}

function readStringPool(b: Buffer, off: number): string[] {
  const r = reader(b);
  const strings: string[] = [];
  if (!r.ok(off, 28)) return strings;
  const chunkSize = r.u32(off + 4);
  const count = r.u32(off + 8);
  const flags = r.u32(off + 16);
  const stringsStart = r.u32(off + 20);
  const utf8 = (flags & 0x100) !== 0;
  const dataBase = off + stringsStart;
  const end = Math.min(off + chunkSize, b.length);
  for (let i = 0; i < Math.min(count, MAX); i++) {
    const idxOff = off + 28 + i * 4;
    if (!r.ok(idxOff, 4)) break;
    let p = dataBase + r.u32(idxOff);
    if (p < 0 || p >= end) {
      strings.push("");
      continue;
    }
    if (utf8) {
      // two length fields (char count, then byte count), each 1–2 bytes
      let charLen = r.u8(p++);
      if (charLen & 0x80) charLen = ((charLen & 0x7f) << 8) | r.u8(p++);
      let byteLen = r.u8(p++);
      if (byteLen & 0x80) byteLen = ((byteLen & 0x7f) << 8) | r.u8(p++);
      strings.push(p + byteLen <= end ? b.toString("utf8", p, p + byteLen) : "");
    } else {
      let charLen = r.u16(p);
      p += 2;
      if (charLen & 0x8000) {
        charLen = ((charLen & 0x7fff) << 16) | r.u16(p);
        p += 2;
      }
      strings.push(p + charLen * 2 <= end ? b.toString("utf16le", p, p + charLen * 2) : "");
    }
  }
  return strings;
}

export function readAndroidManifest(b: Buffer): AndroidManifestFacts {
  const facts: AndroidManifestFacts = {};
  if (!looksLikeAxml(b)) return facts;
  const r = reader(b);
  const fileSize = Math.min(r.u32(4), b.length);
  let p = r.u16(2) || 8;
  let pool: string[] = [];
  let resMap: number[] = [];
  const str = (i: number) => (i >= 0 && i < pool.length ? pool[i]! : "");

  for (let chunks = 0; chunks < MAX && p + 8 <= fileSize; chunks++) {
    const type = r.u16(p);
    const size = r.u32(p + 4);
    if (size < 8 || p + size > fileSize) break;
    if (type === 0x0001) pool = readStringPool(b, p);
    else if (type === 0x0180) {
      const n = Math.min(Math.floor((size - 8) / 4), MAX);
      resMap = [];
      for (let i = 0; i < n; i++) resMap.push(r.u32(p + 8 + i * 4));
    } else if (type === 0x0102 && size >= 36) {
      // START_ELEMENT: chunk header (8) + line/comment (8), then attrExt: ns, name, attributeStart,
      // attributeSize, attributeCount, idIndex, classIndex, styleIndex.
      const elem = str(r.u32(p + 20));
      const attrStart = r.u16(p + 24);
      const attrSize = Math.max(20, r.u16(p + 26));
      const attrCount = r.u16(p + 28);
      const abase = p + 16 + attrStart;
      for (let a = 0; a < Math.min(attrCount, 4096); a++) {
        const ao = abase + a * attrSize;
        if (ao + 20 > p + size) break;
        const aNameIdx = r.u32(ao + 4);
        const dataType = r.u8(ao + 15);
        const data = r.u32(ao + 16);
        const name = str(aNameIdx);
        const resId = aNameIdx < resMap.length ? resMap[aNameIdx]! : 0;
        const boolVal = dataType === TYPE_INT_BOOLEAN ? data !== 0 : undefined;
        const strVal = str(r.u32(ao + 8));
        const is = (n: string, id: number) => name === n || resId === id;
        if (elem === "manifest" && name === "package" && strVal) facts.package = strVal;
        else if (elem === "manifest" && is("versionName", ATTR.versionName) && strVal) facts.versionName = strVal;
        else if (elem === "uses-sdk" && is("minSdkVersion", ATTR.minSdk)) facts.minSdk = data;
        else if (elem === "uses-sdk" && is("targetSdkVersion", ATTR.targetSdk)) facts.targetSdk = data;
        else if (elem === "application" && is("debuggable", ATTR.debuggable) && boolVal !== undefined) facts.debuggable = boolVal;
        else if (elem === "application" && is("allowBackup", ATTR.allowBackup) && boolVal !== undefined) facts.allowBackup = boolVal;
        else if (elem === "application" && is("usesCleartextTraffic", ATTR.usesCleartextTraffic) && boolVal !== undefined) facts.usesCleartextTraffic = boolVal;
      }
    }
    p += size;
  }
  return facts;
}
