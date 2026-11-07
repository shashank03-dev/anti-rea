import { readAndroidManifest } from "../codecs/axml.js";
import type { InventoryItem } from "../lanes/types.js";
import type { Analyzer, AnalyzerContext, BundleContext, ProfileTags, RawFinding } from "./types.js";

/**
 * apk (bundle scope): what a REA tool recovers from an Android APK/AAB — the DEX bytecode (jadx
 * decompiles it to near-source Java/Kotlin), the `<application>` debug/backup flags from the binary
 * AndroidManifest, and the signing scheme (v1-only JAR signing is weak; v2/v3 protect the whole APK).
 *
 * R8 heuristic: the simple names of the classes the DEX DEFINES (class_defs, not type_ids — type_ids
 * also list every referenced framework type such as `Landroid/app/Activity;`, which R8 never renames
 * and which would dilute the signal). Fewer than 20 defined classes is undecidable and said so.
 * Native `lib/<abi>/*.so` entries are analyzed by `native-elf`.
 */

const DEX_MAGIC = Buffer.from("dex\n", "latin1");
const SIG_BLOCK_MAGIC = Buffer.from("APK Sig Block 42", "latin1");
const BLOCK_ID: Record<number, string> = { 0x7109871a: "v2", 0xf05368c0: "v3", 0x1b93ad61: "v3.1" };
const DEX_NAME = /(?:^|\/)classes\d*\.dex$/;
const MIN_CLASSES = 20;

const rel = (it: InventoryItem) => it.ref.path.split("!/").pop() ?? it.ref.path;

/** ULEB128 at offset; returns [value, nextOffset]. */
function uleb(b: Buffer, o: number): [number, number] {
  let result = 0;
  let shift = 0;
  let p = o;
  for (let i = 0; i < 5 && p < b.length; i++) {
    const byte = b[p++]!;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return [result >>> 0, p];
}

/** Simple names of the classes a DEX defines (outer class part), for the R8 heuristic. */
export function dexDefinedClassNames(b: Buffer): string[] {
  if (b.length < 0x70 || !b.subarray(0, 4).equals(DEX_MAGIC)) return [];
  if (b.readUInt32LE(0x28) !== 0x12345678) return []; // big-endian DEX: skip the heuristic
  const u32 = (o: number) => (o >= 0 && o + 4 <= b.length ? b.readUInt32LE(o) : -1);
  const stringIdsSize = u32(0x38);
  const stringIdsOff = u32(0x3c);
  const typeIdsSize = u32(0x40);
  const typeIdsOff = u32(0x44);
  const classDefsSize = u32(0x60);
  const classDefsOff = u32(0x64);
  const strAt = (i: number): string => {
    if (i < 0 || i >= stringIdsSize) return "";
    const dataOff = u32(stringIdsOff + i * 4);
    if (dataOff < 0 || dataOff >= b.length) return "";
    const [, p] = uleb(b, dataOff); // skip the utf16 length
    const end = b.indexOf(0, p);
    return end === -1 || end - p > 4096 ? "" : b.toString("utf8", p, end);
  };
  const out: string[] = [];
  for (let i = 0; i < Math.min(classDefsSize, 50_000); i++) {
    const typeIdx = u32(classDefsOff + i * 32);
    if (typeIdx < 0 || typeIdx >= typeIdsSize) continue;
    const desc = strAt(u32(typeIdsOff + typeIdx * 4));
    if (!desc.startsWith("L") || !desc.endsWith(";")) continue;
    const simple = (desc.slice(1, -1).split("/").pop() ?? "").split("$")[0] ?? "";
    if (simple && simple !== "R" && simple !== "BuildConfig") out.push(simple);
  }
  return out;
}

/** APK Signature Scheme blocks present (v2/v3/v3.1), read from the APK Signing Block before the central directory. */
export function apkSigningSchemes(apk: Buffer): Set<string> {
  const schemes = new Set<string>();
  const min = Math.max(0, apk.length - 65_557);
  let eocd = -1;
  for (let i = apk.length - 22; i >= min; i--)
    if (apk.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  if (eocd < 0) return schemes;
  const cdOffset = apk.readUInt32LE(eocd + 16);
  if (cdOffset < 32 || cdOffset > apk.length) return schemes;
  if (!apk.subarray(cdOffset - 16, cdOffset).equals(SIG_BLOCK_MAGIC)) return schemes; // no block ⇒ v1-only or unsigned
  // Layout: [u64 size][id-value pairs][u64 size][magic]; size counts everything after the first size field.
  const blockSize = Number(apk.readBigUInt64LE(cdOffset - 24));
  const blockStart = cdOffset - blockSize - 8;
  if (blockStart < 0 || Number(apk.readBigUInt64LE(blockStart)) !== blockSize) return schemes;
  const pairsEnd = cdOffset - 24;
  let p = blockStart + 8;
  for (let n = 0; n < 256 && p + 12 <= pairsEnd; n++) {
    const pairLen = Number(apk.readBigUInt64LE(p));
    if (pairLen < 4 || p + 8 + pairLen > pairsEnd) break;
    const scheme = BLOCK_ID[apk.readUInt32LE(p + 8) >>> 0];
    if (scheme) schemes.add(scheme);
    p += 8 + pairLen;
  }
  return schemes;
}

export const apk: Analyzer = {
  id: "apk",
  title: "Android APK: DEX, manifest flags and signing scheme",
  mirrorsRea: "APK / DEX decompilation (jadx) and manifest inspection",
  scope: "bundle",
  needs: {},

  detect(ctx: AnalyzerContext): boolean {
    if (ctx.scope !== "bundle") return false;
    const b = ctx as BundleContext;
    const root = b.group.root.toLowerCase();
    // A container is an APK/AAB by its own structure: a manifest plus DEX code (names only corroborate).
    return !!b.entry("AndroidManifest.xml") && (b.group.entries.some((e) => DEX_NAME.test(rel(e))) || root.endsWith(".apk") || root.endsWith(".aab"));
  },

  profile(): ProfileTags {
    return { platforms: ["Android"], languages: ["Java/Kotlin"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const b = ctx as BundleContext;
    const out: RawFinding[] = [];
    const root = b.group.root || "(release)";
    const isAab = root.toLowerCase().endsWith(".aab") || b.group.entries.some((e) => /^base\/manifest\/AndroidManifest\.xml$/.test(rel(e)));
    const dexes = b.group.entries.filter((e) => DEX_NAME.test(rel(e)));

    // DEX bytecode + R8 heuristic
    if (dexes.length > 0) {
      const names: string[] = [];
      let version = "";
      for (const d of dexes) {
        const buf = b.read(d);
        if (buf && buf.length > 8 && buf.subarray(0, 4).equals(DEX_MAGIC)) {
          if (!version) version = buf.toString("latin1", 4, 7);
          names.push(...dexDefinedClassNames(buf));
        }
      }
      const path = dexes[0]!.ref.path;
      const ids = names.filter((n) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(n));
      const shortShare = ids.length > 0 ? ids.filter((n) => n.length <= 2).length / ids.length : 0;
      const detail = `${dexes.length} dex file(s), version ${version || "?"}; ${ids.length} defined class(es)${ids.length >= MIN_CLASSES ? `, ${(shortShare * 100).toFixed(0)}% with 1–2 character names` : ""}`;
      if (ids.length < MIN_CLASSES)
        out.push({ analyzerId: this.id, rubricId: "code/near-source-bytecode", title: "DEX bytecode (R8 state undecidable)", recovers: "the app logic as decompiled Java/Kotlin (jadx); too few defined classes to tell whether R8 renamed them", remediation: "enable R8 (`minifyEnabled true`) for release builds; it renames classes and members", avoidable: true, path, coverage: "detected-only", detail });
      else if (shortShare > 0.5)
        out.push({ analyzerId: this.id, rubricId: "code/near-source-bytecode", title: "DEX bytecode (R8-obfuscated names)", recovers: "the app logic as decompiled Java/Kotlin (jadx); class and member names appear R8-renamed, so symbolic readability is reduced but control flow and strings remain", remediation: "R8 raises the cost; it cannot hide logic or string constants — keep secrets off the device", avoidable: false, path, coverage: "detected-only", detail });
      else
        out.push({ analyzerId: this.id, rubricId: "code/near-source-bytecode", title: "DEX bytecode ships without R8 name obfuscation", recovers: "near-source Java/Kotlin with the original class, method and field names (jadx decompiles it directly)", remediation: "enable R8 for release builds (`minifyEnabled true`, no `-dontobfuscate`)", avoidable: true, path, coverage: "full", detail });
    }

    // AndroidManifest flags (binary XML; an AAB's protobuf manifest yields no facts, by design)
    const manifest = b.entry("AndroidManifest.xml");
    if (manifest) {
      const buf = b.read(manifest);
      if (buf) {
        const m = readAndroidManifest(buf);
        if (m.debuggable === true)
          out.push({ analyzerId: this.id, rubricId: "tamper/debuggable", title: 'android:debuggable="true"', recovers: "a debuggable build: anyone with the device can attach a debugger (jdb/Android Studio) to the running app and inspect its memory and state", remediation: 'remove `android:debuggable` (release build types set it false); never ship a debug build', avoidable: true, path: manifest.ref.path, coverage: "full", detail: root });
        if (m.allowBackup === true)
          out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: 'android:allowBackup="true"', recovers: "the app's private data can be pulled off the device with `adb backup` without root", remediation: 'set `android:allowBackup="false"` unless you ship a vetted backup agent / data-extraction rules', avoidable: true, path: manifest.ref.path, coverage: "full", detail: root });
      }
    }

    // Signing scheme. The APK Signing Block sits outside every entry, so this needs the container bytes.
    // An AAB is an upload artifact, always JAR-signed and re-signed by the store: no signing verdict.
    if (!isAab) {
      const raw = b.group.raw();
      if (raw) {
        const schemes = apkSigningSchemes(raw);
        const hasV1 = b.group.entries.some((e) => /^META-INF\/[^/]+\.(?:RSA|DSA|EC)$/i.test(rel(e))) && b.group.entries.some((e) => /^META-INF\/[^/]+\.SF$/i.test(rel(e)));
        if (schemes.size === 0 && hasV1)
          out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: "APK uses v1 (JAR) signing only", recovers: "v1 signatures cover entries one by one, not the archive: the APK is open to Janus-style tampering and the ZIP structure is unprotected", remediation: "sign with APK Signature Scheme v2/v3 (`apksigner`; the Android Gradle Plugin does this by default)", avoidable: true, path: root, coverage: "full", detail: "no APK Signing Block; META-INF JAR signature present" });
        else if (schemes.size === 0)
          out.push({ analyzerId: this.id, rubricId: "tamper/weak-protection", title: "APK is unsigned", recovers: "no signature protects the archive; anyone can modify it and re-sign it", remediation: "sign the release with `apksigner` (v2/v3)", avoidable: true, path: root, coverage: "full", detail: "no APK Signing Block and no META-INF JAR signature" });
      }
    }
    return out;
  },
};
