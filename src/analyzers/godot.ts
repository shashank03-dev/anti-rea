import type { Analyzer, AnalyzerContext, ItemContext, ProfileTags, RawFinding } from "./types.js";

/**
 * godot (item scope): a Godot resource pack lists its entries by `res://` path — standalone (`GDPC` magic
 * at offset 0) or embedded in the exported executable (located by the trailer: a u64 pack size and the
 * `GDPC` magic as the file's last 12 bytes; a bare search for "GDPC" would hit the constant in the
 * engine's own code). Shipping `.gd` GDScript is original source text; `.gdc` is tokenised bytecode that
 * decompiles back to near-source; `.gde` and an encrypted directory are reported detected-only.
 *
 * Layout: magic, format, engine major/minor/patch; format ≥ 2 adds pack flags (bit 0 = directory
 * encrypted) and a u64 file base; format ≥ 3 adds a u64 directory offset; then 16 reserved u32, the file
 * count and the entries (u32 path length, path, u64 offset, u64 size, md5, and u32 flags from format 2).
 * Entries are sanity-checked (`res://` paths): a pack whose directory does not decode is reported as such.
 */

const MAGIC = Buffer.from("GDPC", "latin1");

interface Pck {
  format: number;
  encrypted: boolean;
  entries: string[];
}

function readPck(b: Buffer, start: number): Pck | null {
  const u32 = (o: number) => (o >= 0 && o + 4 <= b.length ? b.readUInt32LE(o) : -1);
  const u64 = (o: number) => (o >= 0 && o + 8 <= b.length ? Number(b.readBigUInt64LE(o)) : -1);
  if (start < 0 || start + 16 > b.length || !b.subarray(start, start + 4).equals(MAGIC)) return null;
  const format = u32(start + 4);
  if (format < 0 || format > 16) return null;
  let p = start + 20; // magic + format + major/minor/patch
  let encrypted = false;
  let dirOffset = 0;
  if (format >= 2) {
    encrypted = (u32(p) & 0x1) !== 0;
    p += 4 + 8; // pack flags + file base
    if (format >= 3) {
      dirOffset = Math.max(0, u64(p));
      p += 8;
    }
  }
  p += 16 * 4; // reserved
  if (dirOffset > 0 && start + dirOffset < b.length) p = start + dirOffset;
  const count = u32(p);
  p += 4;
  const entries: string[] = [];
  if (encrypted) return { format, encrypted, entries };
  for (let i = 0; i < Math.min(Math.max(count, 0), 200_000); i++) {
    const pathLen = u32(p);
    p += 4;
    if (pathLen < 0 || pathLen > 4096 || p + pathLen > b.length) break;
    entries.push(b.toString("utf8", p, p + pathLen).replace(/\0+$/, ""));
    p += pathLen + 8 + 8 + 16 + (format >= 2 ? 4 : 0);
  }
  return { format, encrypted, entries: entries.filter((e) => e.startsWith("res://") || e.startsWith("user://")) };
}

/** Where the pack starts: offset 0 for a .pck, or the embedded-pack trailer of an exported executable. */
function packStart(b: Buffer): number {
  if (b.length >= 16 && b.subarray(0, 4).equals(MAGIC)) return 0;
  if (b.length >= 32 && b.subarray(b.length - 4).equals(MAGIC)) {
    const size = Number(b.readBigUInt64LE(b.length - 12));
    const start = b.length - 12 - size;
    if (start >= 0 && b.subarray(start, start + 4).equals(MAGIC)) return start;
  }
  return -1;
}

export const godot: Analyzer = {
  id: "godot",
  title: "Godot resource pack (.pck)",
  mirrorsRea: "Godot PCK unpacking / GDScript recovery",
  scope: "item",
  needs: { full: true },

  detect(ctx: AnalyzerContext): boolean {
    return ctx.scope === "item" && packStart(ctx.bytes) >= 0;
  },

  profile(): ProfileTags {
    return { frameworks: ["Godot"] };
  },

  analyze(ctx: AnalyzerContext): RawFinding[] {
    const { item, bytes } = ctx as ItemContext;
    const path = item.ref.path;
    const start = packStart(bytes);
    const pck = readPck(bytes, start);
    if (!pck) return [];
    const where = `${path}: Godot pack format ${pck.format}${start > 0 ? `, embedded at 0x${start.toString(16)}` : ""}`;
    if (pck.encrypted)
      return [{ analyzerId: this.id, rubricId: "symbols/inherent", title: "Godot pack directory is encrypted", recovers: "an encrypted pack directory: entry names and contents are not readable without the key", remediation: "appears protected (PACK_DIR_ENCRYPTED); the key is compiled into the export template, so keep that template build private", avoidable: false, path, coverage: "detected-only", detail: where }];
    if (pck.entries.length === 0)
      return [{ analyzerId: this.id, rubricId: "symbols/inherent", title: "Godot pack (directory not decoded)", recovers: "a Godot resource pack whose directory this version could not decode; treat its scripts as recoverable", remediation: "export scripts as binary tokens and enable pack encryption if the scripts are sensitive", avoidable: false, path, coverage: "detected-only", detail: where }];
    const out: RawFinding[] = [];
    const gd = pck.entries.filter((e) => /\.gd$/i.test(e));
    const gdc = pck.entries.filter((e) => /\.gdc$/i.test(e));
    const gde = pck.entries.filter((e) => /\.gde$/i.test(e));
    if (gd.length > 0)
      out.push({ analyzerId: this.id, rubricId: "code/source-text", title: "Godot pack ships GDScript source (.gd)", recovers: `${gd.length} GDScript source file(s) in plain text, e.g. ${gd[0]}`, remediation: "export GDScript as binary tokens (Export > Script > Binary tokens) and/or enable pack encryption; note binary tokens still decompile", avoidable: true, path, coverage: "full", detail: `${where}; ${gd.length} .gd file(s)` });
    if (gdc.length > 0)
      out.push({ analyzerId: this.id, rubricId: "code/near-source-bytecode", title: "Godot pack ships tokenised GDScript (.gdc)", recovers: `${gdc.length} compiled GDScript file(s); the token stream decompiles back to near-source with public tools`, remediation: "enable pack encryption if the scripts are sensitive; decompilation of binary tokens remains possible", avoidable: true, path, coverage: "full", detail: `${where}; ${gdc.length} .gdc file(s)` });
    if (gde.length > 0)
      out.push({ analyzerId: this.id, rubricId: "symbols/inherent", title: "Godot pack ships encrypted scripts (.gde)", recovers: `${gde.length} encrypted GDScript file(s); not readable without the export key`, remediation: "appears protected; keep the encryption key out of shipped files", avoidable: false, path, coverage: "detected-only", detail: `${where}; ${gde.length} .gde file(s)` });
    return out;
  },
};
