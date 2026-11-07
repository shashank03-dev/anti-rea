import { crc32, deflateRawSync } from "node:zlib";

/**
 * Minimal container WRITERS, used to build fixtures and tests that exercise the
 * readers with real nested formats. Deterministic output (fixed timestamps).
 */

export interface PackFile {
  readonly path: string; // posix
  readonly data: Buffer;
}

/** Electron ASAR: [u32 4][u32 headerPickleSize][u32 payload][u32 strLen][json][pad] + file data. */
export function writeAsar(files: readonly PackFile[]): Buffer {
  type Node = { files: Record<string, Node> } | { size: number; offset: string };
  const root: { files: Record<string, Node> } = { files: {} };
  let offset = 0;
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : 1));
  for (const f of sorted) {
    const parts = f.path.split("/");
    let dir = root;
    for (const p of parts.slice(0, -1)) {
      const next = (dir.files[p] ??= { files: {} }) as { files: Record<string, Node> };
      dir = next;
    }
    dir.files[parts[parts.length - 1]!] = { size: f.data.length, offset: String(offset) };
    offset += f.data.length;
  }
  const json = Buffer.from(JSON.stringify(root), "utf8");
  const padded = Math.ceil(json.length / 4) * 4;
  const pickle = Buffer.alloc(8 + padded);
  pickle.writeUInt32LE(4 + padded, 0);
  pickle.writeUInt32LE(json.length, 4);
  json.copy(pickle, 8);
  const head = Buffer.alloc(8);
  head.writeUInt32LE(4, 0);
  head.writeUInt32LE(pickle.length, 4);
  return Buffer.concat([head, pickle, ...sorted.map((f) => f.data)]);
}

/** General-purpose bit 11 (APPNOTE 4.4.4): file names are UTF-8. Without it readers assume CP437. */
const UTF8_NAMES = 0x0800;

/** ZIP (deflate by default, stored with {store:true}). DOS time fixed to 1980-01-01. */
export function writeZip(files: readonly PackFile[], opts: { store?: boolean } = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let off = 0;
  for (const f of files) {
    const name = Buffer.from(f.path, "utf8");
    const method = opts.store ? 0 : 8;
    const comp = opts.store ? f.data : deflateRawSync(f.data);
    const crc = crc32(f.data) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(UTF8_NAMES, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0x21, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(f.data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    // "Version made by": host 3 (Unix). Host 0 (MS-DOS) tells readers the names are in the OEM code page,
    // and Info-ZIP UnZip then transcodes UTF-8 names into invalid bytes.
    ch.writeUInt16LE((3 << 8) | 20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(UTF8_NAMES, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(f.data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attributes: regular file, rw-r--r--
    ch.writeUInt32LE(off, 42);
    centrals.push(ch, name);
    off += 30 + name.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

/** ustar tar archive. */
export function writeTar(files: readonly PackFile[]): Buffer {
  const blocks: Buffer[] = [];
  for (const f of files) {
    const h = Buffer.alloc(512);
    h.write(f.path, 0, 100, "utf8");
    h.write("0000644\0", 100);
    h.write("0000000\0", 108);
    h.write("0000000\0", 116);
    h.write(f.data.length.toString(8).padStart(11, "0") + "\0", 124);
    h.write("00000000000\0", 136);
    h.write("        ", 148);
    h.write("0", 156);
    h.write("ustar\0", 257);
    h.write("00", 263);
    let sum = 0;
    for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
    blocks.push(h, f.data, Buffer.alloc((512 - (f.data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}
