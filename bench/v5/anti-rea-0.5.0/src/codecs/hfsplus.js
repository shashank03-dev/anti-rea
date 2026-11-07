import { DecodeError } from "./xz.js";
export function looksLikeHfsPlus(part) {
    if (part.length < 1536)
        return false;
    const sig = part.readUInt16BE(1024);
    return sig === 0x482b /* H+ */ || sig === 0x4858 /* HX */;
}
const KIND_LEAF = 0xff; // -1 as an unsigned byte
const HFS_PRIVATE = "\0\0\0\0HFS+ Private Data";
const DIR_PRIVATE = ".HFS+ Private Directory Data\r";
const UF_COMPRESSED = 0x20;
function readForkRecord(b, off) {
    const hi = b.readUInt32BE(off);
    const lo = b.readUInt32BE(off + 4);
    const logicalSize = hi * 2 ** 32 + lo;
    const totalBlocks = b.readUInt32BE(off + 12);
    const extents = [];
    for (let i = 0; i < 8; i++) {
        const start = b.readUInt32BE(off + 16 + i * 8);
        const count = b.readUInt32BE(off + 20 + i * 8);
        if (count > 0)
            extents.push({ start, count });
    }
    return { logicalSize, totalBlocks, extents };
}
/** Iterate the records of every leaf node of a B-tree file, following the leaf chain. */
function* leafRecords(tree) {
    if (tree.length < 512)
        throw new DecodeError("hfs+ b-tree too small");
    const nodeSize = tree.readUInt16BE(32);
    if (nodeSize < 512 || nodeSize > 32768 || nodeSize & (nodeSize - 1))
        throw new DecodeError("hfs+ b-tree node size invalid");
    const totalNodes = tree.readUInt32BE(36);
    let n = tree.readUInt32BE(24); // firstLeafNode
    const seen = new Set();
    while (n !== 0) {
        if (seen.has(n) || n >= totalNodes || (n + 1) * nodeSize > tree.length)
            throw new DecodeError("hfs+ b-tree leaf chain is corrupt");
        seen.add(n);
        const node = tree.subarray(n * nodeSize, (n + 1) * nodeSize);
        if (node[8] !== KIND_LEAF)
            throw new DecodeError("hfs+ b-tree leaf chain reaches a non-leaf node");
        const numRecords = node.readUInt16BE(10);
        for (let i = 0; i < numRecords; i++) {
            const off = node.readUInt16BE(nodeSize - 2 * (i + 1));
            if (off < 14 || off >= nodeSize)
                throw new DecodeError("hfs+ b-tree record offset out of range");
            yield { node, off };
        }
        n = node.readUInt32BE(0); // fLink
    }
}
const name16 = (b, off, len) => {
    if (off + len * 2 > b.length)
        throw new DecodeError("hfs+ name out of range");
    let s = "";
    for (let i = 0; i < len; i++)
        s += String.fromCharCode(b.readUInt16BE(off + i * 2));
    return s;
};
export function readHfsPlus(part, limits) {
    if (!looksLikeHfsPlus(part))
        throw new DecodeError("no HFS+ volume header");
    const vh = part.subarray(1024, 1536);
    const blockSize = vh.readUInt32BE(40);
    const totalBlocks = vh.readUInt32BE(44);
    if (blockSize < 512 || blockSize & (blockSize - 1))
        throw new DecodeError("hfs+ block size invalid");
    const notes = [];
    const covered = new Uint8Array(totalBlocks);
    const cover = (ext) => {
        for (const e of ext)
            for (let i = e.start; i < e.start + e.count && i < totalBlocks; i++)
                covered[i] = 1;
    };
    const extentBytes = (fork, ext) => {
        if (fork.logicalSize > limits.maxEntryBytes)
            throw new DecodeError("fork too large");
        const parts = [];
        let have = 0;
        for (const e of ext) {
            const start = e.start * blockSize;
            const end = start + e.count * blockSize;
            if (end > part.length)
                throw new DecodeError("hfs+ extent outside the volume");
            parts.push(part.subarray(start, end));
            have += end - start;
            if (have >= fork.logicalSize)
                break;
        }
        if (have < fork.logicalSize)
            throw new DecodeError("hfs+ fork shorter than its logical size");
        const all = parts.length === 1 ? parts[0] : Buffer.concat(parts, have);
        return all.subarray(0, fork.logicalSize);
    };
    // System files. The extents-overflow file cannot itself overflow.
    const extentsFork = readForkRecord(vh, 192);
    const catalogFork = readForkRecord(vh, 272);
    const attributesFork = readForkRecord(vh, 352);
    for (const off of [112, 192, 272, 352, 432])
        cover(readForkRecord(vh, off).extents);
    const extentsTree = extentsFork.logicalSize > 0 ? extentBytes(extentsFork, extentsFork.extents) : null;
    const overflow = new Map(); // `${fileID}:${forkType}` -> extents, in file order
    if (extentsTree) {
        const recs = [];
        for (const { node, off } of leafRecords(extentsTree)) {
            if (node.readUInt16BE(off) !== 10)
                throw new DecodeError("hfs+ extents key length invalid");
            const forkType = node[off + 2];
            const fileID = node.readUInt32BE(off + 4);
            const startBlock = node.readUInt32BE(off + 8);
            const ext = [];
            for (let i = 0; i < 8; i++) {
                const count = node.readUInt32BE(off + 16 + i * 8);
                if (count > 0)
                    ext.push({ start: node.readUInt32BE(off + 12 + i * 8), count });
            }
            recs.push({ key: `${fileID}:${forkType}`, startBlock, ext });
        }
        recs.sort((a, b) => (a.key === b.key ? a.startBlock - b.startBlock : a.key < b.key ? -1 : 1));
        for (const r of recs)
            (overflow.get(r.key) ?? overflow.set(r.key, []).get(r.key)).push(...r.ext);
    }
    const allExtents = (fork, fileID, forkType) => {
        const ext = [...fork.extents];
        let blocks = ext.reduce((s, e) => s + e.count, 0);
        if (blocks < fork.totalBlocks) {
            ext.push(...(overflow.get(`${fileID}:${forkType}`) ?? []));
            blocks = ext.reduce((s, e) => s + e.count, 0);
            if (blocks < fork.totalBlocks)
                throw new DecodeError("hfs+ fork extents incomplete");
        }
        return ext;
    };
    const catExt = allExtents(catalogFork, 4, 0);
    cover(catExt);
    const catalog = extentBytes(catalogFork, catExt);
    // Catalog: folders, files, hard-link targets.
    const folders = new Map();
    const files = [];
    let volume = "";
    for (const { node, off } of leafRecords(catalog)) {
        const keyLength = node.readUInt16BE(off);
        const parent = node.readUInt32BE(off + 2);
        const nameLen = node.readUInt16BE(off + 6);
        const name = name16(node, off + 8, nameLen).replace(/\//g, ":").normalize("NFC");
        const d = off + 2 + keyLength;
        if (d + 2 > node.length)
            throw new DecodeError("hfs+ catalog record out of range");
        const recordType = node.readUInt16BE(d);
        if (recordType === 1) {
            const id = node.readUInt32BE(d + 8);
            folders.set(id, { parent, name });
            if (id === 2)
                volume = name;
        }
        else if (recordType === 2) {
            if (d + 248 > node.length)
                throw new DecodeError("hfs+ file record truncated");
            files.push({
                parent,
                name,
                fileID: node.readUInt32BE(d + 8),
                ownerFlags: node[d + 41],
                mode: node.readUInt16BE(d + 42),
                special: node.readUInt32BE(d + 44),
                type: node.toString("latin1", d + 48, d + 52),
                creator: node.toString("latin1", d + 52, d + 56),
                data: readForkRecord(node, d + 88),
                rsrc: readForkRecord(node, d + 168),
            });
        }
    }
    const pathOf = (folderID) => {
        const segs = [];
        const seen = new Set();
        let id = folderID;
        while (id !== 2) {
            const f = folders.get(id);
            if (!f || seen.has(id))
                return null;
            seen.add(id);
            segs.push(f.name);
            id = f.parent;
        }
        return segs.reverse().join("/");
    };
    const privateId = [...folders].find(([, f]) => f.parent === 2 && f.name === HFS_PRIVATE)?.[0];
    const inodes = new Map();
    if (privateId !== undefined)
        for (const f of files)
            if (f.parent === privateId)
                inodes.set(f.name, f);
    const usedInodes = new Set();
    const entries = [];
    const push = (e) => {
        if (entries.length >= limits.maxEntries)
            throw new DecodeError("hfs+ entry count exceeds limit");
        entries.push(e);
    };
    const emitFork = (name, f, fork, forkType) => {
        let ext;
        try {
            ext = allExtents(fork, f.fileID, forkType);
        }
        catch (e) {
            push({ name, data: null, reason: e.message });
            return;
        }
        cover(ext);
        if (fork.logicalSize > limits.maxEntryBytes) {
            push({ name, data: null, reason: `entry size ${fork.logicalSize} exceeds limit` });
            return;
        }
        try {
            push({ name, data: extentBytes(fork, ext) });
        }
        catch (e) {
            push({ name, data: null, reason: e.message });
        }
    };
    const emitFile = (path, f) => {
        if (f.ownerFlags & UF_COMPRESSED) {
            cover(f.data.extents);
            cover(f.rsrc.extents);
            push({ name: path, data: null, reason: "HFS+-compressed file (decmpfs) is not supported" });
            return;
        }
        emitFork(path, f, f.data, 0x00);
        if (f.rsrc.logicalSize > 0)
            emitFork(`${path}/..namedfork/rsrc`, f, f.rsrc, 0xff);
    };
    let symlinks = 0;
    let dirLinks = 0;
    for (const f of files) {
        if (f.parent === privateId)
            continue; // iNode targets are emitted under their links' paths
        const dir = pathOf(f.parent);
        if (dir === null) {
            push({ name: `(orphaned)/${f.name}`, data: null, reason: "hfs+ file whose folder is missing from the catalog" });
            continue;
        }
        if (dir.split("/")[0] === DIR_PRIVATE) {
            dirLinks++;
            continue;
        }
        const path = dir ? `${dir}/${f.name}` : f.name;
        if ((f.mode & 0xf000) === 0xa000) {
            symlinks++; // a symlink's data fork is its target path; the target, if inside the volume, is read as itself
            cover(f.data.extents);
            continue;
        }
        if (f.type === "hlnk" && f.creator === "hfs+") {
            const target = inodes.get(`iNode${f.special}`);
            if (!target) {
                push({ name: path, data: null, reason: "hfs+ hard link whose iNode file is missing" });
                continue;
            }
            usedInodes.add(target.name);
            emitFile(path, target);
            continue;
        }
        if (f.type === "fdrp" && f.creator === "MACS") {
            dirLinks++;
            continue;
        }
        emitFile(path, f);
    }
    for (const [n, f] of inodes)
        if (!usedInodes.has(n))
            emitFile(`(hfs+ private data)/${n}`, f);
    if (symlinks > 0)
        notes.push(`${symlinks} symbolic link(s) not followed`);
    if (dirLinks > 0)
        notes.push(`${dirLinks} directory hard link(s) not followed; their targets are read in place`);
    // Extended attributes can carry arbitrary values; scan the attributes B-tree as raw bytes.
    if (attributesFork.logicalSize > 0) {
        try {
            const ext = allExtents(attributesFork, 8, 0);
            cover(ext);
            push({ name: "(hfs+ extended attributes)", data: extentBytes(attributesFork, ext) });
        }
        catch (e) {
            push({ name: "(hfs+ extended attributes)", data: null, reason: e.message });
        }
    }
    // Bytes in blocks no file owns (residue of deleted files) are still shipped: scan any that are non-zero.
    covered[0] = 1; // volume header block
    if (totalBlocks > 0)
        covered[totalBlocks - 1] = 1; // alternate volume header
    const residue = [];
    let residueBytes = 0;
    for (let i = 0; i < totalBlocks; i++) {
        if (covered[i])
            continue;
        const start = i * blockSize;
        if (start >= part.length)
            break;
        const blk = part.subarray(start, Math.min(start + blockSize, part.length));
        let nonzero = false;
        for (let j = 0; j < blk.length; j++)
            if (blk[j] !== 0) {
                nonzero = true;
                break;
            }
        if (!nonzero)
            continue;
        residueBytes += blk.length;
        if (residueBytes > limits.maxEntryBytes) {
            push({ name: "(hfs+ unallocated space)", data: null, reason: "non-zero unallocated space exceeds entry limit" });
            residue.length = 0;
            break;
        }
        residue.push(blk);
    }
    if (residue.length > 0) {
        notes.push(`${residue.length} non-zero unallocated block(s) scanned as "(hfs+ unallocated space)"`);
        push({ name: "(hfs+ unallocated space)", data: Buffer.concat(residue) });
    }
    return { volume, entries, notes };
}
