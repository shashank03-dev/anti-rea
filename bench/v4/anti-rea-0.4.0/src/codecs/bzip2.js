import { crc32be } from "./crc.js";
import { DecodeError, LimitError, Out } from "./xz.js";
/**
 * Zero-dependency bzip2 decoder: Huffman/MTF/RLE2 → inverse BWT → RLE1.
 *
 * It follows the reference implementation's bitstream (bzip2 1.0.8,
 * decompress.c). Each block CRC and the stream's combined CRC are verified, and
 * concatenated streams (as written by pbzip2/lbzip2) are supported. Blocks
 * using the "randomised" mode, which only bzip2 0.9.0 produced, are rejected
 * explicitly rather than decoded wrongly.
 */
const MAX_GROUPS = 6;
const MAX_SELECTORS = 18002;
const MAX_CODE_LEN = 20;
const GROUP_SIZE = 50;
class BitReader {
    b;
    pos; // bit position
    constructor(b, byteStart) {
        this.b = b;
        this.pos = byteStart * 8;
    }
    bit() {
        const byte = this.b[this.pos >>> 3];
        if (byte === undefined)
            throw new DecodeError("bzip2 data truncated");
        const v = (byte >>> (7 - (this.pos & 7))) & 1;
        this.pos++;
        return v;
    }
    bits(n) {
        let v = 0;
        for (let i = 0; i < n; i++)
            v = v * 2 + this.bit();
        return v;
    }
}
function buildHuffman(lengths) {
    const count = new Uint16Array(MAX_CODE_LEN + 1);
    for (const l of lengths)
        count[l]++;
    const offs = new Uint16Array(MAX_CODE_LEN + 2);
    for (let l = 1; l <= MAX_CODE_LEN; l++)
        offs[l + 1] = offs[l] + count[l];
    const symbol = new Uint16Array(lengths.length);
    for (let s = 0; s < lengths.length; s++)
        symbol[offs[lengths[s]]++] = s;
    // Reject over-subscribed code sets: they cannot come from a real encoder.
    let left = 1;
    for (let l = 1; l <= MAX_CODE_LEN; l++) {
        left = left * 2 - count[l];
        if (left < 0)
            throw new DecodeError("bzip2 Huffman table is over-subscribed");
    }
    return { count, symbol };
}
function decodeSymbol(br, h) {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let len = 1; len <= MAX_CODE_LEN; len++) {
        code |= br.bit();
        const c = h.count[len];
        if (code - first < c)
            return h.symbol[index + code - first];
        index += c;
        first = (first + c) << 1;
        code <<= 1;
    }
    throw new DecodeError("invalid bzip2 Huffman code");
}
function decodeBlock(br, blockMax, tt, out) {
    const storedCrc = br.bits(32);
    if (br.bit() === 1)
        throw new DecodeError("randomised bzip2 blocks (bzip2 0.9.0) are not supported");
    const origPtr = br.bits(24);
    // Symbol map
    const used = br.bits(16);
    const seqToUnseq = [];
    for (let i = 0; i < 16; i++) {
        if (used & (0x8000 >>> i)) {
            const u = br.bits(16);
            for (let j = 0; j < 16; j++)
                if (u & (0x8000 >>> j))
                    seqToUnseq.push(i * 16 + j);
        }
    }
    if (seqToUnseq.length === 0)
        throw new DecodeError("bzip2 block uses no symbols");
    const alphaSize = seqToUnseq.length + 2;
    const nGroups = br.bits(3);
    if (nGroups < 2 || nGroups > MAX_GROUPS)
        throw new DecodeError("invalid bzip2 Huffman group count");
    const nSelectorsRaw = br.bits(15);
    if (nSelectorsRaw < 1)
        throw new DecodeError("invalid bzip2 selector count");
    const nSelectors = Math.min(nSelectorsRaw, MAX_SELECTORS);
    const selectors = new Uint8Array(nSelectors);
    const mtfGroups = Array.from({ length: nGroups }, (_, i) => i);
    for (let i = 0; i < nSelectorsRaw; i++) {
        let j = 0;
        while (br.bit() === 1)
            if (++j >= nGroups)
                throw new DecodeError("invalid bzip2 selector");
        const v = mtfGroups[j];
        mtfGroups.splice(j, 1);
        mtfGroups.unshift(v);
        if (i < MAX_SELECTORS)
            selectors[i] = v;
    }
    const tables = [];
    for (let t = 0; t < nGroups; t++) {
        const lengths = new Uint8Array(alphaSize);
        let curr = br.bits(5);
        for (let i = 0; i < alphaSize; i++) {
            for (;;) {
                if (curr < 1 || curr > MAX_CODE_LEN)
                    throw new DecodeError("invalid bzip2 code length");
                if (br.bit() === 0)
                    break;
                curr += br.bit() === 0 ? 1 : -1;
            }
            lengths[i] = curr;
        }
        tables.push(buildHuffman(lengths));
    }
    // Huffman → RLE2 (RUNA/RUNB) → MTF
    const mtf = new Uint8Array(256);
    for (let i = 0; i < 256; i++)
        mtf[i] = i;
    const counts = new Uint32Array(256);
    const eob = seqToUnseq.length + 1;
    let n = 0;
    let groupLeft = 0;
    let groupIdx = -1;
    let table = tables[0];
    let run = 0;
    let weight = 1;
    for (;;) {
        if (groupLeft === 0) {
            if (++groupIdx >= nSelectors)
                throw new DecodeError("bzip2 selectors exhausted");
            table = tables[selectors[groupIdx]];
            groupLeft = GROUP_SIZE;
        }
        groupLeft--;
        const sym = decodeSymbol(br, table);
        if (sym <= 1) {
            run += (sym + 1) * weight;
            weight *= 2;
            if (run > blockMax)
                throw new DecodeError("bzip2 run exceeds block size");
            continue;
        }
        if (run > 0) {
            if (n + run > blockMax)
                throw new DecodeError("bzip2 block exceeds declared size");
            const uc = seqToUnseq[mtf[0]];
            counts[uc] += run;
            tt.fill(uc, n, n + run);
            n += run;
            run = 0;
            weight = 1;
        }
        if (sym === eob)
            break;
        if (sym > eob)
            throw new DecodeError("invalid bzip2 symbol");
        const idx = sym - 1;
        const v = mtf[idx];
        mtf.copyWithin(1, 0, idx);
        mtf[0] = v;
        const uc = seqToUnseq[v];
        if (uc === undefined)
            throw new DecodeError("invalid bzip2 MTF index");
        if (n >= blockMax)
            throw new DecodeError("bzip2 block exceeds declared size");
        counts[uc]++;
        tt[n++] = uc;
    }
    if (n === 0)
        throw new DecodeError("empty bzip2 block");
    if (origPtr >= n)
        throw new DecodeError("bzip2 origin pointer out of range");
    // Inverse BWT
    const cftab = new Uint32Array(256);
    for (let i = 1; i < 256; i++)
        cftab[i] = cftab[i - 1] + counts[i - 1];
    for (let i = 0; i < n; i++) {
        const b = tt[i] & 0xff;
        tt[cftab[b]] |= i << 8;
        cftab[b]++;
    }
    // Undo RLE1 while walking the BWT chain, computing the block CRC on the fly.
    const start = out.pos;
    let tPos = tt[origPtr] >>> 8;
    let last = -1;
    let same = 0;
    for (let k = 0; k < n; k++) {
        const e = tt[tPos];
        const b = e & 0xff;
        tPos = e >>> 8;
        if (same === 4) {
            out.ensure(b);
            out.buf.fill(last, out.pos, out.pos + b);
            out.pos += b;
            same = 0;
            last = -1;
            continue;
        }
        out.ensure(1);
        out.buf[out.pos++] = b;
        if (b === last)
            same++;
        else {
            last = b;
            same = 1;
        }
    }
    const crc = crc32be(out.buf, start, out.pos);
    if (crc !== storedCrc)
        throw new DecodeError("bzip2 block CRC mismatch");
    return crc;
}
export function looksLikeBzip2(buf) {
    return buf.length >= 10 && buf[0] === 0x42 && buf[1] === 0x5a && buf[2] === 0x68 && buf[3] >= 0x31 && buf[3] <= 0x39;
}
/**
 * Decompress a .bz2 file. Bytes after the last stream are returned as
 * `trailing` so the caller can still inspect them, instead of dropping them.
 */
export function bzip2Decompress(src, maxOutput) {
    const out = new Out(src.length * 4, maxOutput);
    let ip = 0;
    let streams = 0;
    let tt = null;
    while (ip < src.length) {
        if (!looksLikeBzip2(src.subarray(ip))) {
            if (streams === 0)
                throw new DecodeError("not a bzip2 stream");
            break;
        }
        const blockMax = (src[ip + 3] - 0x30) * 100_000;
        if (!tt || tt.length < blockMax)
            tt = new Uint32Array(blockMax);
        const br = new BitReader(src, ip + 4);
        let combined = 0;
        for (;;) {
            const m1 = br.bits(24);
            const m2 = br.bits(24);
            if (m1 === 0x314159 && m2 === 0x265359) {
                const view = tt.subarray(0, blockMax);
                view.fill(0);
                const crc = decodeBlock(br, blockMax, view, out);
                combined = (((combined << 1) | (combined >>> 31)) ^ crc) >>> 0;
            }
            else if (m1 === 0x177245 && m2 === 0x385090) {
                if (br.bits(32) !== combined)
                    throw new DecodeError("bzip2 stream CRC mismatch");
                break;
            }
            else {
                throw new DecodeError("invalid bzip2 block header");
            }
        }
        ip = Math.ceil(br.pos / 8);
        streams++;
    }
    const trailing = ip < src.length ? Buffer.from(src.subarray(ip)) : null;
    return { data: out.result(), trailing: trailing && trailing.some((b) => b !== 0) ? trailing : null };
}
export { DecodeError, LimitError };
