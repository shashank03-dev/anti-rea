/**
 * Checksums used by the container decoders. Implemented here (not via
 * `zlib.crc32`) so the package keeps working on Node 20, which lacks it.
 */
const CRC32_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++)
            c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c >>> 0;
    }
    return t;
})();
/** CRC-32 (IEEE 802.3, reflected), as used by zip, gzip and xz. */
export function crc32(buf, start = 0, end = buf.length) {
    let c = 0xffffffff;
    for (let i = start; i < end; i++)
        c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}
const CRC32_BE_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n << 24;
        for (let k = 0; k < 8; k++)
            c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : c << 1;
        t[n] = c >>> 0;
    }
    return t;
})();
/** CRC-32 with the same polynomial but MSB-first and unreflected, as used by bzip2. */
export function crc32be(buf, start = 0, end = buf.length) {
    let c = 0xffffffff;
    for (let i = start; i < end; i++)
        c = (c << 8) ^ CRC32_BE_TABLE[((c >>> 24) ^ buf[i]) & 0xff];
    return (c ^ 0xffffffff) >>> 0;
}
// CRC-64/XZ (ECMA-182 polynomial, reflected: 0xC96C5795D7870F42), held as two 32-bit halves.
const CRC64_LO = new Uint32Array(256);
const CRC64_HI = new Uint32Array(256);
(() => {
    const PLO = 0xd7870f42;
    const PHI = 0xc96c5795;
    for (let n = 0; n < 256; n++) {
        let lo = n;
        let hi = 0;
        for (let k = 0; k < 8; k++) {
            const lsb = lo & 1;
            lo = ((lo >>> 1) | ((hi & 1) << 31)) >>> 0;
            hi = hi >>> 1;
            if (lsb) {
                lo = (lo ^ PLO) >>> 0;
                hi = (hi ^ PHI) >>> 0;
            }
        }
        CRC64_LO[n] = lo;
        CRC64_HI[n] = hi;
    }
})();
/** CRC-64/XZ. Returns the 8 little-endian bytes as stored in an xz block check. */
export function crc64(buf, start = 0, end = buf.length) {
    let lo = 0xffffffff;
    let hi = 0xffffffff;
    for (let i = start; i < end; i++) {
        const idx = (lo ^ buf[i]) & 0xff;
        lo = (((lo >>> 8) | (hi << 24)) ^ CRC64_LO[idx]) >>> 0;
        hi = ((hi >>> 8) ^ CRC64_HI[idx]) >>> 0;
    }
    const out = Buffer.alloc(8);
    out.writeUInt32LE((lo ^ 0xffffffff) >>> 0, 0);
    out.writeUInt32LE((hi ^ 0xffffffff) >>> 0, 4);
    return out;
}
