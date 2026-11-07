/* p2ptun web client: QR Code Model 2 encoder (ISO/IEC 18004), no dependencies.
 *
 * Used to show the WireGuard config so the phone app can import it with "+ -> Scan from QR code".
 * Byte mode (UTF-8), versions 1-40, error correction L/M/Q/H, mask chosen by the standard
 * penalty rules. Works in browsers (window.P2PQR) and Node (require), which the tests use.
 *
 *   const qr = P2PQR.encode(text, { ecc: "M" });  // {size, modules[y][x], version, ecc, mask}
 *   el.append(P2PQR.toSvg(qr, document, { scale: 4, margin: 4 }));
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.P2PQR = api;
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  // ISO/IEC 18004 Table 9, indexed by version (1..40): error correction codewords per block and
  // number of blocks. Data codewords per block follow from the version's total codeword count.
  const ECC_PER_BLOCK = {
    L: [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    M: [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
    Q: [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    H: [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  };
  const NUM_BLOCKS = {
    L: [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    M: [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
    Q: [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
    H: [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
  };
  const FORMAT_ECC_BITS = { L: 1, M: 0, Q: 3, H: 2 };

  // ------------------------------------------------------------------ GF(256), Reed-Solomon
  // Field polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d), generator element alpha = 2.
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  for (let i = 0, x = 1; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  const gfMul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

  const generators = {};
  // g(x) = (x - a^0)(x - a^1)...(x - a^(n-1)), coefficients highest degree first (g[0] = 1).
  function rsGenerator(n) {
    if (generators[n]) return generators[n];
    let g = [1];
    for (let i = 0; i < n; i++) {
      const next = new Array(g.length + 1).fill(0);
      for (let j = 0; j < g.length; j++) {
        next[j] ^= g[j];
        next[j + 1] ^= gfMul(g[j], EXP[i]);
      }
      g = next;
    }
    return (generators[n] = g);
  }

  // Remainder of data(x) * x^n divided by g(x): the n error correction codewords of a block.
  function rsRemainder(data, n) {
    const g = rsGenerator(n);
    const r = new Uint8Array(data.length + n);
    r.set(data);
    for (let i = 0; i < data.length; i++) {
      const c = r[i];
      if (c) for (let j = 1; j <= n; j++) r[i + j] ^= gfMul(g[j], c);
    }
    return r.subarray(data.length);
  }

  // ------------------------------------------------------------------ capacity
  // Modules left for codewords (data + EC + remainder bits) after all function patterns,
  // format and version information are placed.
  function rawDataModules(v) {
    let n = (16 * v + 128) * v + 64;
    if (v >= 2) {
      const align = Math.floor(v / 7) + 2;
      n -= (25 * align - 10) * align - 55;
      if (v >= 7) n -= 36;
    }
    return n;
  }
  const totalCodewords = (v) => rawDataModules(v) >> 3;
  const dataCodewords = (v, ecc) => totalCodewords(v) - ECC_PER_BLOCK[ecc][v] * NUM_BLOCKS[ecc][v];
  const countBits = (v) => (v <= 9 ? 8 : 16); // byte mode character count indicator length
  // Bytes that fit in byte mode: mode indicator (4 bits) + count + 8 bits per byte.
  const byteCapacity = (v, ecc) => (dataCodewords(v, ecc) * 8 - 4 - countBits(v)) >> 3;

  // ------------------------------------------------------------------ codewords
  function utf8(text) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text);
    const out = [];
    for (let i = 0; i < text.length; i++) {
      let c = text.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
        const d = text.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
      }
      if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd; // lone surrogate, as TextEncoder does
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return Uint8Array.from(out);
  }

  // Data codewords (byte mode segment, terminator, padding) split into blocks, each followed by
  // its Reed-Solomon codewords, interleaved as in ISO/IEC 18004 7.6.
  function codewords(bytes, v, ecc) {
    const nData = dataCodewords(v, ecc);
    const data = new Uint8Array(nData);
    let bit = 0;
    const put = (val, len) => {
      for (let i = len - 1; i >= 0; i--, bit++) if ((val >>> i) & 1) data[bit >> 3] |= 0x80 >> (bit & 7);
    };
    put(0b0100, 4);
    put(bytes.length, countBits(v));
    for (const b of bytes) put(b, 8);
    bit += Math.min(4, nData * 8 - bit); // terminator (zeros)
    bit = (bit + 7) & ~7;                // zero bits up to a byte boundary
    for (let i = bit >> 3, pad = 0xec; i < nData; i++, pad ^= 0xec ^ 0x11) data[i] = pad;

    const nBlocks = NUM_BLOCKS[ecc][v], nEcc = ECC_PER_BLOCK[ecc][v], total = totalCodewords(v);
    const nShort = nBlocks - (total % nBlocks);                  // short blocks come first
    const shortLen = Math.floor(total / nBlocks) - nEcc;         // data codewords in a short block
    const blocks = [], eccs = [];
    for (let i = 0, k = 0; i < nBlocks; i++) {
      const len = shortLen + (i < nShort ? 0 : 1);
      const blk = data.subarray(k, k + len);
      k += len;
      blocks.push(blk);
      eccs.push(rsRemainder(blk, nEcc));
    }
    const out = [];
    for (let i = 0; i <= shortLen; i++) for (const blk of blocks) if (i < blk.length) out.push(blk[i]);
    for (let i = 0; i < nEcc; i++) for (const e of eccs) out.push(e[i]);
    return out;
  }

  // ------------------------------------------------------------------ matrix
  // Alignment pattern centre coordinates (ISO/IEC 18004 Annex E).
  function alignmentPositions(v) {
    if (v === 1) return [];
    const n = Math.floor(v / 7) + 2, size = v * 4 + 17;
    const step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2;
    const out = [6];
    for (let p = size - 7; out.length < n; p -= step) out.splice(1, 0, p);
    return out;
  }

  // 15-bit format information: 2 bits EC level + 3 bits mask, BCH(15,5), XOR 0x5412.
  function formatBits(ecc, mask) {
    const data = (FORMAT_ECC_BITS[ecc] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return ((data << 10) | (rem & 0x3ff)) ^ 0x5412;
  }

  // 18-bit version information (v >= 7): 6 bits version, BCH(18,6).
  function versionBits(v) {
    let rem = v;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    return (v << 12) | (rem & 0xfff);
  }

  function maskBit(mask, x, y) { // x = column, y = row
    switch (mask) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
      case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 1;
    }
    throw new Error("bad mask");
  }

  class Matrix {
    constructor(v) {
      const size = (this.size = v * 4 + 17);
      this.dark = Array.from({ length: size }, () => new Array(size).fill(false));
      this.fn = Array.from({ length: size }, () => new Array(size).fill(false));

      for (let i = 0; i < size; i++) { this.set(6, i, i % 2 === 0); this.set(i, 6, i % 2 === 0); } // timing
      for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {                             // finders + separators
        for (let dy = -4; dy <= 4; dy++) {
          for (let dx = -4; dx <= 4; dx++) {
            const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
            if (x >= 0 && y >= 0 && x < size && y < size) this.set(x, y, d !== 2 && d !== 4);
          }
        }
      }
      const al = alignmentPositions(v), last = al.length - 1;
      for (let i = 0; i <= last; i++) {
        for (let j = 0; j <= last; j++) {
          if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue; // under finders
          for (let dy = -2; dy <= 2; dy++) {
            for (let dx = -2; dx <= 2; dx++) this.set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
          }
        }
      }
      this.drawFormat(0); // reserves the format areas and the dark module; redrawn per mask
      if (v >= 7) {
        const bits = versionBits(v);
        for (let i = 0; i < 18; i++) {
          const on = ((bits >>> i) & 1) === 1, a = size - 11 + (i % 3), b = Math.floor(i / 3);
          this.set(a, b, on); // top right
          this.set(b, a, on); // bottom left
        }
      }
    }

    set(x, y, on) { this.dark[y][x] = on; this.fn[y][x] = true; }

    drawFormat(bits) {
      const n = this.size, bit = (i) => ((bits >>> i) & 1) === 1;
      for (let i = 0; i <= 5; i++) this.set(8, i, bit(i)); // around the top-left finder
      this.set(8, 7, bit(6));
      this.set(8, 8, bit(7));
      this.set(7, 8, bit(8));
      for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) this.set(n - 1 - i, 8, bit(i)); // second copy: top right ...
      for (let i = 8; i < 15; i++) this.set(8, n - 15 + i, bit(i)); // ... and bottom left
      this.set(8, n - 8, true); // dark module
    }

    // Codeword bits in two-module-wide columns, zig-zagging up and down from the bottom right,
    // skipping function modules and the vertical timing column. Remainder bits stay light.
    placeData(cw) {
      const n = this.size, nbits = cw.length * 8;
      let i = 0;
      for (let right = n - 1; right >= 1; right -= 2) {
        if (right === 6) right = 5;
        const upward = ((right + 1) & 2) === 0;
        for (let vert = 0; vert < n; vert++) {
          const y = upward ? n - 1 - vert : vert;
          for (let j = 0; j < 2; j++) {
            const x = right - j;
            if (this.fn[y][x]) continue;
            this.dark[y][x] = i < nbits && ((cw[i >> 3] >>> (7 - (i & 7))) & 1) === 1;
            i++;
          }
        }
      }
    }

    applyMask(mask) { // XOR, so applying twice undoes it
      const n = this.size;
      for (let y = 0; y < n; y++) {
        for (let x = 0; x < n; x++) if (!this.fn[y][x] && maskBit(mask, x, y)) this.dark[y][x] = !this.dark[y][x];
      }
    }

    // ISO/IEC 18004 7.8.3 evaluation: N1 runs of >= 5, N2 2x2 blocks, N3 1:1:3:1:1 finder-like
    // patterns with 4 light modules on one side (outside the symbol counts as light), N4 balance.
    penalty() {
      const n = this.size, m = this.dark;
      let score = 0, darkCount = 0;
      const line = new Array(n);
      for (let dir = 0; dir < 2; dir++) {
        for (let a = 0; a < n; a++) {
          for (let b = 0; b < n; b++) line[b] = dir === 0 ? m[a][b] : m[b][a];
          score += linePenalty(line);
        }
      }
      for (let y = 0; y < n; y++) {
        for (let x = 0; x < n; x++) {
          const c = m[y][x];
          if (c) darkCount++;
          if (x < n - 1 && y < n - 1 && c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) score += 3;
        }
      }
      const total = n * n;
      score += 10 * Math.floor((Math.abs(darkCount * 2 - total) * 10) / total);
      return score;
    }
  }

  function linePenalty(line) {
    const n = line.length;
    let score = 0, run = 1;
    for (let i = 1; i <= n; i++) {
      if (i < n && line[i] === line[i - 1]) run++;
      else {
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
    const light = (from, to) => {
      for (let i = Math.max(from, 0); i < Math.min(to, n); i++) if (line[i]) return false;
      return true;
    };
    for (let i = 0; i + 6 < n; i++) {
      if (line[i] && !line[i + 1] && line[i + 2] && line[i + 3] && line[i + 4] && !line[i + 5] && line[i + 6] &&
          (light(i - 4, i) || light(i + 7, i + 11))) score += 40;
    }
    return score;
  }

  // ------------------------------------------------------------------ API
  // text: string (encoded as UTF-8) or bytes (Uint8Array / array of 0..255).
  // opts.ecc: "L" | "M" (default) | "Q" | "H"; opts.mask: 0..7 to force a mask (default: best);
  // opts.minVersion: smallest version to consider (default 1).
  function encode(text, opts) {
    const o = opts || {};
    const ecc = o.ecc === undefined ? "M" : String(o.ecc).toUpperCase();
    if (!Object.prototype.hasOwnProperty.call(FORMAT_ECC_BITS, ecc)) throw new Error(`QR: unknown error correction level ${o.ecc}`);
    const minVersion = o.minVersion === undefined ? 1 : o.minVersion;
    if (!Number.isInteger(minVersion) || minVersion < 1 || minVersion > 40) throw new Error("QR: minVersion must be 1..40");
    if (o.mask !== undefined && !(Number.isInteger(o.mask) && o.mask >= 0 && o.mask <= 7)) throw new Error("QR: mask must be 0..7");

    let bytes;
    if (typeof text === "string") bytes = utf8(text);
    else if (text && typeof text.length === "number") {
      bytes = Uint8Array.from(text);
      if (bytes.some((b, i) => b !== text[i])) throw new Error("QR: byte values must be 0..255");
    } else throw new Error("QR: text must be a string or bytes");

    let version = 0;
    for (let v = minVersion; v <= 40; v++) {
      if (bytes.length <= byteCapacity(v, ecc)) { version = v; break; }
    }
    if (!version) {
      throw new Error(`QR: data too long (${bytes.length} bytes; at most ${byteCapacity(40, ecc)} fit at error correction level ${ecc})`);
    }

    const mx = new Matrix(version);
    mx.placeData(codewords(bytes, version, ecc));
    let mask = o.mask;
    if (mask === undefined) {
      let best = Infinity;
      for (let k = 0; k < 8; k++) {
        mx.applyMask(k);
        mx.drawFormat(formatBits(ecc, k));
        const p = mx.penalty();
        if (p < best) { best = p; mask = k; }
        mx.applyMask(k);
      }
    }
    mx.applyMask(mask);
    mx.drawFormat(formatBits(ecc, mask));
    return { size: mx.size, modules: mx.dark, version, ecc, mask };
  }

  // SVG for a QR from encode(): white background (quiet zone included) and one path of dark
  // modules, in module units via viewBox so it scales; width/height = modules * scale pixels.
  function toSvg(qr, doc, opts) {
    const o = opts || {};
    const scale = o.scale === undefined ? 4 : o.scale, margin = o.margin === undefined ? 4 : o.margin;
    if (!(scale > 0)) throw new Error("QR: scale must be > 0");
    if (!Number.isInteger(margin) || margin < 0) throw new Error("QR: margin must be an integer >= 0");
    const NS = "http://www.w3.org/2000/svg";
    const dim = qr.size + 2 * margin;
    const svg = doc.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", `0 0 ${dim} ${dim}`);
    svg.setAttribute("width", String(dim * scale));
    svg.setAttribute("height", String(dim * scale));
    svg.setAttribute("shape-rendering", "crispEdges");
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", o.label || "QR code");
    const bg = doc.createElementNS(NS, "rect");
    bg.setAttribute("x", "0");
    bg.setAttribute("y", "0");
    bg.setAttribute("width", String(dim));
    bg.setAttribute("height", String(dim));
    bg.setAttribute("fill", "#fff");
    svg.appendChild(bg);
    let d = "";
    for (let y = 0; y < qr.size; y++) {
      const row = qr.modules[y];
      for (let x = 0; x < qr.size; ) {
        if (!row[x]) { x++; continue; }
        let run = 1;
        while (x + run < qr.size && row[x + run]) run++;
        d += `M${x + margin},${y + margin}h${run}v1h-${run}z`;
        x += run;
      }
    }
    const path = doc.createElementNS(NS, "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "#000");
    svg.appendChild(path);
    return svg;
  }

  return { encode, toSvg, byteCapacity };
});
