// Node CLI around web/qr.js for tests/test_qr.py. Reads a JSON request on stdin, writes JSON on stdout.
//   {text, ecc?, mask?, min_version?, eci?}  or {hex, ...} (raw bytes)
//     -> {size, version, ecc, mask, eci, modules: ["0101..", ...]} or {error}
//   {items: [request, ...]}            -> {results: [result, ...]}
//   {cmd: "svg", text, ecc?, scale?, margin?} -> {qr: result, svg: element tree built via a fake document}
//   {cmd: "capacity", eci?}            -> {"1L": 17, "1M": 14, ..., "40H": 1273} (byte-mode capacity,
//                                         with room for the UTF-8 ECI header when eci is true)
"use strict";
const QR = require("../web/qr.js");

function encode(req) {
  const data = req.hex !== undefined ? Uint8Array.from(Buffer.from(req.hex, "hex")) : req.text;
  const qr = QR.encode(data, { ecc: req.ecc, mask: req.mask, minVersion: req.min_version, eci: req.eci });
  return {
    size: qr.size, version: qr.version, ecc: qr.ecc, mask: qr.mask, eci: qr.eci,
    modules: qr.modules.map((row) => row.map((on) => (on ? "1" : "0")).join("")),
  };
}

function one(req) {
  try { return encode(req); } catch (e) { return { error: e.message }; }
}

// Minimal document: only createElementNS/setAttribute/appendChild exist, and elements are sealed so
// anything else (innerHTML, style, createElement, ...) throws inside qr.js's strict-mode code.
function fakeDocument() {
  return Object.freeze({
    createElementNS(ns, tag) {
      return Object.seal({
        ns, tag, attrs: {}, children: [],
        setAttribute(k, v) { this.attrs[k] = String(v); },
        appendChild(c) { this.children.push(c); return c; },
      });
    },
  });
}
const tree = (el) => ({ ns: el.ns, tag: el.tag, attrs: el.attrs, children: el.children.map(tree) });

function run(req) {
  if (req.items) return { results: req.items.map(one) };
  if (req.cmd === "capacity") {
    const caps = {};
    for (let v = 1; v <= 40; v++) for (const e of "LMQH") caps[v + e] = QR.byteCapacity(v, e, !!req.eci);
    return caps;
  }
  if (req.cmd === "svg") {
    const qr = QR.encode(req.text, { ecc: req.ecc });
    const opts = {};
    if (req.scale !== undefined) opts.scale = req.scale;
    if (req.margin !== undefined) opts.margin = req.margin;
    return { qr: encode(req), svg: tree(QR.toSvg(qr, fakeDocument(), opts)) };
  }
  return one(req);
}

let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  try {
    process.stdout.write(JSON.stringify(run(JSON.parse(input))));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }));
  }
});
