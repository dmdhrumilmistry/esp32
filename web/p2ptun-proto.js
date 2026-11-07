/* p2ptun web client: protocol + crypto (no dependencies).
 *
 * Mirrors firmware/main/p2p_crypto.c and client/p2ptun_proto.py; see docs/PROTOCOL.md.
 * Works in browsers (window.P2P) and Node >= 20 (require), which the tests use.
 *
 * Primitives: X25519 (WebCrypto when available, else RFC 7748 ladder), HMAC/SHA-256 (WebCrypto),
 * ChaCha20-Poly1305 (RFC 8439) and BIP-340 Schnorr on secp256k1 (BigInt).
 */
(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.P2P = api;
})(typeof self !== "undefined" ? self : globalThis, function (root) {
  "use strict";

  const NOSTR_KIND = 21820;
  const PROTO_VERSION = 1;
  const MAX_SKEW_S = 120;
  const DEFAULT_STUN = ["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478"];
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const subtle = root.crypto.subtle;

  // ------------------------------------------------------------------ bytes
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  function unhex(s, n) {
    if (typeof s !== "string" || !/^(?:[0-9a-fA-F]{2})*$/.test(s)) throw new Error("bad hex");
    const b = Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
    if (n !== undefined && b.length !== n) throw new Error(`expected ${n} bytes`);
    return b;
  }
  function b64(b) {
    let s = "";
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s);
  }
  function unb64(s, n) {
    if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error("bad base64");
    const b = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    if (n !== undefined && b.length !== n) throw new Error(`expected ${n} bytes`);
    return b;
  }
  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const random = (n) => root.crypto.getRandomValues(new Uint8Array(n));
  const beToBig = (b) => (b.length ? BigInt("0x" + hex(b)) : 0n);
  const bigToBe = (x, n = 32) => unhex(x.toString(16).padStart(n * 2, "0"));
  const leToBig = (b) => beToBig(Uint8Array.from(b).reverse());
  const bigToLe = (x, n) => bigToBe(x, n).reverse();
  const mod = (a, m) => ((a % m) + m) % m;
  function powmod(b, e, m) {
    let r = 1n; b = mod(b, m);
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }
  function invmod(a, m) {
    let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
    while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error("not invertible");
    return mod(s0, m);
  }
  function ctEqual(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ------------------------------------------------------------------ hashes
  const sha256 = async (b) => new Uint8Array(await subtle.digest("SHA-256", b));
  async function hmacSha256(key, msg) {
    const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await subtle.sign("HMAC", k, msg));
  }
  async function taggedHash(tag, ...parts) {
    const t = await sha256(enc.encode(tag));
    return sha256(concat(t, t, ...parts));
  }

  // ------------------------------------------------------------------ X25519
  const P25519 = (1n << 255n) - 19n;
  function x25519js(scalar, u) {
    const k = Uint8Array.from(scalar);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    const kn = leToBig(k);
    const ub = Uint8Array.from(u); ub[31] &= 127;
    const x1 = leToBig(ub) % P25519;
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
    const m = (a) => mod(a, P25519);
    for (let t = 254; t >= 0; t--) {
      const kt = (kn >> BigInt(t)) & 1n;
      swap ^= kt;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = kt;
      const A = m(x2 + z2), AA = m(A * A), B = m(x2 - z2), BB = m(B * B), E = m(AA - BB);
      const C = m(x3 + z3), D = m(x3 - z3), DA = m(D * A), CB = m(C * B);
      x3 = m((DA + CB) ** 2n);
      z3 = m(x1 * m((DA - CB) ** 2n));
      x2 = m(AA * BB);
      z2 = m(E * (AA + 121665n * E));
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    const out = bigToLe(m(x2 * powmod(z2, P25519 - 2n, P25519)), 32);
    if (out.every((x) => x === 0)) throw new Error("x25519: low-order point");
    return out;
  }

  // WebCrypto X25519 is constant-time; the BigInt ladder is a fallback for older browsers.
  const PKCS8_X25519 = unhex("302e020100300506032b656e04220420");
  async function x25519(priv, pub) {
    try {
      const sk = await subtle.importKey("pkcs8", concat(PKCS8_X25519, priv), { name: "X25519" }, false, ["deriveBits"]);
      const pk = await subtle.importKey("raw", pub, { name: "X25519" }, false, []);
      const out = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pk }, sk, 256));
      if (out.every((x) => x === 0)) throw new Error("x25519: low-order point");
      return out;
    } catch (e) {
      if (/low-order/.test(e.message) || e.name === "OperationError") throw new Error("x25519: low-order point");
      return x25519js(priv, pub);
    }
  }
  const BASEPOINT = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();

  function wgGenKey() {
    const k = random(32);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    return k;
  }
  const wgPubKey = (priv) => x25519(priv, BASEPOINT);

  // ------------------------------------------------------------------ ChaCha20-Poly1305
  function chachaBlock(key, counter, nonce) {
    const s = new Uint32Array(16);
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    const kv = new DataView(key.buffer, key.byteOffset, 32), nv = new DataView(nonce.buffer, nonce.byteOffset, 12);
    for (let i = 0; i < 8; i++) s[4 + i] = kv.getUint32(i * 4, true);
    s[12] = counter >>> 0;
    for (let i = 0; i < 3; i++) s[13 + i] = nv.getUint32(i * 4, true);
    const w = Uint32Array.from(s);
    const rotl = (v, c) => (v << c) | (v >>> (32 - c));
    const qr = (a, b, c, d) => {
      w[a] += w[b]; w[d] = rotl(w[d] ^ w[a], 16);
      w[c] += w[d]; w[b] = rotl(w[b] ^ w[c], 12);
      w[a] += w[b]; w[d] = rotl(w[d] ^ w[a], 8);
      w[c] += w[d]; w[b] = rotl(w[b] ^ w[c], 7);
    };
    for (let i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    const out = new Uint8Array(64), ov = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) ov.setUint32(i * 4, (w[i] + s[i]) >>> 0, true);
    return out;
  }
  function chacha20(key, counter, nonce, data) {
    const out = new Uint8Array(data.length);
    for (let off = 0, c = counter; off < data.length; off += 64, c++) {
      const ks = chachaBlock(key, c, nonce);
      for (let i = 0; i < 64 && off + i < data.length; i++) out[off + i] = data[off + i] ^ ks[i];
    }
    return out;
  }
  function poly1305(key, msg) {
    const r = leToBig(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const s = leToBig(key.subarray(16, 32));
    const p = (1n << 130n) - 5n;
    let acc = 0n;
    for (let i = 0; i < msg.length; i += 16) {
      const blk = msg.subarray(i, i + 16);
      acc = ((acc + leToBig(blk) + (1n << BigInt(8 * blk.length))) * r) % p;
    }
    return bigToLe((acc + s) & ((1n << 128n) - 1n), 16);
  }
  function aeadMacData(aad, ct) {
    const pad = (n) => new Uint8Array((16 - (n % 16)) % 16);
    const lens = new Uint8Array(16), lv = new DataView(lens.buffer);
    lv.setUint32(0, aad.length, true); lv.setUint32(8, ct.length, true);
    return concat(aad, pad(aad.length), ct, pad(ct.length), lens);
  }
  function aeadEncrypt(key, nonce, pt, aad) {
    const otk = chachaBlock(key, 0, nonce).subarray(0, 32);
    const ct = chacha20(key, 1, nonce, pt);
    return concat(ct, poly1305(otk, aeadMacData(aad, ct)));
  }
  function aeadDecrypt(key, nonce, ctTag, aad) {
    if (ctTag.length < 16) throw new Error("short ciphertext");
    const ct = ctTag.subarray(0, ctTag.length - 16), tag = ctTag.subarray(ctTag.length - 16);
    const otk = chachaBlock(key, 0, nonce).subarray(0, 32);
    if (!ctEqual(poly1305(otk, aeadMacData(aad, ct)), tag)) throw new Error("authentication failed");
    return chacha20(key, 1, nonce, ct);
  }

  // ------------------------------------------------------------------ secp256k1 / BIP-340
  const SP = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const SN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const SG = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
              0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
  function padd(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (a[0] === b[0] && a[1] !== b[1]) return null;
    const lam = a[0] === b[0] && a[1] === b[1]
      ? mod(3n * a[0] * a[0] * invmod(2n * a[1], SP), SP)
      : mod((b[1] - a[1]) * invmod(b[0] - a[0], SP), SP);
    const x = mod(lam * lam - a[0] - b[0], SP);
    return [x, mod(lam * (a[0] - x) - a[1], SP)];
  }
  function pmul(p, k) {
    let r = null;
    while (k > 0n) { if (k & 1n) r = padd(r, p); p = padd(p, p); k >>= 1n; }
    return r;
  }
  function schnorrPubkey(sk) {
    const d = beToBig(sk);
    if (d <= 0n || d >= SN) throw new Error("invalid secret key");
    return bigToBe(pmul(SG, d)[0]);
  }
  async function schnorrSign(sk, msg, aux = random(32)) {
    const d0 = beToBig(sk);
    if (d0 <= 0n || d0 >= SN) throw new Error("invalid secret key");
    const P = pmul(SG, d0);
    const d = P[1] % 2n === 0n ? d0 : SN - d0;
    const px = bigToBe(P[0]);
    const t = bigToBe(d ^ beToBig(await taggedHash("BIP0340/aux", aux)));
    const k0 = beToBig(await taggedHash("BIP0340/nonce", t, px, msg)) % SN;
    if (k0 === 0n) throw new Error("bad nonce");
    const R = pmul(SG, k0);
    const k = R[1] % 2n === 0n ? k0 : SN - k0;
    const rx = bigToBe(R[0]);
    const e = beToBig(await taggedHash("BIP0340/challenge", rx, px, msg)) % SN;
    return concat(rx, bigToBe(mod(k + e * d, SN)));
  }

  // ------------------------------------------------------------------ envelope + nostr
  const AAD = enc.encode("p2ptun-v1");
  async function envelopeKey(myPriv, peerPub) {
    return hmacSha256(await x25519(myPriv, peerPub), enc.encode("p2ptun-signal-v1"));
  }
  function envelopeSeal(key, pt) {
    const nonce = random(12);
    return b64(concat(nonce, aeadEncrypt(key, nonce, pt, AAD)));
  }
  function envelopeOpen(key, content) {
    const raw = unb64(content);
    if (raw.length < 28) throw new Error("short envelope");
    return aeadDecrypt(key, raw.subarray(0, 12), raw.subarray(12), AAD);
  }
  async function nostrEvent(sk, kind, createdAt, pTag, content) {
    const pubkey = hex(schnorrPubkey(sk));
    const tags = [["p", pTag]];
    const id = await sha256(enc.encode(JSON.stringify([0, pubkey, createdAt, kind, tags, content])));
    return { id: hex(id), pubkey, created_at: createdAt, kind, tags, content, sig: hex(await schnorrSign(sk, id)) };
  }

  // ------------------------------------------------------------------ config
  // Accepts the JSON shown by the device web UI, or the whole `p2ptun.py join '...'` command.
  function parseDeviceConfig(text) {
    const a = text.indexOf("{"), b = text.lastIndexOf("}");
    if (a < 0 || b < a) throw new Error("paste the JSON shown by the device after authorizing your key");
    const c = JSON.parse(text.slice(a, b + 1));
    const d = c.device || {};
    unb64(d.wg_pub, 32);
    unhex(d.nostr_pub, 32);
    if (!/^\d+\.\d+\.\d+\.\d+\/32$/.test(c.address || "")) throw new Error("bad address");
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(d.tunnel_ip || "")) throw new Error("bad tunnel_ip");
    const routes = d.routes || [];
    if (!routes.every((r) => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(r))) throw new Error("bad routes");
    const relays = (c.relays || []).filter((u) => /^wss:\/\/[^\s"'<>\\]+$/.test(u));
    if (!relays.length) throw new Error("no wss:// relays in config");
    return { name: String(c.name || ""), address: c.address,
             device: { wg_pub: d.wg_pub, nostr_pub: d.nostr_pub.toLowerCase(), tunnel_ip: d.tunnel_ip, routes }, relays };
  }

  function wgConfig(privB64, cfg, endpoint, listenPort) {
    const allowed = [cfg.device.tunnel_ip + "/32", ...cfg.device.routes].join(", ");
    return [
      "[Interface]",
      `PrivateKey = ${privB64}`,
      `Address = ${cfg.address}`,
      ...(listenPort ? [`ListenPort = ${listenPort}`] : []),
      "",
      "[Peer]",
      `PublicKey = ${cfg.device.wg_pub}`,
      `Endpoint = ${endpoint}`,
      `AllowedIPs = ${allowed}`,
      "PersistentKeepalive = 25",
      "",
    ].join("\n");
  }

  const hostOf = (ep) => ep.slice(0, ep.lastIndexOf(":"));

  // Decide what the WireGuard app should dial. clientIp: our public IP if known (WebRTC).
  function pickEndpoint(ack, clientIp) {
    const notes = [];
    const ep = ack.ep || "", lan = ack.lan || "";
    if (!ep && !lan) throw new Error("the device doesn't know a reachable address yet; try again in a minute");
    if (lan && (!ep || (clientIp && hostOf(ep) === clientIp))) {
      notes.push("You're on the same network as the device, so this config uses its LAN address and only works here.");
      return { endpoint: lan, direct: true, notes };
    }
    const direct = ack.via === "upnp" || ack.via === "natpmp" || ack.via === "manual";
    if (!direct) {
      notes.push("The device has no router port mapping (UPnP/NAT-PMP off). The stock WireGuard app can only connect if NATs on both sides cooperate. If it doesn't connect, enable UPnP/NAT-PMP on the device's router or set a port forward + endpoint override in the device UI.");
    }
    return { endpoint: ep, direct, notes };
  }

  // ------------------------------------------------------------------ rendezvous
  async function makeKnock(cfg, privKey, opts = {}) {
    const key = await envelopeKey(privKey, unb64(cfg.device.wg_pub, 32));
    let esk;
    for (;;) { esk = random(32); try { schnorrPubkey(esk); break; } catch (e) { /* retry */ } }
    const now = Math.floor(Date.now() / 1000);
    const nonce = hex(random(8));
    const knock = { v: PROTO_VERSION, t: "knock", ts: now, n: nonce };
    if (opts.ep) knock.ep = opts.ep;
    if (opts.lan) knock.lan = opts.lan;
    const content = envelopeSeal(key, enc.encode(JSON.stringify(knock)));
    const event = await nostrEvent(esk, NOSTR_KIND, now, cfg.device.nostr_pub, content);
    return { key, nonce, event, epub: hex(schnorrPubkey(esk)), now };
  }

  function parseAck(pt, nonce) {
    const m = JSON.parse(dec.decode(pt));
    if (m.v !== PROTO_VERSION || m.t !== "ack" || m.n !== nonce) throw new Error("not our ack");
    if (Math.abs(m.ts - Date.now() / 1000) > MAX_SKEW_S) throw new Error("stale ack (check this device's clock)");
    return m;
  }

  // Publish an encrypted knock to every relay and resolve with the device's ack.
  async function rendezvous(cfg, privKey, opts = {}) {
    const WS = opts.WebSocket || root.WebSocket;
    const log = opts.log || (() => {});
    const k = await makeKnock(cfg, privKey, opts);
    const subId = hex(random(4));
    return new Promise((resolve, reject) => {
      const sockets = [];
      let done = false, closed = 0;
      const finish = (err, ack) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        for (const s of sockets) { try { s.close(); } catch (e) { /* ignore */ } }
        if (err) reject(err); else resolve(ack);
      };
      const timer = setTimeout(() => finish(new Error(
        "No answer from the device. Is it online, is this key authorized (and not blocked), and is this device's clock correct?")),
        opts.timeoutMs || 25000);
      const onGone = (url) => {
        if (done) return; // we closed it ourselves
        log(`relay ${url} closed`);
        if (++closed === cfg.relays.length) finish(new Error("could not reach any relay"));
      };
      for (const url of cfg.relays) {
        let ws;
        try { ws = new WS(url); } catch (e) { onGone(url); continue; }
        sockets.push(ws);
        ws.onopen = () => {
          ws.send(JSON.stringify(["REQ", subId, { kinds: [NOSTR_KIND], "#p": [k.epub], since: k.now - 10 }]));
          ws.send(JSON.stringify(["EVENT", k.event]));
          log(`knock sent via ${url}`);
        };
        ws.onmessage = (m) => {
          let msg;
          try { msg = JSON.parse(typeof m.data === "string" ? m.data : dec.decode(m.data)); } catch (e) { return; }
          if (msg[0] === "OK" && msg[1] === k.event.id && msg[2] === false) log(`${url} rejected the knock: ${msg[3] || ""}`);
          if (msg[0] !== "EVENT" || msg.length !== 3) return;
          const ev = msg[2];
          if (!ev || ev.kind !== NOSTR_KIND || ev.pubkey !== cfg.device.nostr_pub) return;
          try { finish(null, parseAck(envelopeOpen(k.key, ev.content), k.nonce)); } catch (e) { /* not for us */ }
        };
        ws.onerror = () => log(`relay ${url} error`);
        ws.onclose = () => onGone(url);
      }
    });
  }

  // Public IPv4 of this browser via a WebRTC STUN (srflx) candidate. null if unavailable.
  function publicIpWebRTC(stunUrls = DEFAULT_STUN, timeoutMs = 3000) {
    if (!root.RTCPeerConnection) return Promise.resolve(null);
    return new Promise((resolve) => {
      let pc;
      const end = (ip) => { try { pc.close(); } catch (e) { /* ignore */ } resolve(ip); };
      try { pc = new root.RTCPeerConnection({ iceServers: [{ urls: stunUrls }] }); } catch (e) { resolve(null); return; }
      const t = setTimeout(() => end(null), timeoutMs);
      pc.onicecandidate = (e) => {
        const m = e.candidate && / (\d+\.\d+\.\d+\.\d+) \d+ typ srflx/.exec(e.candidate.candidate);
        if (m) { clearTimeout(t); end(m[1]); }
      };
      pc.createDataChannel("p2ptun");
      pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => { clearTimeout(t); end(null); });
    });
  }

  // ------------------------------------------------------------------ key storage (optional passphrase)
  async function lockKey(priv, passphrase) {
    const salt = random(16), iv = random(12);
    const base = await subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const k = await subtle.deriveKey({ name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" }, base,
                                     { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, k, priv));
    return { alg: "pbkdf2-sha256-310000/aes-256-gcm", salt: b64(salt), iv: b64(iv), ct: b64(ct) };
  }
  async function unlockKey(locked, passphrase) {
    const base = await subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const k = await subtle.deriveKey({ name: "PBKDF2", salt: unb64(locked.salt), iterations: 310000, hash: "SHA-256" },
                                     base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    try {
      return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(locked.iv) }, k, unb64(locked.ct)));
    } catch (e) {
      throw new Error("wrong passphrase");
    }
  }

  return {
    NOSTR_KIND, PROTO_VERSION, DEFAULT_STUN,
    hex, unhex, b64, unb64,
    x25519, x25519js, wgGenKey, wgPubKey,
    aeadEncrypt, aeadDecrypt, chachaBlock, poly1305,
    schnorrPubkey, schnorrSign, nostrEvent,
    envelopeKey, envelopeSeal, envelopeOpen,
    parseDeviceConfig, wgConfig, pickEndpoint,
    makeKnock, parseAck, rendezvous, publicIpWebRTC,
    lockKey, unlockKey,
  };
});
