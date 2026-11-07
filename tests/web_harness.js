// Node CLI around web/p2ptun-proto.js for tests/test_web.py. Reads a JSON request on stdin,
// writes a JSON result on stdout.
"use strict";
const P2P = require("../web/p2ptun-proto.js");

const u8 = (h) => P2P.unhex(h);

async function run(req) {
  switch (req.cmd) {
    case "x25519": {
      const priv = P2P.unb64(req.priv), pub = P2P.unb64(req.pub);
      const web = P2P.b64(await P2P.x25519(priv, pub));
      const js = P2P.b64(P2P.x25519js(priv, pub));
      return { web, js };
    }
    case "wgpub": return { pub: P2P.b64(await P2P.wgPubKey(P2P.unb64(req.priv))) };
    case "genkey": { const k = P2P.wgGenKey(); return { priv: P2P.b64(k), pub: P2P.b64(await P2P.wgPubKey(k)) }; }
    case "aead_enc": return { out: P2P.hex(P2P.aeadEncrypt(u8(req.key), u8(req.nonce), u8(req.pt), u8(req.aad))) };
    case "aead_dec":
      try { return { out: P2P.hex(P2P.aeadDecrypt(u8(req.key), u8(req.nonce), u8(req.ct), u8(req.aad))) }; }
      catch (e) { return { error: e.message }; }
    case "pubkey": return { pub: P2P.hex(P2P.schnorrPubkey(u8(req.sk))) };
    case "sign": return { sig: P2P.hex(await P2P.schnorrSign(u8(req.sk), u8(req.msg), u8(req.aux))) };
    case "event": return await P2P.nostrEvent(u8(req.sk), req.kind, req.created_at, req.p, req.content);
    case "seal": {
      const key = await P2P.envelopeKey(P2P.unb64(req.priv), P2P.unb64(req.pub));
      return { content: P2P.envelopeSeal(key, new TextEncoder().encode(req.pt)) };
    }
    case "open": {
      const key = await P2P.envelopeKey(P2P.unb64(req.priv), P2P.unb64(req.pub));
      try { return { pt: new TextDecoder().decode(P2P.envelopeOpen(key, req.content)) }; }
      catch (e) { return { error: e.message }; }
    }
    case "parse_config":
      try { return P2P.parseDeviceConfig(req.text); } catch (e) { return { error: e.message }; }
    case "wgconfig": return { conf: P2P.wgConfig(req.priv, req.cfg, req.endpoint, req.listen_port) };
    case "pick":
      try { return P2P.pickEndpoint(req.ack, req.client_ip); } catch (e) { return { error: e.message }; }
    case "lock": {
      const locked = await P2P.lockKey(P2P.unb64(req.priv), req.pass);
      const back = P2P.b64(await P2P.unlockKey(locked, req.pass));
      let wrong = null;
      try { await P2P.unlockKey(locked, req.pass + "x"); } catch (e) { wrong = e.message; }
      return { back, wrong, alg: locked.alg };
    }
    case "parse_invite":
      try { const inv = P2P.parseInvite(req.text); return { name: inv.name, secret: P2P.hex(inv.secret), cfg: inv.cfg }; }
      catch (e) { return { error: e.message }; }
    case "pair": {
      try {
        const inv = P2P.parseInvite(req.link);
        if (req.relays) inv.cfg.relays = req.relays; // tests: local ws:// relay (invites require wss://)
        return { cfg: await P2P.pair(inv, P2P.unb64(req.priv), { timeoutMs: req.timeout_ms || 6000 }) };
      } catch (e) { return { error: e.message }; }
    }
    case "rendezvous": {
      const ack = await P2P.rendezvous(req.cfg, P2P.unb64(req.priv), { ep: req.ep, timeoutMs: req.timeout_ms || 6000 });
      return { ack };
    }
    default: throw new Error("unknown cmd " + req.cmd);
  }
}

let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", async () => {
  try {
    process.stdout.write(JSON.stringify(await run(JSON.parse(input))));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }));
  }
});
