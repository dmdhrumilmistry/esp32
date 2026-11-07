/* p2ptun web client UI. All protocol/crypto lives in p2ptun-proto.js. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const STORE = "p2ptun.v1";
  const PUNCH_PORT = 51821; // ListenPort used when hole punching is the only option

  function load() {
    try { return JSON.parse(localStorage.getItem(STORE)) || {}; } catch (e) { return {}; }
  }
  function save(s) {
    try { localStorage.setItem(STORE, JSON.stringify(s)); }
    catch (e) { alert("This browser blocks storage (private mode?). The key will be lost when you close the page."); }
  }
  let state = load();

  function msg(id, text, good) { const m = $(id); m.textContent = text || ""; m.className = "msg " + (good ? "good" : "err"); }
  const show = (id, on) => $(id).classList.toggle("hide", !on);
  async function copy(text, btn) {
    const label = btn.textContent;
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; }
    catch (e) { btn.textContent = "Copy failed: select manually"; }
    setTimeout(() => (btn.textContent = label), 1500);
  }
  function download(name, text) {
    const url = URL.createObjectURL(new Blob([text], { type: "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url; a.download = name;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  // QR code of the exact config text for the phone's WireGuard app ("+ → Scan from QR code").
  // Hidden when there is no config, qr.js didn't load or the text doesn't fit.
  function showQr(text) {
    const slot = $("r-qr");
    slot.textContent = "";
    let ok = false;
    if (text && typeof P2PQR === "object") {
      try {
        const qr = P2PQR.encode(text, { ecc: "M" });
        slot.append(P2PQR.toSvg(qr, document, { scale: 4, margin: 4, label: "QR code of the WireGuard config" }));
        ok = true;
      } catch (e) {
        slot.textContent = "";
      }
    }
    show("r-qr-box", ok);
  }

  // Hides and empties the result (config text and QR both carry the private key). Called whenever
  // the key or device config changes; bumping resultGen also discards a "Get config" still running.
  let resultGen = 0;
  function clearResult() {
    resultGen++;
    show("result", false);
    $("r-conf").value = "";
    showQr("");
  }

  function render() {
    const hasKey = !!state.pub;
    show("key-none", !hasKey); show("key-have", hasKey);
    if (hasKey) {
      $("pub").textContent = state.pub;
      $("key-prot").textContent = state.locked ? "passphrase-protected" : "stored unencrypted in this browser";
      $("key-prot").className = "pill " + (state.locked ? "ok" : "warn");
    }
    show("dev-none", !state.config); show("dev-have", !!state.config);
    if (state.config) {
      const c = state.config;
      $("dev-summary").textContent =
        `${c.name || "this client"} → ${c.address}\nLAN: ${c.device.routes.join(", ") || "(none)"}\nrelays: ${c.relays.join(", ")}`;
    }
    show("unlock-row", !!state.locked);
    $("go").disabled = !(hasKey && state.config);
  }

  async function storeKey(priv, pass) {
    const pub = P2P.b64(await P2P.wgPubKey(priv));
    state = { ...state, pub };
    delete state.priv; delete state.locked;
    if (pass) state.locked = await P2P.lockKey(priv, pass);
    else state.priv = P2P.b64(priv);
    save(state);
    clearResult();
    render();
  }

  async function privateKey() {
    if (state.priv) return P2P.unb64(state.priv, 32);
    const pass = $("unlock-pass").value;
    if (!pass) throw new Error("enter your passphrase");
    return P2P.unlockKey(state.locked, pass);
  }

  $("gen").onclick = async () => {
    const p1 = $("gen-pass").value, p2 = $("gen-pass2").value;
    if (p1 !== p2) return msg("m-key", "Passphrases don't match");
    if (p1 && p1.length < 8) return msg("m-key", "Use at least 8 characters, or leave it empty");
    $("gen").disabled = true;
    try { await storeKey(P2P.wgGenKey(), p1); msg("m-key", ""); } catch (e) { msg("m-key", e.message); }
    $("gen").disabled = false;
  };
  $("imp").onclick = async () => {
    try {
      const k = P2P.unb64($("imp-key").value.trim(), 32);
      await storeKey(k, $("gen-pass").value);
      $("imp-key").value = "";
    } catch (e) { msg("m-key", "Not a WireGuard private key (base64, 32 bytes)"); }
  };
  $("copy-pub").onclick = () => copy(state.pub, $("copy-pub"));
  $("export").onclick = async () => {
    try {
      const priv = await privateKey();
      download("p2ptun-key-backup.json", JSON.stringify({ private_key: P2P.b64(priv), ...(state.config || {}) }, null, 2));
    } catch (e) { msg("m-go", e.message); }
  };
  $("forget").onclick = () => {
    if (!confirm("Delete this key from the browser? Also delete or block it on the device.")) return;
    state = {}; save(state); clearResult(); render();
  };

  $("dev-save").onclick = () => {
    try {
      state.config = P2P.parseDeviceConfig($("dev-text").value);
      save(state); msg("m-dev", ""); clearResult(); render();
    } catch (e) { msg("m-dev", e.message); }
  };
  $("dev-change").onclick = () => {
    $("dev-text").value = state.config ? JSON.stringify(state.config) : "";
    delete state.config; save(state); clearResult(); render();
  };

  $("go").onclick = async () => {
    const log = (line) => { $("log").textContent += line + "\n"; };
    $("log").textContent = ""; msg("m-go", ""); clearResult();
    const gen = resultGen;
    $("go").disabled = true;
    try {
      const priv = await privateKey();
      log("Finding this network's public address…");
      const myIp = await P2P.publicIpWebRTC();
      log(myIp ? `public IP ${myIp}` : "public IP unknown (WebRTC blocked); that's fine");
      log("Knocking via Nostr relays (encrypted)…");
      // If the device turns out to be reachable only by hole punching, it punches towards this guess.
      const ack = await P2P.rendezvous(state.config, priv, { ep: myIp ? `${myIp}:${PUNCH_PORT}` : undefined, log });
      log(`device answered (${ack.via || "?"})`);
      const pick = P2P.pickEndpoint(ack, myIp);
      if (gen !== resultGen) return; // key or device config changed (e.g. "Forget key") meanwhile
      const conf = P2P.wgConfig(P2P.b64(priv), state.config, pick.endpoint, pick.direct ? null : PUNCH_PORT);
      $("r-ep").textContent = pick.endpoint;
      $("r-via").textContent = { upnp: "router mapping (UPnP)", natpmp: "router mapping (NAT-PMP)", manual: "manual endpoint",
                                 stun: "hole punching" }[ack.via] || ack.via || "";
      $("r-via").className = "pill " + (pick.direct ? "ok" : "warn");
      const notes = $("r-notes"); notes.textContent = "";
      for (const n of pick.notes) { const d = document.createElement("div"); d.className = "note"; d.textContent = n; notes.append(d); }
      $("r-conf").value = conf;
      showQr(conf);
      show("result", true);
      $("result").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      if (gen === resultGen) msg("m-go", e.message);
    } finally {
      $("go").disabled = !(state.pub && state.config);
    }
  };
  $("dl").onclick = () => download("p2ptun.conf", $("r-conf").value);
  $("copy-conf").onclick = () => copy($("r-conf").value, $("copy-conf"));

  // ---- one-scan pairing: the invite arrives in the URL #fragment (never sent to the server)
  let invite = null;
  function readInvite() {
    if (!/p2ptun=/.test(location.hash)) return;
    const raw = location.hash;
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) { location.hash = ""; }
    try {
      invite = P2P.parseInvite(raw);
    } catch (e) {
      show("pair-card", true);
      $("pair-go").disabled = true;
      msg("m-pair", "This invite link is damaged: " + e.message);
      return;
    }
    $("pair-dev").textContent = invite.cfg.device.tunnel_ip + " (" + (invite.cfg.device.routes.join(", ") || "device only") + ")";
    $("pair-name").textContent = invite.name || "a new peer";
    show("pair-newkey", !state.pub); show("pair-oldkey", !!state.pub); show("pair-unlock", !!state.locked);
    show("pair-card", true);
    $("pair-card").scrollIntoView({ block: "start" });
  }
  $("pair-cancel").onclick = () => { invite = null; show("pair-card", false); };
  $("pair-go").onclick = async () => {
    if (!invite) return;
    const log = (line) => { $("pair-log").textContent += line + "\n"; };
    $("pair-log").textContent = ""; msg("m-pair", "");
    $("pair-go").disabled = true;
    try {
      if (!state.pub) {
        const pass = $("pair-pass").value;
        if (pass && pass.length < 8) throw new Error("Use at least 8 characters for the passphrase, or leave it empty");
        await storeKey(P2P.wgGenKey(), pass);
        log("created a new key");
      }
      let priv;
      if (state.priv) priv = P2P.unb64(state.priv, 32);
      else {
        const pass = $("pair-unlock-pass").value || $("pair-pass").value;
        if (!pass) throw new Error("enter your passphrase");
        priv = await P2P.unlockKey(state.locked, pass);
      }
      log("asking the device to add this key (encrypted)…");
      const cfg = await P2P.pair(invite, priv, { log });
      state.config = cfg; save(state);
      invite = null;
      clearResult(); render();
      msg("m-pair", `Paired as ${cfg.name} (${cfg.address}). Now press “Get WireGuard config” below.`, true);
      $("go").scrollIntoView({ behavior: "smooth", block: "center" });
    } catch (e) {
      msg("m-pair", e.message);
      $("pair-go").disabled = false;
    }
  };
  window.addEventListener("hashchange", readInvite);

  render();
  readInvite();
})();
