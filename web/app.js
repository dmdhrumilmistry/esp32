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
    state = {}; save(state); render();
  };

  $("dev-save").onclick = () => {
    try {
      state.config = P2P.parseDeviceConfig($("dev-text").value);
      save(state); msg("m-dev", ""); render();
    } catch (e) { msg("m-dev", e.message); }
  };
  $("dev-change").onclick = () => {
    $("dev-text").value = state.config ? JSON.stringify(state.config) : "";
    delete state.config; save(state); render();
  };

  $("go").onclick = async () => {
    const log = (line) => { $("log").textContent += line + "\n"; };
    $("log").textContent = ""; msg("m-go", ""); show("result", false);
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
      const conf = P2P.wgConfig(P2P.b64(priv), state.config, pick.endpoint, pick.direct ? null : PUNCH_PORT);
      $("r-ep").textContent = pick.endpoint;
      $("r-via").textContent = { upnp: "router mapping (UPnP)", natpmp: "router mapping (NAT-PMP)", manual: "manual endpoint",
                                 stun: "hole punching" }[ack.via] || ack.via || "";
      $("r-via").className = "pill " + (pick.direct ? "ok" : "warn");
      const notes = $("r-notes"); notes.textContent = "";
      for (const n of pick.notes) { const d = document.createElement("div"); d.className = "note"; d.textContent = n; notes.append(d); }
      $("r-conf").value = conf;
      show("result", true);
      $("result").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      msg("m-go", e.message);
    } finally {
      $("go").disabled = false;
    }
  };
  $("dl").onclick = () => download("p2ptun.conf", $("r-conf").value);
  $("copy-conf").onclick = () => copy($("r-conf").value, $("copy-conf"));

  render();
})();
