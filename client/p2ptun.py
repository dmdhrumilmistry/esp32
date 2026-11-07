#!/usr/bin/env python3
"""p2ptun client: connect to an ESP32 p2ptun device peer-to-peer, no server of your own.

  python3 p2ptun.py pair '<invite link>'      # easiest: one-time invite from the device web UI
  python3 p2ptun.py genkey            # create p2ptun.json with a new WireGuard key, print the public key
  python3 p2ptun.py join '<json>'     # paste the config the device's web UI shows after you authorize the key
  sudo python3 p2ptun.py up           # Linux: rendezvous via Nostr, hole-punch, bring up WireGuard, stay connected
  python3 p2ptun.py resolve -o p2ptun.conf   # any OS: rendezvous and write a config for the WireGuard app

Phones (Android/iOS) and any other OS can also use the browser client in web/ (no Python needed).

See ../docs/PROTOCOL.md for how it works.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import p2ptun_proto as proto

try:
    import websockets
except ImportError:  # pragma: no cover
    websockets = None

DEFAULT_STUN = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
DEFAULT_PORT = 51821
DEFAULT_IFACE = "p2ptun0"


def log(*a):
    print("[p2ptun]", *a, flush=True)


def die(msg: str, code: int = 1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)

# ---------------------------------------------------------------------------
# config file
# ---------------------------------------------------------------------------

def load_cfg(path: Path) -> dict:
    if not path.exists():
        die(f"{path} not found; run `p2ptun.py genkey` first")
    return json.loads(path.read_text())


def save_cfg(path: Path, cfg: dict):
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)  # private key
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


def require_joined(cfg: dict):
    for k in ("private_key", "address", "device", "relays"):
        if k not in cfg:
            die("config incomplete; authorize this key in the device web UI and run `p2ptun.py join '<json>'`")


def cmd_genkey(args):
    path = Path(args.config)
    cfg = json.loads(path.read_text()) if path.exists() else {}
    if "private_key" in cfg and not args.force:
        log(f"{path} already has a key (use --force to replace it)")
    else:
        cfg["private_key"] = proto.b64(proto.wg_genkey())
        save_cfg(path, cfg)
        log(f"new key written to {path} (mode 600)")
    pub = proto.b64(proto.wg_pubkey(proto.unb64(cfg["private_key"], 32)))
    print("\nPaste this public key into the device web UI → 'Authorize a client':\n")
    print(f"  {pub}\n")


def cmd_join(args):
    path = Path(args.config)
    cfg = load_cfg(path)
    blob = json.loads(args.blob)
    dev = blob.get("device", {})
    proto.unb64(dev["wg_pub"], 32)
    bytes.fromhex(dev["nostr_pub"])
    if len(dev["nostr_pub"]) != 64:
        die("bad device nostr_pub")
    if not blob.get("relays"):
        die("config has no relays")
    cfg.update({"name": blob.get("name", ""), "address": blob["address"], "device": dev, "relays": blob["relays"]})
    save_cfg(path, cfg)
    log(f"joined device {dev['wg_pub'][:12]}… as {blob['address']}; LAN routes: {', '.join(dev.get('routes', [])) or 'none'}")
    log("next: sudo python3 p2ptun.py up   (Linux)   or   python3 p2ptun.py resolve   (other OS)")

# ---------------------------------------------------------------------------
# rendezvous over Nostr
# ---------------------------------------------------------------------------

async def exchange(cfg: dict, key: bytes, message: dict, accept, timeout: float, timeout_msg: str):
    """Seal `message` with `key`, send it to the device via all relays, return accept(reply) for the
    first reply that opens with `key` and for which accept() returns non-None (accept may raise)."""
    if websockets is None:
        die("pip install websockets")
    dev = cfg["device"]
    # Fresh throwaway Nostr identity per message: relays can't link sessions to this client.
    while True:
        esk = os.urandom(32)
        try:
            epub = proto.schnorr_pubkey(esk).hex()
            break
        except ValueError:
            continue
    content = proto.envelope_seal(key, json.dumps(message, separators=(",", ":")).encode())
    event = proto.nostr_event(esk, proto.NOSTR_KIND, int(time.time()), dev["nostr_pub"], content)

    loop = asyncio.get_running_loop()
    result: asyncio.Future = loop.create_future()

    async def via(url: str):
        try:
            async with websockets.connect(url, open_timeout=8, close_timeout=2) as ws:
                sub = os.urandom(4).hex()
                await ws.send(json.dumps(["REQ", sub, {"kinds": [proto.NOSTR_KIND], "#p": [epub],
                                                       "since": int(time.time()) - proto.MAX_CLOCK_SKEW}]))
                await ws.send(json.dumps(["EVENT", event]))
                async for raw in ws:
                    msg = json.loads(raw)
                    if msg[0] == "OK" and msg[1] == event["id"] and not msg[2]:
                        log(f"{url} rejected the message: {msg[3] if len(msg) > 3 else ''}")
                    elif msg[0] == "EVENT" and len(msg) == 3:
                        ev = msg[2]
                        if ev.get("kind") != proto.NOSTR_KIND or ev.get("pubkey") != dev["nostr_pub"]:
                            continue
                        try:
                            reply = json.loads(proto.envelope_open(key, ev["content"]))
                        except Exception:
                            continue  # not for us / forged
                        try:
                            value = accept(reply)
                        except Exception as e:
                            if not result.done():
                                result.set_exception(e)
                            return
                        if value is not None and not result.done():
                            result.set_result(value)
                            return
        except Exception as e:  # one relay failing is fine
            log(f"relay {url}: {type(e).__name__}: {e}")

    tasks = [asyncio.create_task(via(u)) for u in cfg["relays"]]
    try:
        return await asyncio.wait_for(result, timeout)
    except asyncio.TimeoutError:
        die(timeout_msg)
    finally:
        for t in tasks:
            t.cancel()


async def rendezvous(cfg: dict, my_ep: str, lan: str | None, timeout: float = 25.0) -> dict:
    priv = proto.unb64(cfg["private_key"], 32)
    key = proto.envelope_key(priv, proto.unb64(cfg["device"]["wg_pub"], 32))
    knock, nonce = proto.make_knock(my_ep, lan)

    def accept(m):
        if m.get("v") != proto.PROTO_VERSION or m.get("t") != "ack" or m.get("n") != nonce:
            return None
        if abs(int(m.get("ts", 0)) - time.time()) > proto.MAX_CLOCK_SKEW:
            return None
        return m
    return await exchange(cfg, key, knock, accept, timeout,
                          "no answer from the device (offline? key not authorized or blocked? clock wrong?)")


async def pair_with(invite: dict, priv: bytes, timeout: float = 25.0) -> dict:
    key = proto.pair_key(invite["secret"])
    nonce = os.urandom(8).hex()
    msg = {"v": proto.PROTO_VERSION, "t": "pair", "ts": int(time.time()), "n": nonce,
           "pub": proto.b64(proto.wg_pubkey(priv))}

    def accept(m):
        if m.get("v") != proto.PROTO_VERSION or m.get("n") != nonce:
            return None
        if abs(int(m.get("ts", 0)) - time.time()) > proto.MAX_CLOCK_SKEW:
            return None
        if m.get("t") == "pair-error":
            raise RuntimeError(f"pairing refused by the device: {m.get('error', 'unknown reason')}")
        if m.get("t") == "paired" and re.fullmatch(r"\d+\.\d+\.\d+\.\d+/32", str(m.get("address", ""))):
            return m
        return None
    return await exchange(invite["cfg"], key, msg, accept, timeout,
                          "no answer from the device (offline? invite expired or already used?)")


def discover(port: int, stun: list[str]) -> tuple[str, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        die(f"UDP port {port} busy ({e}); is the tunnel already up? try --port")
    try:
        ip, mport = proto.stun_query(s, stun)
    finally:
        s.close()
    lan = f"{proto.local_ip()}:{port}"
    return f"{ip}:{mport}", lan


def pick_endpoint(ack: dict, my_ep: str) -> str:
    dev_ep, dev_lan = ack.get("ep") or "", ack.get("lan") or ""
    my_ip = my_ep.rpartition(":")[0]
    # Same public IP as the device => same network; most routers can't hairpin, so use the LAN
    # address. pub_ip comes from the device's STUN (works when ep is a DDNS name, too).
    dev_pub_ip = ack.get("pub_ip") or dev_ep.rpartition(":")[0]
    if dev_lan and my_ip and dev_pub_ip == my_ip:
        log("device is behind the same NAT; using its LAN address")
        proto.parse_endpoint(dev_lan)
        return dev_lan
    if not dev_ep:
        die("device doesn't know a reachable address yet (STUN blocked on its network?)")
    proto.parse_endpoint(dev_ep)
    return dev_ep


def knock(cfg: dict, args) -> tuple[str, str, str]:
    my_ep, lan = discover(args.port, args.stun)
    log(f"my public endpoint {my_ep} (LAN {lan})")
    ack = asyncio.run(rendezvous(cfg, my_ep, lan))
    ep = pick_endpoint(ack, my_ep)
    via = ack.get("via", "stun")
    how = "router port mapping" if via in ("upnp", "natpmp") else "manual endpoint" if via == "manual" else "hole punching"
    log(f"device answered: {ack.get('ep') or '?'} via {how} → using {ep}")
    return ep, my_ep, lan, via

# ---------------------------------------------------------------------------
# Linux WireGuard plumbing
# ---------------------------------------------------------------------------

def sh(*argv: str, input: str | None = None, check: bool = True):
    return subprocess.run(argv, input=input, text=True, check=check, capture_output=True)


def wg_up(cfg: dict, iface: str, port: int, endpoint: str):
    dev = cfg["device"]
    allowed = [dev["tunnel_ip"] + "/32"] + dev.get("routes", [])
    sh("ip", "link", "del", "dev", iface, check=False)
    sh("ip", "link", "add", "dev", iface, "type", "wireguard")
    sh("wg", "set", iface, "listen-port", str(port), "private-key", "/dev/stdin", input=cfg["private_key"] + "\n")
    sh("wg", "set", iface, "peer", dev["wg_pub"], "endpoint", endpoint,
       "allowed-ips", ",".join(allowed), "persistent-keepalive", "25")
    sh("ip", "address", "add", cfg["address"], "dev", iface)
    sh("ip", "link", "set", "mtu", "1420", "up", "dev", iface)
    for net in allowed:
        sh("ip", "route", "replace", net, "dev", iface)
    log(f"{iface} up: {cfg['address']} → device {dev['tunnel_ip']}, routes {', '.join(allowed)}")


def wg_down(iface: str):
    sh("ip", "link", "del", "dev", iface, check=False)
    log(f"{iface} removed")


def last_handshake(iface: str, peer: str) -> int:
    r = sh("wg", "show", iface, "latest-handshakes", check=False)
    for line in r.stdout.splitlines():
        k, _, v = line.partition("\t")
        if k == peer:
            return int(v or 0)
    return 0


def cmd_up(args):
    if not sys.platform.startswith("linux"):
        die("`up` manages a Linux WireGuard interface; on other systems use `resolve`")
    if os.geteuid() != 0:
        die("run as root (sudo) to create the WireGuard interface")
    for tool in ("wg", "ip"):
        if not shutil.which(tool):
            die(f"`{tool}` not found (install wireguard-tools / iproute2)")
    cfg = load_cfg(Path(args.config))
    require_joined(cfg)
    dev_pub = cfg["device"]["wg_pub"]

    ep, my_ep, lan, _ = knock(cfg, args)
    wg_up(cfg, args.iface, args.port, ep)

    stop = False

    def on_sig(*_):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    started, connected, last_knock = time.time(), False, time.time()
    try:
        while not stop:
            time.sleep(2)
            hs = last_handshake(args.iface, dev_pub)
            age = time.time() - hs if hs else None
            if hs and not connected:
                connected = True
                log(f"connected ✔  try: ping {cfg['device']['tunnel_ip']}   (Ctrl+C to disconnect)")
            if not hs and not connected and time.time() - started > 30:
                log("no handshake after 30 s: both sides may be behind symmetric NAT or UDP is blocked")
                started = time.time()
            # Stale session (device rebooted / NAT changed / we were blocked): re-knock.
            # Our own NAT mapping is kept alive by keepalives, so the original endpoint is reused.
            if (age is None or age > 180) and time.time() - last_knock > 60:
                connected = False
                last_knock = time.time()
                try:
                    ack = asyncio.run(rendezvous(cfg, my_ep, lan, timeout=15))
                    new_ep = pick_endpoint(ack, my_ep)
                    sh("wg", "set", args.iface, "peer", dev_pub, "endpoint", new_ep)
                    log(f"re-knocked, device at {new_ep}")
                except SystemExit:
                    log("device did not answer the re-knock (blocked or offline); retrying in 60 s")
    finally:
        wg_down(args.iface)


def cmd_resolve(args):
    cfg = load_cfg(Path(args.config))
    require_joined(cfg)
    ep, _, _, via = knock(cfg, args)
    dev = cfg["device"]
    allowed = ", ".join([dev["tunnel_ip"] + "/32"] + dev.get("routes", []))
    direct = via in proto.DIRECT_VIA
    head = ("# The device is directly reachable: this config keeps working until its public address changes.\n"
            if direct else
            f"# Hole punching: import into WireGuard within ~30 s; ListenPort MUST stay {args.port}.\n")
    listen = "" if direct else f"ListenPort = {args.port}\n"
    conf = f"""{head}[Interface]
PrivateKey = {cfg['private_key']}
Address = {cfg['address']}
{listen}
[Peer]
PublicKey = {dev['wg_pub']}
Endpoint = {ep}
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""
    if args.out:
        # Contains the private key: write a fresh 0600 file and rename it over the target, so an
        # existing file's permissions (or a symlink at the path) are never reused.
        out = Path(args.out)
        tmp = out.with_name(f".{out.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(conf)
        os.replace(tmp, out)
        log(f"wrote {args.out}: import it into the WireGuard app")
    else:
        print("\n" + conf)


def cmd_pair(args):
    path = Path(args.config)
    cfg = json.loads(path.read_text()) if path.exists() else {}
    invite = proto.parse_invite(args.invite)
    if "private_key" not in cfg:
        cfg["private_key"] = proto.b64(proto.wg_genkey())
        save_cfg(path, cfg)
        log(f"new key written to {path} (mode 600)")
    priv = proto.unb64(cfg["private_key"], 32)
    log(f"pairing with device {invite['cfg']['device']['wg_pub'][:12]}… as '{invite['name']}'")
    try:
        reply = asyncio.run(pair_with(invite, priv))
    except RuntimeError as e:
        die(str(e))
    cfg.update({"name": reply.get("name", invite["name"]), "address": reply["address"],
                "device": invite["cfg"]["device"], "relays": invite["cfg"]["relays"]})
    save_cfg(path, cfg)
    log(f"paired ✔ as {cfg['name']} ({cfg['address']}); config saved to {path}")
    log("next: sudo python3 p2ptun.py up   (Linux)   or   python3 p2ptun.py resolve -o p2ptun.conf")


def cmd_show(args):
    cfg = load_cfg(Path(args.config))
    print(proto.b64(proto.wg_pubkey(proto.unb64(cfg["private_key"], 32))))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default="p2ptun.json", help="client config file (default ./p2ptun.json)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("genkey", help="create a client key")
    g.add_argument("--force", action="store_true")
    j = sub.add_parser("join", help="store the device config shown by the web UI")
    j.add_argument("blob")
    for name, helptext in (("up", "connect (Linux, root)"), ("resolve", "print a wg-quick config (any OS)")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"local WireGuard UDP port (default {DEFAULT_PORT})")
        p.add_argument("--stun", nargs="+", default=DEFAULT_STUN, metavar="HOST:PORT")
        if name == "up":
            p.add_argument("--iface", default=DEFAULT_IFACE)
        else:
            p.add_argument("-o", "--out", help="write the config to this file (mode 600) instead of printing it")
    pr = sub.add_parser("pair", help="pair using an invite link/QR from the device web UI")
    pr.add_argument("invite", help="the invite link (https://…#p2ptun=…) or its p2ptun= value")
    sub.add_parser("pubkey", help="print this client's public key")
    args = ap.parse_args()
    {"genkey": cmd_genkey, "join": cmd_join, "up": cmd_up, "resolve": cmd_resolve, "pubkey": cmd_show,
     "pair": cmd_pair}[args.cmd](args)


if __name__ == "__main__":
    main()
