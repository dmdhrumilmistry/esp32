"""End-to-end rendezvous test: real client code <-> local Nostr relay <-> simulated device.

The simulated device does all of its crypto (envelope open/seal, BIP-340 signed Nostr event)
through the firmware's C code built for the host (tests/host/p2p_host), so this checks that the
ESP32 and the client really understand each other over a relay that verifies signatures.
"""
import asyncio
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
import p2ptun_proto as proto  # noqa: E402
import p2ptun  # noqa: E402

HOST = ROOT / "tests" / "host" / "p2p_host"

try:
    import websockets
    from coincurve import PublicKeyXOnly
except ImportError:  # pragma: no cover
    websockets = None


def c(*args):
    r = subprocess.run([str(HOST), *args], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


class Relay:
    """Minimal NIP-01 relay: verifies id + signature, fans EVENTs out to matching REQs."""

    def __init__(self):
        self.subs = {}  # ws -> list of (sub_id, filter)
        self.rejected = 0

    @staticmethod
    def valid(ev):
        ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
                         separators=(",", ":"), ensure_ascii=False)
        import hashlib
        if hashlib.sha256(ser.encode()).hexdigest() != ev["id"]:
            return False
        return PublicKeyXOnly(bytes.fromhex(ev["pubkey"])).verify(bytes.fromhex(ev["sig"]), bytes.fromhex(ev["id"]))

    @staticmethod
    def matches(f, ev):
        if "kinds" in f and ev["kind"] not in f["kinds"]:
            return False
        if "#p" in f and not any(t[0] == "p" and t[1] in f["#p"] for t in ev["tags"]):
            return False
        return True

    async def handler(self, ws):
        self.subs[ws] = []
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg[0] == "REQ":
                    self.subs[ws].append((msg[1], msg[2]))
                    await ws.send(json.dumps(["EOSE", msg[1]]))
                elif msg[0] == "EVENT":
                    ev = msg[1]
                    ok = self.valid(ev)
                    await ws.send(json.dumps(["OK", ev["id"], ok, "" if ok else "invalid: bad signature"]))
                    if not ok:
                        self.rejected += 1
                        continue
                    for other, subs in list(self.subs.items()):
                        for sid, f in subs:
                            if self.matches(f, ev):
                                try:
                                    await other.send(json.dumps(["EVENT", sid, ev]))
                                except websockets.ConnectionClosed:
                                    pass
        except websockets.ConnectionClosed:
            pass
        finally:
            self.subs.pop(ws, None)


class SimDevice:
    """Device-side protocol, crypto done by the C firmware code."""

    def __init__(self, url, authorized_pubs):
        self.url = url
        self.priv = proto.wg_genkey()
        self.pub = proto.wg_pubkey(self.priv)
        _, self.nsk = c("nostrsk", proto.b64(self.priv))
        _, self.npub = c("pubkey", self.nsk)
        self.authorized = authorized_pubs
        self.public_ep = "198.51.100.20:51820"
        self.punched = []
        self.last_ts = {}

    async def run(self, ready: asyncio.Event):
        async with websockets.connect(self.url) as ws:
            await ws.send(json.dumps(["REQ", "p2ptun", {"kinds": [proto.NOSTR_KIND], "#p": [self.npub]}]))
            ready.set()
            async for raw in ws:
                msg = json.loads(raw)
                if msg[0] != "EVENT":
                    continue
                ev = msg[2]
                for pub in self.authorized:
                    rc, pt = c("open", proto.b64(self.priv), proto.b64(pub), ev["content"])
                    if rc != 0:
                        continue
                    knock = json.loads(pt)
                    if knock["t"] != "knock" or knock["ts"] <= self.last_ts.get(pub, 0):
                        break
                    self.last_ts[pub] = knock["ts"]
                    self.punched.append(knock["ep"])
                    ack = json.dumps({"v": 1, "t": "ack", "ts": int(time.time()), "n": knock["n"],
                                      "ep": self.public_ep, "lan": "192.168.1.50:51820"}, separators=(",", ":"))
                    _, content = c("seal", proto.b64(self.priv), proto.b64(pub), ack)
                    _, out = c("event", self.nsk, str(proto.NOSTR_KIND), str(int(time.time())), ev["pubkey"], content)
                    await ws.send(json.dumps(["EVENT", json.loads(out)]))
                    break


@unittest.skipUnless(HOST.exists() and websockets, "needs tests/host/p2p_host, websockets, coincurve")
class TestRendezvous(unittest.TestCase):
    def run_scenario(self, client_authorized: bool, timeout=6):
        async def scenario():
            relay = Relay()
            async with websockets.serve(relay.handler, "127.0.0.1", 0) as server:
                port = server.sockets[0].getsockname()[1]
                url = f"ws://127.0.0.1:{port}"
                client_priv = proto.wg_genkey()
                client_pub = proto.wg_pubkey(client_priv)
                dev = SimDevice(url, [client_pub] if client_authorized else [proto.wg_pubkey(proto.wg_genkey())])
                ready = asyncio.Event()
                dev_task = asyncio.create_task(dev.run(ready))
                await ready.wait()
                cfg = {"private_key": proto.b64(client_priv), "address": "10.77.0.2/32",
                       "device": {"wg_pub": proto.b64(dev.pub), "nostr_pub": dev.npub,
                                  "tunnel_ip": "10.77.0.1", "routes": ["192.168.1.0/24"]},
                       "relays": [url, url]}  # duplicate relay: device must answer once, client accept once
                try:
                    ack = await p2ptun.rendezvous(cfg, "203.0.113.9:40001", "10.0.0.5:51821", timeout=timeout)
                finally:
                    dev_task.cancel()
                return ack, dev, relay
        return asyncio.run(scenario())

    def test_authorized_client_gets_device_endpoint(self):
        ack, dev, relay = self.run_scenario(True)
        self.assertEqual(ack["ep"], "198.51.100.20:51820")
        self.assertEqual(dev.punched, ["203.0.113.9:40001"])  # duplicate delivery was ignored
        self.assertEqual(relay.rejected, 0)                    # every C-signed event verified
        self.assertEqual(p2ptun.pick_endpoint(ack, "203.0.113.9:40001"), "198.51.100.20:51820")
        # same public IP -> LAN address of the device
        self.assertEqual(p2ptun.pick_endpoint(ack, "198.51.100.20:1234"), "192.168.1.50:51820")

    def test_unauthorized_client_gets_nothing(self):
        with self.assertRaises(SystemExit):
            self.run_scenario(False, timeout=2)


if __name__ == "__main__":
    unittest.main()
