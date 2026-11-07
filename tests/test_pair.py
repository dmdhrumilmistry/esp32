"""One-scan pairing end-to-end (docs/PROTOCOL.md "Pairing"): Python and browser clients <-> local
signature-verifying Nostr relay <-> simulated device whose crypto runs through the firmware's C code.
Also covers invite parsing and the DNS-endpoint same-NAT fix."""
import asyncio
import base64
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "tests"))
import p2ptun_proto as proto  # noqa: E402
import p2ptun  # noqa: E402
from test_rendezvous import HOST, Relay, SimDevice, websockets  # noqa: E402

NODE = shutil.which("node")


def js(**req):
    r = subprocess.run([NODE, str(ROOT / "tests" / "web_harness.js")], input=json.dumps(req),
                       capture_output=True, text=True, timeout=60)
    return json.loads(r.stdout)


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def invite_link(blob):
    return "https://example.github.io/esp32/#p2ptun=" + b64u(json.dumps(blob).encode())


GOOD = {"v": 1, "name": "phone", "secret": b64u(b"\x05" * 16),
        "device": {"wg_pub": proto.b64(b"\x01" * 32), "nostr_pub": "ab" * 32, "tunnel_ip": "10.77.0.1",
                   "routes": ["192.168.1.0/24"]},
        "relays": ["wss://relay.example", "ws://insecure.example"]}


class TestInviteParsing(unittest.TestCase):
    def check_py(self, text):
        return proto.parse_invite(text)

    def test_python_accepts_link_fragment_and_blob(self):
        link = invite_link(GOOD)
        for text in (link, "#" + link.split("#")[1], link.split("p2ptun=")[1]):
            inv = self.check_py(text)
            self.assertEqual(inv["name"], "phone")
            self.assertEqual(inv["secret"], b"\x05" * 16)
            self.assertEqual(inv["cfg"]["relays"], ["wss://relay.example"])

    def test_python_rejects_bad_invites(self):
        for bad in ({**GOOD, "secret": b64u(b"\x05" * 8)}, {**GOOD, "v": 2}, {**GOOD, "relays": ["ws://x"]},
                    {**GOOD, "device": {**GOOD["device"], "nostr_pub": "XY" * 32}}):
            with self.assertRaises(Exception):
                self.check_py(invite_link(bad))
        with self.assertRaises(Exception):
            self.check_py("https://example/#nothing-here")

    @unittest.skipUnless(NODE, "node not installed")
    def test_js_matches_python(self):
        r = js(cmd="parse_invite", text=invite_link(GOOD))
        self.assertEqual(r["name"], "phone")
        self.assertEqual(r["secret"], "05" * 16)
        self.assertEqual(r["cfg"]["relays"], ["wss://relay.example"])
        self.assertNotIn("address", r["cfg"])
        self.assertIn("error", js(cmd="parse_invite", text=invite_link({**GOOD, "secret": b64u(b"\x05" * 4)})))
        self.assertIn("error", js(cmd="parse_invite", text="https://x/#p2ptun=!!!"))


class TestSameNatDetection(unittest.TestCase):
    """The device reports pub_ip so clients detect 'same network' even when ep is a DNS name."""
    ACK = {"ep": "home.example.org:51820", "via": "manual", "lan": "192.168.1.50:51820", "pub_ip": "198.51.100.20"}

    def test_python(self):
        self.assertEqual(p2ptun.pick_endpoint(self.ACK, "198.51.100.20:40000"), "192.168.1.50:51820")
        self.assertEqual(p2ptun.pick_endpoint(self.ACK, "203.0.113.9:40000"), "home.example.org:51820")

    @unittest.skipUnless(NODE, "node not installed")
    def test_js(self):
        self.assertEqual(js(cmd="pick", ack=self.ACK, client_ip="198.51.100.20")["endpoint"], "192.168.1.50:51820")
        self.assertEqual(js(cmd="pick", ack=self.ACK, client_ip="203.0.113.9")["endpoint"], "home.example.org:51820")
        # no reachable endpoint must be an error, not a LAN-only config claiming "same network"
        self.assertIn("error", js(cmd="pick", ack={"ep": "", "lan": "192.168.1.50:51820"}, client_ip=None))


@unittest.skipUnless(HOST.exists() and websockets, "needs tests/host/p2p_host and websockets")
class TestPairing(unittest.TestCase):
    def scenario(self, steps):
        async def run():
            relay = Relay()
            async with websockets.serve(relay.handler, "127.0.0.1", 0) as server:
                url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                dev = SimDevice(url, [])
                ready = asyncio.Event()
                task = asyncio.create_task(dev.run(ready))
                await ready.wait()
                try:
                    return await steps(dev, url), dev, relay
                finally:
                    task.cancel()
        return asyncio.run(run())

    def test_python_pair_then_knock(self):
        async def steps(dev, url):
            link = dev.add_invite("laptop")
            inv = proto.parse_invite(link)
            inv["cfg"]["relays"] = [url]
            priv = proto.wg_genkey()
            reply = await p2ptun.pair_with(inv, priv, timeout=6)
            # the new key is now authorized: a normal knock gets an ack
            cfg = {"private_key": proto.b64(priv), "address": reply["address"], **inv["cfg"]}
            ack = await p2ptun.rendezvous(cfg, "203.0.113.9:40001", None, timeout=6)
            retry = await p2ptun.pair_with(inv, priv, timeout=6)            # lost-ack retry: idempotent
            with self.assertRaises(RuntimeError) as err:                     # someone else: refused
                await p2ptun.pair_with(inv, proto.wg_genkey(), timeout=6)
            return reply, ack, retry, str(err.exception)
        (reply, ack, retry, err), dev, relay = self.scenario(steps)
        self.assertEqual(reply["t"], "paired")
        self.assertEqual(reply["address"], "10.77.0.10/32")
        self.assertEqual(ack["ep"], dev.public_ep)
        self.assertEqual(retry["address"], "10.77.0.10/32")
        self.assertIn("already used", err)
        self.assertEqual(relay.rejected, 0)

    def test_wrong_secret_gets_no_answer(self):
        async def steps(dev, url):
            dev.add_invite("phone")
            forged = proto.parse_invite(invite_link({**GOOD, "device": {**GOOD["device"], "wg_pub": proto.b64(dev.pub),
                                                                        "nostr_pub": dev.npub}}))
            forged["cfg"]["relays"] = [url]
            with self.assertRaises(SystemExit):
                await p2ptun.pair_with(forged, proto.wg_genkey(), timeout=2)
        self.scenario(steps)

    @unittest.skipUnless(NODE, "node not installed")
    def test_browser_pair_then_knock(self):
        async def steps(dev, url):
            link = dev.add_invite("phone")
            priv = proto.wg_genkey()

            async def node(req):
                p = await asyncio.create_subprocess_exec(NODE, str(ROOT / "tests" / "web_harness.js"),
                                                         stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
                out, _ = await p.communicate(json.dumps(req).encode())
                return json.loads(out)
            paired = await node({"cmd": "pair", "link": link, "priv": proto.b64(priv), "relays": [url]})
            knock = await node({"cmd": "rendezvous", "cfg": paired.get("cfg", {}), "priv": proto.b64(priv)})
            other = await node({"cmd": "pair", "link": link, "priv": proto.b64(proto.wg_genkey()), "relays": [url]})
            return paired, knock, other
        (paired, knock, other), dev, relay = self.scenario(steps)
        self.assertNotIn("error", paired, paired)
        self.assertEqual(paired["cfg"]["address"], "10.77.0.10/32")
        self.assertEqual(paired["cfg"]["name"], "phone")
        self.assertEqual(paired["cfg"]["device"]["wg_pub"], proto.b64(dev.pub))
        self.assertEqual(knock["ack"]["ep"], dev.public_ep)
        self.assertIn("already used", other["error"])
        self.assertEqual(relay.rejected, 0)


if __name__ == "__main__":
    unittest.main()
