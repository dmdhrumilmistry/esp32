"""Cross-checks the browser client's crypto/protocol (web/p2ptun-proto.js, run under Node) against
Python `cryptography`, libsecp256k1 (coincurve) and the firmware's C code (tests/host/p2p_host)."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "tests"))
import p2ptun_proto as proto  # noqa: E402

HOST = ROOT / "tests" / "host" / "p2p_host"
NODE = shutil.which("node")

try:
    from coincurve import PrivateKey, PublicKeyXOnly
except ImportError:  # pragma: no cover
    PrivateKey = PublicKeyXOnly = None


def js(**req):
    r = subprocess.run([NODE, str(ROOT / "tests" / "web_harness.js")], input=json.dumps(req),
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout)


def c(*args):
    r = subprocess.run([str(HOST), *args], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


@unittest.skipUnless(NODE, "node not installed")
class TestWebCrypto(unittest.TestCase):
    def test_x25519_webcrypto_and_fallback_match_python(self):
        for _ in range(5):
            a, b = proto.wg_genkey(), proto.wg_genkey()
            out = js(cmd="x25519", priv=proto.b64(a), pub=proto.b64(proto.wg_pubkey(b)))
            want = proto.b64(X25519PrivateKey.from_private_bytes(a).exchange(
                X25519PublicKey.from_public_bytes(proto.wg_pubkey(b))))
            self.assertEqual(out["web"], want)
            self.assertEqual(out["js"], want)
            self.assertEqual(js(cmd="wgpub", priv=proto.b64(a))["pub"], proto.b64(proto.wg_pubkey(a)))

    def test_generated_key_is_valid_wireguard_key(self):
        k = js(cmd="genkey")
        priv = proto.unb64(k["priv"], 32)
        self.assertEqual(priv[0] & 7, 0)
        self.assertEqual(priv[31] & 0xC0, 0x40)
        self.assertEqual(k["pub"], proto.b64(proto.wg_pubkey(priv)))

    def test_chacha20poly1305_matches_cryptography(self):
        for n in (0, 1, 15, 16, 17, 63, 64, 65, 300):
            key, nonce, pt, aad = os.urandom(32), os.urandom(12), os.urandom(n), os.urandom(n % 23)
            want = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
            got = js(cmd="aead_enc", key=key.hex(), nonce=nonce.hex(), pt=pt.hex(), aad=aad.hex())["out"]
            self.assertEqual(got, want.hex(), n)
            self.assertEqual(js(cmd="aead_dec", key=key.hex(), nonce=nonce.hex(), ct=want.hex(), aad=aad.hex())["out"], pt.hex())
        bad = bytearray(want)
        bad[-1] ^= 1
        self.assertIn("error", js(cmd="aead_dec", key=key.hex(), nonce=nonce.hex(), ct=bytes(bad).hex(), aad=aad.hex()))

    @unittest.skipUnless(PrivateKey, "coincurve missing")
    def test_schnorr_matches_libsecp256k1(self):
        for _ in range(4):
            sk, msg, aux = os.urandom(32), os.urandom(32), os.urandom(32)
            self.assertEqual(js(cmd="pubkey", sk=sk.hex())["pub"], proto.schnorr_pubkey(sk).hex())
            self.assertEqual(js(cmd="sign", sk=sk.hex(), msg=msg.hex(), aux=aux.hex())["sig"],
                             PrivateKey(sk).sign_schnorr(msg, aux).hex())

    @unittest.skipUnless(PublicKeyXOnly, "coincurve missing")
    def test_nostr_event_valid(self):
        sk, p = os.urandom(32), os.urandom(32).hex()
        content = proto.b64(os.urandom(60))
        ev = js(cmd="event", sk=sk.hex(), kind=proto.NOSTR_KIND, created_at=1730000000, p=p, content=content)
        ref = proto.nostr_event(sk, proto.NOSTR_KIND, 1730000000, p, content)
        self.assertEqual(ev["id"], ref["id"])
        self.assertTrue(PublicKeyXOnly(bytes.fromhex(ev["pubkey"])).verify(bytes.fromhex(ev["sig"]), bytes.fromhex(ev["id"])))


@unittest.skipUnless(NODE and HOST.exists(), "needs node and tests/host/p2p_host")
class TestWebEnvelopeInterop(unittest.TestCase):
    def setUp(self):
        self.dev, self.cli = proto.wg_genkey(), proto.wg_genkey()
        self.dev_pub, self.cli_pub = proto.wg_pubkey(self.dev), proto.wg_pubkey(self.cli)

    def test_js_to_c_and_python(self):
        content = js(cmd="seal", priv=proto.b64(self.cli), pub=proto.b64(self.dev_pub), pt='{"t":"knock"}')["content"]
        self.assertEqual(c("open", proto.b64(self.dev), proto.b64(self.cli_pub), content), (0, '{"t":"knock"}'))
        self.assertEqual(proto.envelope_open(proto.envelope_key(self.dev, self.cli_pub), content), b'{"t":"knock"}')

    def test_c_to_js_and_wrong_key(self):
        _, content = c("seal", proto.b64(self.dev), proto.b64(self.cli_pub), '{"t":"ack"}')
        self.assertEqual(js(cmd="open", priv=proto.b64(self.cli), pub=proto.b64(self.dev_pub), content=content)["pt"], '{"t":"ack"}')
        other = proto.wg_pubkey(proto.wg_genkey())
        self.assertIn("error", js(cmd="open", priv=proto.b64(self.cli), pub=proto.b64(other), content=content))


DEVICE_BLOB = {"name": "phone", "address": "10.77.0.4/32",
               "device": {"wg_pub": proto.b64(b"\x01" * 32), "nostr_pub": "ab" * 32, "tunnel_ip": "10.77.0.1",
                          "routes": ["192.168.1.0/24"]},
               "relays": ["wss://relay.damus.io", "ws://insecure.example", "wss://x\"><script>"]}


@unittest.skipUnless(NODE, "node not installed")
class TestWebConfig(unittest.TestCase):
    def test_parse_from_command_and_filters_relays(self):
        cmd = "python3 p2ptun.py join '" + json.dumps(DEVICE_BLOB) + "'"
        cfg = js(cmd="parse_config", text=cmd)
        self.assertEqual(cfg["relays"], ["wss://relay.damus.io"])
        self.assertEqual(cfg["device"]["routes"], ["192.168.1.0/24"])
        bad = json.loads(json.dumps(DEVICE_BLOB))
        bad["device"]["routes"] = ["192.168.1.0/24\nPostUp = rm -rf /"]
        self.assertIn("error", js(cmd="parse_config", text=json.dumps(bad)))
        self.assertIn("error", js(cmd="parse_config", text="hello"))

    def test_wireguard_config_text(self):
        cfg = js(cmd="parse_config", text=json.dumps(DEVICE_BLOB))
        conf = js(cmd="wgconfig", priv="PRIV=", cfg=cfg, endpoint="198.51.100.20:51820", listen_port=None)["conf"]
        self.assertIn("Endpoint = 198.51.100.20:51820", conf)
        self.assertIn("AllowedIPs = 10.77.0.1/32, 192.168.1.0/24", conf)
        self.assertNotIn("ListenPort", conf)
        self.assertIn("ListenPort = 51821", js(cmd="wgconfig", priv="P", cfg=cfg, endpoint="a:1", listen_port=51821)["conf"])

    def test_pick_endpoint(self):
        ack = {"ep": "198.51.100.20:51820", "via": "upnp", "lan": "192.168.1.50:51820"}
        r = js(cmd="pick", ack=ack, client_ip="203.0.113.9")
        self.assertEqual((r["endpoint"], r["direct"], r["notes"]), ("198.51.100.20:51820", True, []))
        r = js(cmd="pick", ack=ack, client_ip="198.51.100.20")         # same NAT as the device
        self.assertEqual(r["endpoint"], "192.168.1.50:51820")
        r = js(cmd="pick", ack=dict(ack, via="stun"), client_ip=None)  # no router mapping: warn
        self.assertFalse(r["direct"])
        self.assertTrue(r["notes"])
        self.assertIn("error", js(cmd="pick", ack={"ep": "", "lan": ""}, client_ip=None))

    def test_passphrase_lock(self):
        r = js(**{"cmd": "lock", "priv": proto.b64(b"\x07" * 32), "pass": "correct horse"})
        self.assertEqual(r["back"], proto.b64(b"\x07" * 32))
        self.assertEqual(r["wrong"], "wrong passphrase")


@unittest.skipUnless(NODE and HOST.exists(), "needs node and tests/host/p2p_host")
class TestWebRendezvous(unittest.TestCase):
    """Browser client code (under Node's WebSocket) <-> local verifying relay <-> simulated C device."""

    def test_js_client_gets_ack_without_endpoint(self):
        from test_rendezvous import Relay, SimDevice, websockets  # noqa: E402
        if websockets is None:
            self.skipTest("websockets missing")

        async def scenario():
            relay = Relay()
            async with websockets.serve(relay.handler, "127.0.0.1", 0) as server:
                url = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}"
                cli = proto.wg_genkey()
                dev = SimDevice(url, [proto.wg_pubkey(cli)])
                ready = asyncio.Event()
                task = asyncio.create_task(dev.run(ready))
                await ready.wait()
                cfg = {"address": "10.77.0.4/32", "relays": [url],
                       "device": {"wg_pub": proto.b64(dev.pub), "nostr_pub": dev.npub, "tunnel_ip": "10.77.0.1",
                                  "routes": []}}
                proc = await asyncio.create_subprocess_exec(
                    NODE, str(ROOT / "tests" / "web_harness.js"), stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE)
                out, _ = await proc.communicate(json.dumps({"cmd": "rendezvous", "cfg": cfg, "priv": proto.b64(cli)}).encode())
                task.cancel()
                return json.loads(out), dev, relay
        res, dev, relay = asyncio.run(scenario())
        self.assertNotIn("error", res, res)
        self.assertEqual(res["ack"]["ep"], dev.public_ep)
        self.assertEqual(relay.rejected, 0)   # JS-signed knock passed signature verification
        self.assertEqual(dev.punched, [None])  # browser knock carries no endpoint


if __name__ == "__main__":
    unittest.main()
