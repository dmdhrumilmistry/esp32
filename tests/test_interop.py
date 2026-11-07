"""Cross-checks the firmware's portable C crypto/STUN code (built for the host) against the
Python client and against libsecp256k1 (coincurve).

    make -C tests/host && python3 -m unittest discover -s tests -v
"""
import json
import os
import socket
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client"))
import p2ptun_proto as proto  # noqa: E402

HOST = ROOT / "tests" / "host" / "p2p_host"

try:
    from coincurve import PrivateKey, PublicKeyXOnly
except ImportError:  # pragma: no cover
    PrivateKey = PublicKeyXOnly = None


def c(*args, ok=True):
    r = subprocess.run([str(HOST), *args], capture_output=True, text=True)
    if ok and r.returncode != 0:
        raise AssertionError(f"p2p_host {args[0]} failed rc={r.returncode}: {r.stderr}")
    return r.returncode, r.stdout.strip()


# BIP-340 official test vectors 0, 1 and 3 (secret key, aux_rand, message, signature).
BIP340 = [
    ("0000000000000000000000000000000000000000000000000000000000000003",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
     "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
     "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
    ("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
     "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
     "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"),
]


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestSchnorr(unittest.TestCase):
    def test_bip340_vectors_c_and_python(self):
        for sk, aux, msg, sig in BIP340:
            _, got = c("sign", sk.lower(), msg.lower(), aux.lower())
            self.assertEqual(got, sig.lower(), f"C sig mismatch for sk={sk}")
            py = proto.schnorr_sign(bytes.fromhex(sk), bytes.fromhex(msg), bytes.fromhex(aux))
            self.assertEqual(py.hex(), sig.lower(), f"Python sig mismatch for sk={sk}")

    def test_random_keys_c_matches_python_and_libsecp256k1(self):
        for _ in range(10):
            sk, msg, aux = os.urandom(32), os.urandom(32), os.urandom(32)
            _, pub = c("pubkey", sk.hex())
            self.assertEqual(pub, proto.schnorr_pubkey(sk).hex())
            _, sig = c("sign", sk.hex(), msg.hex(), aux.hex())
            self.assertEqual(sig, proto.schnorr_sign(sk, msg, aux).hex())
            if PublicKeyXOnly:
                self.assertTrue(PublicKeyXOnly(bytes.fromhex(pub)).verify(bytes.fromhex(sig), msg))
                # BIP-340 signing is deterministic given aux: must equal libsecp256k1 byte-for-byte
                self.assertEqual(sig, PrivateKey(sk).sign_schnorr(msg, aux).hex())

    def test_invalid_secret_keys_rejected(self):
        self.assertEqual(c("pubkey", "00" * 32, ok=False)[0], 1)
        n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        self.assertEqual(c("pubkey", n, ok=False)[0], 1)

    def test_nostr_key_derivation_matches(self):
        for _ in range(5):
            wg = proto.wg_genkey()
            _, sk = c("nostrsk", proto.b64(wg))
            self.assertEqual(sk, proto.nostr_key_from_wg(wg).hex())


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestNostrEvent(unittest.TestCase):
    def test_c_event_is_valid_nip01(self):
        sk = os.urandom(32)
        p = os.urandom(32).hex()
        content = proto.b64(os.urandom(90))
        _, out = c("event", sk.hex(), str(proto.NOSTR_KIND), "1730000000", p, content)
        ev = json.loads(out)
        ref = proto.nostr_event(sk, proto.NOSTR_KIND, 1730000000, p, content)
        # id is deterministic; sig uses random aux so compare by verification
        self.assertEqual(ev["id"], ref["id"])
        self.assertEqual(ev["pubkey"], ref["pubkey"])
        self.assertEqual(ev["tags"], [["p", p]])
        self.assertEqual(ev["content"], content)
        if PublicKeyXOnly:
            self.assertTrue(PublicKeyXOnly(bytes.fromhex(ev["pubkey"])).verify(
                bytes.fromhex(ev["sig"]), bytes.fromhex(ev["id"])))
            self.assertTrue(PublicKeyXOnly(bytes.fromhex(ref["pubkey"])).verify(
                bytes.fromhex(ref["sig"]), bytes.fromhex(ref["id"])))

    def test_c_event_rejects_injection(self):
        sk = os.urandom(32).hex()
        p = os.urandom(32).hex()
        self.assertNotEqual(c("event", sk, "1", "1", p, 'x","tags":[]', ok=False)[0], 0)
        self.assertNotEqual(c("event", sk, "1", "1", p.upper(), "QQ==", ok=False)[0], 0)


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.dev_priv, self.cli_priv = proto.wg_genkey(), proto.wg_genkey()
        self.dev_pub, self.cli_pub = proto.wg_pubkey(self.dev_priv), proto.wg_pubkey(self.cli_priv)

    def test_wg_pubkey_matches(self):
        _, pub = c("wgpub", proto.b64(self.dev_priv))
        self.assertEqual(pub, proto.b64(self.dev_pub))

    def test_python_to_c(self):
        key = proto.envelope_key(self.cli_priv, self.dev_pub)
        msg = json.dumps({"v": 1, "t": "knock", "ts": 1, "n": "ab", "ep": "1.2.3.4:5"})
        content = proto.envelope_seal(key, msg.encode())
        _, pt = c("open", proto.b64(self.dev_priv), proto.b64(self.cli_pub), content)
        self.assertEqual(pt, msg)

    def test_c_to_python(self):
        _, content = c("seal", proto.b64(self.dev_priv), proto.b64(self.cli_pub), '{"t":"ack"}')
        key = proto.envelope_key(self.cli_priv, self.dev_pub)
        self.assertEqual(proto.envelope_open(key, content), b'{"t":"ack"}')

    def test_wrong_peer_and_tamper_rejected(self):
        key = proto.envelope_key(self.cli_priv, self.dev_pub)
        content = proto.envelope_seal(key, b"hello")
        other = proto.wg_pubkey(proto.wg_genkey())
        self.assertEqual(c("open", proto.b64(self.dev_priv), proto.b64(other), content, ok=False)[0], 3)
        raw = bytearray(proto.unb64(content))
        raw[15] ^= 1
        self.assertEqual(c("open", proto.b64(self.dev_priv), proto.b64(self.cli_pub),
                           proto.b64(bytes(raw)), ok=False)[0], 3)
        self.assertEqual(c("open", proto.b64(self.dev_priv), proto.b64(self.cli_pub), "AAAA", ok=False)[0], 3)


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestStun(unittest.TestCase):
    def test_request_matches(self):
        txid = os.urandom(12)
        _, req = c("stunreq", txid.hex())
        self.assertEqual(req, proto.stun_request(txid).hex())

    def _resp(self, txid, ip, port, xor=True, extra=b""):
        ipb = socket.inet_aton(ip)
        if xor:
            port ^= proto.STUN_MAGIC >> 16
            ipb = bytes(a ^ b for a, b in zip(ipb, struct.pack("!I", proto.STUN_MAGIC)))
        attr = struct.pack("!HHBBH", 0x0020 if xor else 0x0001, 8, 0, 1, port) + ipb
        body = extra + attr
        return struct.pack("!HHI", 0x0101, len(body), proto.STUN_MAGIC) + txid + body

    def test_parse_xor_and_plain(self):
        txid = os.urandom(12)
        # unknown attribute with padding first (SOFTWARE, 5 bytes -> padded to 8)
        extra = struct.pack("!HH", 0x8022, 5) + b"abcde\0\0\0"
        for xor in (True, False):
            pkt = self._resp(txid, "203.0.113.7", 40001, xor=xor, extra=extra)
            _, got = c("stunparse", pkt.hex(), txid.hex())
            self.assertEqual(got, "203.0.113.7:40001")
            self.assertEqual(proto.stun_parse(pkt, txid), ("203.0.113.7", 40001))

    def test_parse_rejects_wrong_txid_and_truncation(self):
        txid = os.urandom(12)
        pkt = self._resp(txid, "198.51.100.1", 1234)
        self.assertEqual(c("stunparse", pkt.hex(), os.urandom(12).hex(), ok=False)[0], 3)
        self.assertEqual(c("stunparse", pkt[:-2].hex(), txid.hex(), ok=False)[0], 3)
        bad = bytearray(pkt)
        bad[22:24] = struct.pack("!H", 200)  # attribute length overruns packet
        self.assertEqual(c("stunparse", bytes(bad).hex(), txid.hex(), ok=False)[0], 3)

    def test_wireguard_packets_not_mistaken_for_stun(self):
        txid = os.urandom(12)
        wg_init = bytes([1, 0, 0, 0]) + os.urandom(144)
        self.assertEqual(c("stunparse", wg_init.hex(), txid.hex(), ok=False)[0], 3)


if __name__ == "__main__":
    unittest.main()
