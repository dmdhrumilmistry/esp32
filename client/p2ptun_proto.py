"""p2ptun signaling protocol (client side). Mirrors firmware/main/p2p_crypto.c and p2p_stun.c.

See docs/PROTOCOL.md for the wire format.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

NOSTR_KIND = 21820           # ephemeral range: relays forward, don't store
PROTO_VERSION = 1
ENVELOPE_AAD = b"p2ptun-v1"
ENVELOPE_LABEL = b"p2ptun-signal-v1"
MAX_CLOCK_SKEW = 120         # seconds

# ---------------------------------------------------------------------------
# WireGuard / X25519
# ---------------------------------------------------------------------------

def wg_genkey() -> bytes:
    raw = X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    b = bytearray(raw)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def wg_pubkey(priv: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str, n: int | None = None) -> bytes:
    b = base64.b64decode(s, validate=True)
    if n is not None and len(b) != n:
        raise ValueError(f"expected {n} bytes, got {len(b)}")
    return b

# ---------------------------------------------------------------------------
# Envelope: X25519(wg keys) -> HMAC-SHA256 -> ChaCha20-Poly1305
# ---------------------------------------------------------------------------

def envelope_key(my_wg_priv: bytes, peer_wg_pub: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(my_wg_priv).exchange(
        X25519PublicKey.from_public_bytes(peer_wg_pub))
    return hmac.new(shared, ENVELOPE_LABEL, hashlib.sha256).digest()


def envelope_seal(key: bytes, plaintext: bytes) -> str:
    nonce = os.urandom(12)
    return b64(nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, ENVELOPE_AAD))


def envelope_open(key: bytes, content: str) -> bytes:
    raw = base64.b64decode(content, validate=True)
    if len(raw) < 28:
        raise ValueError("short envelope")
    return ChaCha20Poly1305(key).decrypt(raw[:12], raw[12:], ENVELOPE_AAD)

# ---------------------------------------------------------------------------
# BIP-340 Schnorr (pure Python; only used to sign small signaling events)
# ---------------------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], _P - 2, _P) % _P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], _P - 2, _P) % _P
    x3 = (lam * lam - p1[0] - p2[0]) % _P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % _P)


def _mul(p, n):
    r = None
    while n:
        if n & 1:
            r = _add(r, p)
        p = _add(p, p)
        n >>= 1
    return r


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def schnorr_pubkey(sk: bytes) -> bytes:
    d = int.from_bytes(sk, "big")
    if not 0 < d < _N:
        raise ValueError("invalid secret key")
    return _mul(_G, d)[0].to_bytes(32, "big")


def schnorr_sign(sk: bytes, msg: bytes, aux: bytes | None = None) -> bytes:
    aux = os.urandom(32) if aux is None else aux
    d0 = int.from_bytes(sk, "big")
    if not 0 < d0 < _N:
        raise ValueError("invalid secret key")
    P = _mul(_G, d0)
    d = d0 if P[1] % 2 == 0 else _N - d0
    px = P[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + px + msg), "big") % _N
    if k0 == 0:
        raise ValueError("bad nonce")
    R = _mul(_G, k0)
    k = k0 if R[1] % 2 == 0 else _N - k0
    rx = R[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx + px + msg), "big") % _N
    return rx + ((k + e * d) % _N).to_bytes(32, "big")


def nostr_key_from_wg(wg_priv: bytes) -> bytes:
    sk = hashlib.sha256(b"p2ptun/nostr/v1" + wg_priv).digest()
    while not 0 < int.from_bytes(sk, "big") < _N:
        sk = hashlib.sha256(sk).digest()
    return sk

# ---------------------------------------------------------------------------
# Nostr events (NIP-01)
# ---------------------------------------------------------------------------

def nostr_event(sk: bytes, kind: int, created_at: int, p_tag: str, content: str) -> dict:
    pub = schnorr_pubkey(sk).hex()
    tags = [["p", p_tag]]
    ser = json.dumps([0, pub, created_at, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).digest()
    return {"id": eid.hex(), "pubkey": pub, "created_at": created_at, "kind": kind,
            "tags": tags, "content": content, "sig": schnorr_sign(sk, eid).hex()}

# ---------------------------------------------------------------------------
# Signaling messages
# ---------------------------------------------------------------------------

def make_knock(ep: str, lan: str | None) -> tuple[dict, str]:
    nonce = os.urandom(8).hex()
    msg = {"v": PROTO_VERSION, "t": "knock", "ts": int(time.time()), "n": nonce, "ep": ep}
    if lan:
        msg["lan"] = lan
    return msg, nonce


def parse_ack(pt: bytes, expect_nonce: str) -> dict:
    msg = json.loads(pt)
    if msg.get("v") != PROTO_VERSION or msg.get("t") != "ack" or msg.get("n") != expect_nonce:
        raise ValueError("not our ack")
    if abs(int(msg.get("ts", 0)) - time.time()) > MAX_CLOCK_SKEW:
        raise ValueError("stale ack")
    return msg


def parse_endpoint(s: str) -> tuple[str, int]:
    """host:port where host is an IPv4 literal or a DNS name (manual endpoint / DDNS)."""
    host, _, port = s.rpartition(":")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,63}", host or ""):
        raise ValueError("bad endpoint host")
    p = int(port)
    if not 0 < p < 65536:
        raise ValueError("bad port")
    return host, p


DIRECT_VIA = ("upnp", "natpmp", "manual")  # device reachable without hole punching

# ---------------------------------------------------------------------------
# STUN (RFC 5389 Binding)
# ---------------------------------------------------------------------------
STUN_MAGIC = 0x2112A442


def stun_request(txid: bytes) -> bytes:
    return struct.pack("!HHI", 0x0001, 0, STUN_MAGIC) + txid


def stun_parse(pkt: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(pkt) < 20:
        return None
    mtype, mlen, magic = struct.unpack("!HHI", pkt[:8])
    if mtype != 0x0101 or magic != STUN_MAGIC or pkt[8:20] != txid or mlen + 20 != len(pkt):
        return None
    off, mapped = 20, None
    while off + 4 <= len(pkt):
        atype, alen = struct.unpack("!HH", pkt[off:off + 4])
        v = pkt[off + 4: off + 4 + alen]
        if atype in (0x0020, 0x0001) and alen >= 8 and v[1] == 0x01:
            port = struct.unpack("!H", v[2:4])[0]
            ip = bytearray(v[4:8])
            if atype == 0x0020:
                port ^= STUN_MAGIC >> 16
                for i, m in enumerate(struct.pack("!I", STUN_MAGIC)):
                    ip[i] ^= m
                return socket.inet_ntoa(bytes(ip)), port
            mapped = (socket.inet_ntoa(bytes(ip)), port)
        off += 4 + ((alen + 3) & ~3)
    return mapped


def stun_query(sock: socket.socket, servers: list[str], timeout: float = 2.0) -> tuple[str, int]:
    """Discover the public ip:port of `sock` (must already be bound)."""
    sock.settimeout(timeout)
    for server in servers:
        host, _, port = server.rpartition(":")
        try:
            addr = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        except OSError:
            continue
        txid = os.urandom(12)
        for _ in range(2):
            sock.sendto(stun_request(txid), addr)
            try:
                deadline = time.time() + timeout
                while time.time() < deadline:
                    data, _src = sock.recvfrom(2048)
                    res = stun_parse(data, txid)
                    if res:
                        return res
            except socket.timeout:
                pass
    raise RuntimeError("STUN failed on all servers (is UDP blocked?)")


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packets sent; just picks the outbound interface
        return s.getsockname()[0]
    finally:
        s.close()
