"""Tests for per-peer access rules (firmware/main/p2p_acl.c), built for the host as tests/host/p2p_host."""
import socket
import struct
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "tests" / "host" / "p2p_host"
LAN = "192.168.1.0/24"
DEV = "10.77.0.1"


def ipv4(dst, proto=6, dport=22, src="10.77.0.2", frag_off=0, ihl=5, l4=True):
    opts = b"\x01" * ((ihl - 5) * 4)  # NOP options
    payload = struct.pack("!HH", 40000, dport) + b"\x00" * 16 if l4 else b""
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, 1, frag_off, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + opts + payload


def check(rules, pkt, lan=LAN):
    r = subprocess.run([str(HOST), "acl-check", rules, lan, DEV, pkt.hex()], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else f"rc{r.returncode}:{r.stdout.strip()}"


def parse(rules):
    r = subprocess.run([str(HOST), "acl-parse", rules], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestAclParse(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse(""), (0, "all"))
        self.assertEqual(parse("  ,\n "), (0, "all"))
        self.assertEqual(parse("any"), (0, "all"))
        self.assertEqual(parse("lan, ANY"), (0, "all"))
        self.assertEqual(parse("lan,device"), (0, "2 rules"))
        self.assertEqual(parse("tcp:192.168.1.20:22\nudp:192.168.1.1:53, 192.168.1.0/24:80-443, icmp:lan"), (0, "4 rules"))
        self.assertEqual(parse("10.0.0.0/0"), (0, "1 rules"))

    def test_invalid(self):
        for bad in ("lan device", "192.168.1.300", "192.168.1", "192.168.1.1/33", "tcp:lan:0", "tcp:lan:70000",
                    "lan:443-80", "icmp:lan:80", "sctp:lan", "foo", "1.2.3.4.5", "lan:", "lan:-5",
                    ",".join(["lan"] * 9), "x" * 120):
            rc, msg = parse(bad)
            self.assertEqual(rc, 4, bad)
            self.assertTrue(msg, bad)


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestAclMatch(unittest.TestCase):
    def test_full_access(self):
        self.assertEqual(check("", ipv4("8.8.8.8", 17, 53)), "allow")
        self.assertEqual(check("", b"\x60" + b"\x00" * 39), "allow")  # even IPv6 when unrestricted

    def test_lan_and_device_keywords(self):
        self.assertEqual(check("lan", ipv4("192.168.1.20")), "allow")
        self.assertEqual(check("lan", ipv4("192.168.2.20")), "deny")
        self.assertEqual(check("lan", ipv4(DEV, 6, 80)), "deny")          # web UI not included in "lan"
        self.assertEqual(check("device", ipv4(DEV, 6, 80)), "allow")
        self.assertEqual(check("lan", ipv4("192.168.1.20"), lan="-"), "deny")  # LAN unknown -> nothing

    def test_protocol_and_ports(self):
        r = "tcp:192.168.1.20:22, udp:192.168.1.1:53, 192.168.1.30:8000-8100, icmp:192.168.1.0/24"
        self.assertEqual(check(r, ipv4("192.168.1.20", 6, 22)), "allow")
        self.assertEqual(check(r, ipv4("192.168.1.20", 6, 23)), "deny")
        self.assertEqual(check(r, ipv4("192.168.1.20", 17, 22)), "deny")   # wrong protocol
        self.assertEqual(check(r, ipv4("192.168.1.1", 17, 53)), "allow")
        self.assertEqual(check(r, ipv4("192.168.1.30", 17, 8050)), "allow")  # port without proto: tcp or udp
        self.assertEqual(check(r, ipv4("192.168.1.30", 6, 8100)), "allow")
        self.assertEqual(check(r, ipv4("192.168.1.30", 6, 8101)), "deny")
        self.assertEqual(check("192.168.1.30:8000-8100", ipv4("192.168.1.30", 1, 0, l4=False)), "deny")  # ICMP never matches a port rule
        self.assertEqual(check(r, ipv4("192.168.1.99", 1, 0, l4=False)), "allow")

    def test_cidr(self):
        self.assertEqual(check("10.1.0.0/16", ipv4("10.1.200.3")), "allow")
        self.assertEqual(check("10.1.0.0/16", ipv4("10.2.0.3")), "deny")
        self.assertEqual(check("10.1.2.3/16", ipv4("10.1.9.9")), "allow")  # host bits ignored
        self.assertEqual(check("0.0.0.0/0", ipv4("1.2.3.4")), "allow")

    def test_ip_options_and_fragments(self):
        self.assertEqual(check("tcp:192.168.1.20:22", ipv4("192.168.1.20", 6, 22, ihl=7)), "allow")
        self.assertEqual(check("tcp:192.168.1.20:22", ipv4("192.168.1.20", 6, 22, frag_off=10)), "deny")
        self.assertEqual(check("192.168.1.20", ipv4("192.168.1.20", 6, 22, frag_off=10)), "allow")

    def test_malformed_packets_denied(self):
        good = ipv4("192.168.1.20")
        self.assertEqual(check("lan", good[:19]), "deny")                     # truncated header
        self.assertEqual(check("lan", b"\x60" + good[1:]), "deny")           # IPv6 when restricted
        self.assertEqual(check("lan", bytes([0x44]) + good[1:]), "deny")    # IHL < 5
        self.assertEqual(check("lan", bytes([0x4F]) + good[1:]), "deny")    # IHL beyond packet
        self.assertEqual(check("tcp:lan:22", ipv4("192.168.1.20", 6, 22)[:21]), "deny")  # no room for ports


if __name__ == "__main__":
    unittest.main()
