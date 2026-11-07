"""Wake-on-LAN helpers (firmware/main/p2p_wol.c), built for the host as tests/host/p2p_host."""
import subprocess
import unittest
from pathlib import Path

HOST = Path(__file__).resolve().parents[1] / "tests" / "host" / "p2p_host"


def wol(mac):
    r = subprocess.run([str(HOST), "wol", mac], capture_output=True, text=True)
    return r.returncode, r.stdout.split()


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestWol(unittest.TestCase):
    def test_magic_packet(self):
        rc, (norm, pkt) = wol("AA-bb-CC-dd-EE-01")
        self.assertEqual(rc, 0)
        self.assertEqual(norm, "aa:bb:cc:dd:ee:01")
        raw = bytes.fromhex(pkt)
        self.assertEqual(len(raw), 102)
        self.assertEqual(raw, b"\xff" * 6 + bytes.fromhex("aabbccddee01") * 16)

    def test_rejects_bad_macs(self):
        for bad in ("", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "aa:bb-cc:dd:ee:ff", "gg:bb:cc:dd:ee:ff",
                    "aabbccddeeff", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:f "):
            self.assertNotEqual(wol(bad)[0], 0, bad)


if __name__ == "__main__":
    unittest.main()
