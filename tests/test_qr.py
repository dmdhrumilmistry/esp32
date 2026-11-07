"""Round-trips the browser client's QR encoder (web/qr.js, run under Node) through a real QR decoder
(zxing-cpp): what the phone's WireGuard app scans must be exactly the config text the page shows."""
import base64
import json
import random
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "qr_harness.js"
NODE = shutil.which("node")

try:
    import numpy as np
    import zxingcpp
except ImportError:  # pragma: no cover
    np = zxingcpp = None

LEVELS = "LMQH"
# Byte-mode capacities (bytes) from ISO/IEC 18004 Table 7, for the versions the task calls out.
CAPACITY = {
    1: (17, 14, 11, 7),
    2: (32, 26, 20, 14),
    7: (154, 122, 86, 64),
    10: (271, 213, 151, 119),
    15: (520, 412, 292, 220),
    27: (1465, 1125, 805, 625),
    40: (2953, 2331, 1663, 1273),
}
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n"
# WireGuard documentation's example keys: base64 with '+', '/' and '='.
WG_CONF = "\n".join([
    "[Interface]",
    "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
    "Address = 10.77.0.4/32",
    "ListenPort = 51821",
    "",
    "[Peer]",
    "PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=",
    "Endpoint = 203.0.113.45:51820",
    "AllowedIPs = 10.77.0.1/32, 192.168.1.0/24, 192.168.50.0/24",
    "PersistentKeepalive = 25",
    "",
])


def node(req):
    r = subprocess.run([NODE, str(HARNESS)], input=json.dumps(req), capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout)


def encode_many(reqs):
    return node({"items": reqs})["results"]


def filler(n, seed):
    rng = random.Random(seed)
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def render(rows, scale=4, quiet=4):
    """Module rows ('0'/'1' strings) -> grayscale image, black on white with a quiet zone."""
    dark = np.array([[c == "1" for c in row] for row in rows], dtype=bool)
    img = np.pad(np.where(dark, 0, 255).astype(np.uint8), quiet, constant_values=255)
    return np.ascontiguousarray(np.repeat(np.repeat(img, scale, axis=0), scale, axis=1))


def decode(img):
    return zxingcpp.read_barcodes(img, formats=zxingcpp.BarcodeFormat.QRCode)


@unittest.skipUnless(NODE and zxingcpp is not None, "needs node, zxing-cpp and numpy")
class TestQr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Byte capacity per (version, level) as the encoder computes it; spot-checked against the
        # standard's table and proven by the decode sweeps below.
        cls.caps = {(int(k[:-1]), k[-1]): n for k, n in node({"cmd": "capacity"}).items()}
        # Same with the 12-bit UTF-8 ECI header that non-ASCII strings carry.
        cls.caps_eci = {(int(k[:-1]), k[-1]): n for k, n in node({"cmd": "capacity", "eci": True}).items()}

    def assertScans(self, r, data, ecc):
        """r (harness result) decodes with zxing-cpp to exactly `data` at level `ecc`."""
        self.assertNotIn("error", r)
        size = r["size"]
        self.assertEqual(size, 4 * r["version"] + 17)
        self.assertEqual(r["ecc"], ecc)
        self.assertEqual(len(r["modules"]), size)
        self.assertTrue(all(len(row) == size and set(row) <= {"0", "1"} for row in r["modules"]))
        found = decode(render(r["modules"]))
        self.assertEqual(len(found), 1, f"zxing-cpp found no QR code (version {r['version']}-{ecc})")
        got = found[0]
        self.assertEqual(got.bytes, data)
        self.assertEqual(got.ec_level, ecc)
        extra = getattr(got, "extra", None) or {}
        if "Version" in extra:
            self.assertEqual(str(extra["Version"]), str(r["version"]))
        if "DataMask" in extra:
            self.assertEqual(int(extra["DataMask"]), r["mask"])
        return got

    def assertSameModules(self, got, want):
        # Not assertEqual: unittest's difflib message for long, mostly-equal row strings is quadratic.
        self.assertEqual(len(got), len(want), "matrix size")
        diff = [(y, x) for y, (a, b) in enumerate(zip(got, want)) for x in range(max(len(a), len(b)))
                if a[x:x + 1] != b[x:x + 1]]
        if diff:
            self.fail(f"{len(diff)} modules differ (row, column): {diff[:8]}")

    def test_short_ascii(self):
        for text in ["A", "hello", "p2ptun says hi!"]:
            with self.subTest(text=text):
                r = node({"text": text})
                self.assertEqual(r["ecc"], "M")  # default level
                self.assertFalse(r["eci"])  # ASCII: plain byte mode, no ECI header
                self.assertEqual(r["version"], 1 if len(text) <= 14 else 2)
                self.assertEqual(self.assertScans(r, text.encode(), "M").text, text)

    def test_wireguard_config_every_level(self):
        rng = random.Random(7)
        key = lambda: base64.b64encode(rng.randbytes(32)).decode()  # noqa: E731
        random_conf = WG_CONF.replace("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", key()).replace(
            "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=", key())
        for conf in (WG_CONF, random_conf):
            for ecc in LEVELS:
                with self.subTest(ecc=ecc, conf=conf[:40]):
                    r = node({"text": conf, "ecc": ecc})
                    self.assertFalse(r["eci"])
                    got = self.assertScans(r, conf.encode(), ecc)
                    self.assertEqual(got.text, conf)
                    if ecc == "M":  # what the page uses: small enough to scan off a laptop screen
                        self.assertLessEqual(r["version"], 15)
        self.assertIn("+", WG_CONF)
        self.assertIn("\n", WG_CONF)

    def test_utf8_multibyte(self):
        texts = ["é", "日本語", "Grüße aus Köln — 東京 🐍 ✓ Ωmega", "€" * 100, "🔐 p2ptun\n" * 20]
        reqs = [{"text": t, "ecc": e} for t in texts for e in LEVELS]
        for req, r in zip(reqs, encode_many(reqs)):
            with self.subTest(text=req["text"][:20], ecc=req["ecc"]):
                data = req["text"].encode("utf-8")
                self.assertTrue(r["eci"])
                self.assertEqual(r["version"], min(v for v in range(1, 41) if self.caps_eci[(v, req["ecc"])] >= len(data)))
                self.assertEqual(self.assertScans(r, data, req["ecc"]).text, req["text"])

    def test_utf8_eci_matches_reference_encoder(self):
        """Non-ASCII strings carry ECI 26 (UTF-8) so decoders don't guess Shift-JIS: bit-identical to
        zxing-cpp's writer, which emits that ECI for this text; without the ECI the symbol differs."""
        try:
            zxingcpp.create_barcode("x", zxingcpp.BarcodeFormat.QRCode, ec_level="M", version=1, data_mask=0)
        except (TypeError, ValueError, AttributeError) as e:  # pragma: no cover
            self.skipTest(f"zxing-cpp writer lacks version/data_mask options: {e}")
        text = "€uro ✓"
        for v, e, k in ((1, "L", 0), (2, "M", 3), (2, "M", 7), (7, "Q", 5), (10, "H", 2)):
            with self.subTest(version=v, ecc=e, mask=k):
                ref = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode, ec_level=e, version=v, data_mask=k)
                img = np.array(ref.to_image(scale=1, add_quiet_zones=False))
                rows = ["".join("1" if px < 128 else "0" for px in row) for row in img]
                r = node({"text": text, "ecc": e, "mask": k, "min_version": v})
                self.assertTrue(r["eci"])
                self.assertSameModules(r["modules"], rows)
                plain = node({"text": text, "ecc": e, "mask": k, "min_version": v, "eci": False})
                self.assertFalse(plain["eci"])
                self.assertNotEqual(plain["modules"], rows)
                self.assertEqual(self.assertScans(plain, text.encode(), e).text, text)

    def test_eci_capacity(self):
        for v in range(1, 41):
            for e in LEVELS:
                # 12 header bits cost one byte, or two when the byte-mode bits have < 4 spare bits.
                self.assertIn(self.caps[(v, e)] - self.caps_eci[(v, e)], (1, 2), f"{v}-{e}")
        self.assertEqual(self.caps_eci[(40, "H")], 1272)

    def test_raw_bytes(self):
        data = bytes(range(256))
        r = node({"hex": data.hex(), "ecc": "L"})
        self.assertFalse(r["eci"])  # bytes are not assumed to be UTF-8
        self.assertScans(r, data, "L")

    def test_capacity_matches_standard(self):
        for v, caps in CAPACITY.items():
            for e, n in zip(LEVELS, caps):
                self.assertEqual(self.caps[(v, e)], n, f"capacity {v}-{e}")
        for e in LEVELS:
            seq = [self.caps[(v, e)] for v in range(1, 41)]
            self.assertEqual(seq, sorted(set(seq)), "capacity must grow with the version")

    def test_version_boundaries(self):
        """Exactly full for the listed versions picks that version; one byte more picks the next."""
        reqs, want = [], []
        for v in CAPACITY:
            for e in LEVELS:
                n = self.caps[(v, e)]
                reqs.append({"text": filler(n, v * 10 + LEVELS.index(e)), "ecc": e})
                want.append(v)
                if v < 40:
                    reqs.append({"text": filler(n + 1, v * 10 + LEVELS.index(e)), "ecc": e})
                    want.append(v + 1)
        for req, r, v in zip(reqs, encode_many(reqs), want):
            with self.subTest(len=len(req["text"]), ecc=req["ecc"]):
                self.assertNotIn("error", r)
                self.assertEqual(r["version"], v)
                self.assertScans(r, req["text"].encode(), req["ecc"])

    def test_every_version_and_level_at_capacity(self):
        """Fills every version 1-40 at every level: exercises all block-structure table entries,
        alignment pattern positions and version information words."""
        reqs = [{"text": filler(self.caps[(v, e)], 1000 + v * 4 + i), "ecc": e}
                for v in range(1, 41) for i, e in enumerate(LEVELS)]
        for req, r in zip(reqs, encode_many(reqs)):
            with self.subTest(len=len(req["text"]), ecc=req["ecc"]):
                self.assertScans(r, req["text"].encode(), req["ecc"])

    def test_every_mask(self):
        reqs = [{"text": "mask %d" % k, "ecc": e, "mask": k, "min_version": v}  # <= 7 bytes: fits 1-H
                for k in range(8) for e in LEVELS for v in (1, 7, 22)]
        for req, r in zip(reqs, encode_many(reqs)):
            with self.subTest(mask=req["mask"], ecc=req["ecc"], version=req["min_version"]):
                self.assertEqual((r["mask"], r["version"]), (req["mask"], req["min_version"]))
                self.assertScans(r, req["text"].encode(), req["ecc"])

    def test_matches_reference_encoder(self):
        """Same version/level/mask -> bit-identical to zxing-cpp's own QR writer (function patterns,
        both format information copies, version information, codeword placement)."""
        try:
            zxingcpp.create_barcode("x", zxingcpp.BarcodeFormat.QRCode, ec_level="M", version=1, data_mask=0)
        except (TypeError, ValueError, AttributeError) as e:  # pragma: no cover
            self.skipTest(f"zxing-cpp writer lacks version/data_mask options: {e}")
        reqs = []
        for v in (1, 2, 6, 7, 14, 32, 40):
            for e in LEVELS:
                for k in range(8):
                    text = f"hello p2ptun {v} {e} {k}"[: CAPACITY[1][LEVELS.index(e)]]  # lowercase: byte mode
                    reqs.append({"text": text, "ecc": e, "mask": k, "min_version": v})
        for req, r in zip(reqs, encode_many(reqs)):
            with self.subTest(version=req["min_version"], ecc=req["ecc"], mask=req["mask"]):
                ref = zxingcpp.create_barcode(req["text"], zxingcpp.BarcodeFormat.QRCode, ec_level=req["ecc"],
                                              version=req["min_version"], data_mask=req["mask"])
                img = np.array(ref.to_image(scale=1, add_quiet_zones=False))
                rows = ["".join("1" if px < 128 else "0" for px in row) for row in img]
                self.assertSameModules(r["modules"], rows)

    def test_over_capacity_throws(self):
        cases = [("x" * 2954, "L", 2953), ("x" * 2332, "M", 2331), ("x" * 1664, "Q", 1663),
                 ("x" * 1274, "H", 1273),
                 ("€" * 424 + "x", "H", 1272)]  # 425 chars, 1273 UTF-8 bytes: too many with the ECI header
        for text, ecc, cap in cases:
            with self.subTest(ecc=ecc, len=len(text)):
                r = node({"text": text, "ecc": ecc})
                self.assertIn("error", r)
                self.assertIn("too long", r["error"])
                self.assertIn(str(cap), r["error"])
        self.assertEqual(node({"text": "€" * 424, "ecc": "H"})["version"], 40)  # 1272 bytes + ECI: fits
        self.assertEqual(node({"text": "€" * 424 + "x", "ecc": "H", "eci": False})["version"], 40)  # 1273, no ECI

    def test_bad_options_throw(self):
        for req in ({"text": "x", "ecc": "Z"}, {"text": "x", "mask": 8}, {"text": "x", "min_version": 41},
                    {"text": "x", "eci": 1}):
            with self.subTest(req=req):
                self.assertIn("error", node(req))

    def test_empty_text(self):
        r = node({"text": ""})
        self.assertEqual((r["version"], r["size"]), (1, 21))

    def test_svg(self):
        for scale, margin in ((5, 4), (1, 0), (3, 2)):
            with self.subTest(scale=scale, margin=margin):
                self.check_svg(scale, margin)

    def check_svg(self, scale, margin):
        out = node({"cmd": "svg", "text": WG_CONF, "scale": scale, "margin": margin})
        self.assertNotIn("error", out)
        qr, svg = out["qr"], out["svg"]
        ns = "http://www.w3.org/2000/svg"
        dim = qr["size"] + 2 * margin
        self.assertEqual((svg["ns"], svg["tag"]), (ns, "svg"))
        self.assertEqual(svg["attrs"]["viewBox"], f"0 0 {dim} {dim}")
        self.assertEqual(svg["attrs"]["width"], str(dim * scale))
        self.assertEqual(svg["attrs"]["height"], str(dim * scale))
        self.assertEqual(svg["attrs"]["shape-rendering"], "crispEdges")
        rect, path = svg["children"]
        self.assertEqual((rect["ns"], rect["tag"], path["ns"], path["tag"]), (ns, "rect", ns, "path"))
        self.assertEqual({k: rect["attrs"][k] for k in ("x", "y", "width", "height")},
                         {"x": "0", "y": "0", "width": str(dim), "height": str(dim)})
        self.assertEqual(rect["attrs"]["fill"], "#fff")
        self.assertEqual(path["attrs"]["fill"], "#000")

        # Rasterize the path (horizontal runs of dark modules) and compare with the module matrix.
        d = path["attrs"]["d"]
        runs = re.findall(r"M(\d+),(\d+)h(\d+)v1h-(\d+)z", d)
        self.assertTrue("".join(f"M{x},{y}h{n}v1h-{m}z" for x, y, n, m in runs) == d, "unexpected path data")
        canvas = np.zeros((dim, dim), dtype=bool)
        for x, y, n, m in runs:
            x, y, n = int(x), int(y), int(n)
            self.assertEqual(n, int(m))
            self.assertFalse(canvas[y, x:x + n].any(), "overlapping runs")
            canvas[y, x:x + n] = True
        inner = canvas[margin:dim - margin, margin:dim - margin]
        self.assertEqual(int(canvas.sum()), int(inner.sum()), "dark modules in the quiet zone")
        self.assertSameModules(["".join("1" if c else "0" for c in row) for row in inner], qr["modules"])
        img = np.pad(np.where(canvas, 0, 255).astype(np.uint8), 4 - margin, constant_values=255)
        img = np.ascontiguousarray(np.repeat(np.repeat(img, 4, 0), 4, 1))
        self.assertEqual([f.text for f in decode(img)], [WG_CONF])


class TestQrPage(unittest.TestCase):
    """index.html/app.js wiring (static checks; the encoder itself is tested above)."""

    def test_page_loads_qr_before_app(self):
        page = (ROOT / "web" / "index.html").read_text()
        scripts = re.findall(r'<script src="([^"]+)"></script>', page)
        self.assertEqual(scripts, ["p2ptun-proto.js", "qr.js", "app.js"])
        result = page[page.index('<div id="result"'):]
        self.assertIn('id="r-qr-box"', result)
        self.assertIn('id="r-qr"', result)
        self.assertIn("script-src 'self'", page)

    def test_result_cleared_when_key_or_device_changes(self):
        """The config text and QR carry the private key: "Forget key", a new/imported key and a device
        config change must hide and empty them (and void a "Get config" still in flight)."""
        src = (ROOT / "web" / "app.js").read_text()
        clear = src[src.index("function clearResult()"):]
        clear = clear[:clear.index("\n  }\n")]
        for needle in ('resultGen++', 'show("result", false)', '$("r-conf").value = ""', 'showQr("")'):
            self.assertIn(needle, clear)
        for start in ('$("forget").onclick', '$("dev-save").onclick', '$("dev-change").onclick',
                      'async function storeKey(', '$("go").onclick'):
            with self.subTest(handler=start):
                body = src[src.index(start):]
                body = body[:body.index("\n  }")]
                self.assertIn("clearResult()", body)
        go = src[src.index('$("go").onclick'):]
        self.assertLess(go.index("if (gen !== resultGen) return"), go.index("showQr(conf)"))

    def test_no_inner_html(self):
        for name in ("qr.js", "app.js"):
            src = (ROOT / "web" / name).read_text()
            for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function"):
                self.assertNotIn(bad, src, f"{name} uses {bad}")


if __name__ == "__main__":
    unittest.main()
