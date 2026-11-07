"""Tests for the firmware's NAT-PMP / UPnP-IGD helpers (firmware/main/p2p_portmap_proto.c),
built for the host as tests/host/p2p_host. Fixtures mimic real routers (miniupnpd, FRITZ!Box-style)."""
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "tests" / "host" / "p2p_host"


def c(*args):
    r = subprocess.run([str(HOST), *args], capture_output=True, text=True)
    return r.returncode, r.stdout


def cf(cmd, text, *extra):
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write(text)
    try:
        return c(cmd, f.name, *extra)
    finally:
        Path(f.name).unlink()


MINIUPNPD_DESC = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-microsoft-com:service:OSInfo:1</serviceType>
<controlURL>/ctl/OSInfo</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
<controlURL>/ctl/CmnIfCfg</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList><service>
  <serviceType> urn:schemas-upnp-org:service:WANIPConnection:1 </serviceType>
  <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
  <controlURL>/ctl/IPConn</controlURL>
  <eventSubURL>/evt/IPConn</eventSubURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>"""

PPP_ONLY_DESC = """<root><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
<controlURL>upnp/control/wanpppc1</controlURL></service>
</serviceList></device></root>"""

HOSTILE_DESC = """<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1"/><x a="</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></root>"""


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestNatPmp(unittest.TestCase):
    def test_map_request(self):
        _, out = c("natpmp-map", "51820", "51820", "7200")
        self.assertEqual(bytes.fromhex(out.strip()), struct.pack("!BBHHHI", 0, 1, 0, 51820, 51820, 7200))

    def test_parse_external_address(self):
        resp = struct.pack("!BBHI4B", 0, 128, 0, 1234, 203, 0, 113, 77)
        self.assertEqual(c("natpmp-ext", resp.hex())[1].strip(), "203.0.113.77")
        bad = struct.pack("!BBHI4B", 0, 128, 3, 1234, 0, 0, 0, 0)  # result 3 = network failure
        self.assertEqual(c("natpmp-ext", bad.hex())[0], 3)

    def test_parse_mapping(self):
        resp = struct.pack("!BBHIHHI", 0, 129, 0, 99, 51820, 40123, 7200)
        self.assertEqual(c("natpmp-mapped", resp.hex(), "51820")[1].split(), ["40123", "7200"])
        self.assertEqual(c("natpmp-mapped", resp.hex(), "1234")[0], 3)            # other internal port
        refused = struct.pack("!BBHIHHI", 0, 129, 2, 99, 51820, 0, 0)            # result 2 = not authorized
        self.assertEqual(c("natpmp-mapped", refused.hex(), "51820")[0], 3)
        self.assertEqual(c("natpmp-mapped", resp[:12].hex(), "51820")[0], 3)     # truncated


@unittest.skipUnless(HOST.exists(), "run `make -C tests/host` first")
class TestUpnp(unittest.TestCase):
    def test_ssdp_location(self):
        resp = ("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                "Location: http://192.168.1.1:5000/rootDesc.xml \r\nSERVER: OpenWRT/OpenWrt UPnP/1.1 MiniUPnPd/2.3.3\r\n\r\n")
        rc, out = cf("ssdp-location", resp)
        self.assertEqual((rc, out.strip()), (0, "http://192.168.1.1:5000/rootDesc.xml"))
        self.assertNotEqual(cf("ssdp-location", "HTTP/1.1 200 OK\r\nLOCATION: https://x/y\r\n\r\n")[0], 0)
        self.assertNotEqual(cf("ssdp-location", "HTTP/1.1 200 OK\r\nLOCATION: http://a/b\"<x>\r\n\r\n")[0], 0)

    def test_find_wanip_service(self):
        rc, out = cf("igd", MINIUPNPD_DESC)
        self.assertEqual((rc, out.split()), (0, ["urn:schemas-upnp-org:service:WANIPConnection:1", "/ctl/IPConn"]))

    def test_find_wanppp_fallback(self):
        rc, out = cf("igd", PPP_ONLY_DESC)
        self.assertEqual(out.split(), ["urn:schemas-upnp-org:service:WANPPPConnection:1", "upnp/control/wanpppc1"])

    def test_hostile_description_rejected(self):
        self.assertNotEqual(cf("igd", HOSTILE_DESC)[0], 0)
        self.assertNotEqual(cf("igd", "<root></root>")[0], 0)

    def test_url_resolution(self):
        base = "http://192.168.1.1:5000/rootDesc.xml"
        self.assertEqual(c("urlres", base, "/ctl/IPConn")[1].split(),
                         ["http://192.168.1.1:5000/ctl/IPConn", "192.168.1.1", "5000", "/ctl/IPConn"])
        self.assertEqual(c("urlres", "http://192.168.178.1:49000/igddesc/igd.xml", "upnp/control/wanpppc1")[1].split()[0],
                         "http://192.168.178.1:49000/igddesc/upnp/control/wanpppc1")
        self.assertEqual(c("urlres", base, "http://10.0.0.1/ctl")[1].split()[1:3], ["10.0.0.1", "80"])

    def test_soap_add_mapping(self):
        rc, out = c("soap-add", "urn:schemas-upnp-org:service:WANIPConnection:1", "51820", "51820", "192.168.1.50", "7200")
        self.assertEqual(rc, 0)
        for frag in ('xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"', "<NewExternalPort>51820</NewExternalPort>",
                     "<NewProtocol>UDP</NewProtocol>", "<NewInternalClient>192.168.1.50</NewInternalClient>",
                     "<NewLeaseDuration>7200</NewLeaseDuration>"):
            self.assertIn(frag, out)
        self.assertNotEqual(c("soap-add", 'x"><evil', "1", "1", "1.2.3.4", "0")[0], 0)

    def test_soap_responses(self):
        ok = ('<?xml version="1.0"?><s:Envelope><s:Body><u:GetExternalIPAddressResponse>'
              "<NewExternalIPAddress>198.51.100.20</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>")
        self.assertEqual(cf("soap-extip", ok)[1].strip(), "198.51.100.20")
        fault = ("<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode>"
                 "<errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>")
        self.assertEqual(cf("soap-err", fault)[1].strip(), "725")
        self.assertEqual(cf("soap-err", ok)[1].strip(), "-1")

    def test_http_plain_and_chunked(self):
        plain = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n<root/>"
        self.assertEqual(cf("http", plain)[1], "200\n<root/>")
        chunked = ("HTTP/1.1 500 Internal Server Error\r\nTransfer-Encoding: chunked\r\n\r\n"
                   "5\r\n<s:En\r\na\r\nvelope/>  \r\n0\r\n\r\n")
        self.assertEqual(cf("http", chunked)[1], "500\n<s:Envelope/>  ")
        self.assertNotEqual(cf("http", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffff\r\nabc")[0], 0)
        # sizes that would wrap pointer arithmetic (32- and 64-bit) or are negative must be rejected
        for size in ("ffffffff", "ffffffffffffffff", "-1", "+5", "fffffffffffffffffffff", ""):
            rc, _ = cf("http", f"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nx\r\n0\r\n\r\n")
            self.assertNotEqual(rc, 0, size)

    def test_private_ranges(self):
        for ip in ("10.1.2.3", "172.20.0.1", "192.168.0.1", "100.64.0.1", "100.127.255.255", "169.254.1.1", "127.0.0.1"):
            self.assertEqual(c("private", ip)[1].strip(), "private", ip)
        for ip in ("198.51.100.20", "100.128.0.1", "172.32.0.1", "8.8.8.8"):
            self.assertEqual(c("private", ip)[1].strip(), "public", ip)


if __name__ == "__main__":
    unittest.main()
