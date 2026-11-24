"""Offline unit tests for DNS-over-TLS packet framing, flags, and config hardening."""

from pathlib import Path
import struct
import unittest

from src.dns_security_audit import (
    audit_gateway_configs,
    build_dns_query,
    encode_qname,
    frame_dot_message,
    parse_dns_response,
)


class SecureDnsGatewayTestSuite(unittest.TestCase):
    def test_encode_qname_and_edns0_do_bit_structure(self) -> None:
        encoded = encode_qname("dns.quad9.net.")
        self.assertEqual(encoded, b"\x03dns\x05quad9\x03net\x00")

        with self.assertRaises(ValueError):
            encode_qname("a" * 64 + ".example.com")

        pkt = build_dns_query("quad9.net", tx_id=0x2A01, enable_dnssec=True)
        tx_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", pkt[:12])
        self.assertEqual(tx_id, 0x2A01)
        self.assertEqual(flags, 0x0120)
        self.assertEqual((qd, an, ns, ar), (1, 0, 0, 1))
        # Verify trailing 11-byte EDNS0 OPT record carries DO bit (0x8000)
        self.assertEqual(pkt[-11:], b"\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00")

    def test_dot_tcp_length_prefix_framing(self) -> None:
        raw_query = build_dns_query("iana.org", tx_id=0x0042, enable_dnssec=False)
        framed = frame_dot_message(raw_query)
        (declared_len,) = struct.unpack("!H", framed[:2])
        self.assertEqual(declared_len, len(raw_query))
        self.assertEqual(len(framed), len(raw_query) + 2)

    def test_parse_dnssec_authenticated_noerror_response(self) -> None:
        # QR=1, RD=1, RA=1, AD=1 (0x81A0), RCODE=0 (NOERROR), ANCOUNT=2
        synthetic_resp = struct.pack("!HHHHHH", 0x7F11, 0x81A0, 1, 2, 0, 1)
        parsed = parse_dns_response(synthetic_resp, expected_tx_id=0x7F11)
        self.assertEqual(parsed["rcode_name"], "NOERROR")
        self.assertTrue(parsed["ad_authenticated"])
        self.assertTrue(parsed["ra_available"])
        self.assertEqual(parsed["answer_count"], 2)

    def test_parse_quad9_nxdomain_sinkhole_and_txid_guard(self) -> None:
        # QR=1, RD=1, RA=1, AD=0, RCODE=3 (NXDOMAIN -> Quad9 threat block / non-existent)
        nx_resp = struct.pack("!HHHHHH", 0x99AA, 0x8183, 1, 0, 1, 1)
        parsed = parse_dns_response(nx_resp, expected_tx_id=0x99AA)
        self.assertEqual(parsed["rcode_name"], "NXDOMAIN")
        self.assertFalse(parsed["ad_authenticated"])

        with self.assertRaises(ValueError):
            parse_dns_response(nx_resp, expected_tx_id=0x1111)

    def test_gateway_config_security_invariants_pass(self) -> None:
        repo_configs = Path(__file__).resolve().parent.parent / "configs"
        audit = audit_gateway_configs(repo_configs)
        self.assertTrue(audit["all_controls_passed"], msg=f"Failed controls: {audit}")


if __name__ == "__main__":
    unittest.main()
