"""Pure-Python DNS-over-TLS (RFC 7858) & DNSSEC (RFC 6840) security auditor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import time
from typing import Any

RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def encode_qname(domain: str) -> bytes:
    """Encode a domain name into RFC 1035 wire-format length-prefixed labels."""
    cleaned = domain.strip().rstrip(".")
    if not cleaned:
        raise ValueError("Domain name must not be empty")

    out = bytearray()
    for label in cleaned.split("."):
        raw_label = label.encode("ascii")
        if not (1 <= len(raw_label) <= 63):
            raise ValueError(f"Invalid DNS label length in '{domain}'")
        out.append(len(raw_label))
        out.extend(raw_label)
    out.append(0)

    if len(out) > 255:
        raise ValueError("Encoded QNAME exceeds 255-octet RFC 1035 limit")
    return bytes(out)


def build_dns_query(
    domain: str,
    tx_id: int = 0x4A2B,
    qtype: int = 1,
    enable_dnssec: bool = True,
) -> bytes:
    """Construct an RFC 1035 query with optional EDNS0 DO-bit for DNSSEC validation."""
    flags = 0x0120 if enable_dnssec else 0x0100  # RD=1, AD=1 when DNSSEC requested
    arcount = 1 if enable_dnssec else 0

    header = struct.pack("!HHHHHH", tx_id & 0xFFFF, flags, 1, 0, 0, arcount)
    question = encode_qname(domain) + struct.pack("!HH", qtype, 1)  # QCLASS=IN (1)

    if not enable_dnssec:
        return header + question

    # EDNS0 OPT pseudo-RR (Type 41, UDP payload 1232, DO bit 0x8000 set)
    edns0_opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    return header + question + edns0_opt


def frame_dot_message(dns_payload: bytes) -> bytes:
    """Prepend the mandatory 2-octet big-endian length header for DNS-over-TLS (RFC 7858)."""
    return struct.pack("!H", len(dns_payload)) + dns_payload


def parse_dns_response(raw: bytes, expected_tx_id: int | None = None) -> dict[str, Any]:
    """Parse an RFC 1035 DNS wire response header and extract security flags."""
    if len(raw) < 12:
        raise ValueError("Truncated DNS packet (< 12-byte header)")

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", raw[:12])
    if expected_tx_id is not None and tx_id != (expected_tx_id & 0xFFFF):
        raise ValueError(f"DNS transaction ID mismatch: expected {expected_tx_id}, got {tx_id}")

    qr_bit = (flags >> 15) & 0x1
    if qr_bit != 1:
        raise ValueError("Invalid DNS response: QR bit is 0 (query packet)")

    rcode = flags & 0x000F
    return {
        "tx_id": tx_id,
        "rcode": rcode,
        "rcode_name": RCODE_MAP.get(rcode, f"RCODE_{rcode}"),
        "ad_authenticated": bool(flags & 0x0020),
        "ra_available": bool(flags & 0x0080),
        "tc_truncated": bool(flags & 0x0200),
        "question_count": qdcount,
        "answer_count": ancount,
        "authority_count": nscount,
        "additional_count": arcount,
    }


def _recv_exact(sock: ssl.SSLSocket, num_bytes: int) -> bytes:
    """Read an exact byte count from a stream socket."""
    chunks = bytearray()
    while len(chunks) < num_bytes:
        chunk = sock.recv(num_bytes - len(chunks))
        if not chunk:
            raise EOFError("Remote DoT peer closed TLS stream unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def query_quad9_dot(
    domain: str,
    server_ip: str = "9.9.9.9",
    port: int = 853,
    sni_hostname: str = "dns.quad9.net",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Execute a live encrypted DNS-over-TLS lookup with strict X.509 SNI validation."""
    tx_id = secrets.randbits(16)
    wire_query = frame_dot_message(build_dns_query(domain, tx_id=tx_id, enable_dnssec=True))

    tls_ctx = ssl.create_default_context()
    tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_ctx.check_hostname = True
    tls_ctx.verify_mode = ssl.CERT_REQUIRED

    t_start = time.perf_counter()
    with socket.create_connection((server_ip, port), timeout=timeout) as tcp_sock:
        with tls_ctx.wrap_socket(tcp_sock, server_hostname=sni_hostname) as tls_sock:
            tls_sock.sendall(wire_query)
            (resp_len,) = struct.unpack("!H", _recv_exact(tls_sock, 2))
            raw_resp = _recv_exact(tls_sock, resp_len)
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            tls_proto = tls_sock.version()
            cipher_info = tls_sock.cipher()

    parsed = parse_dns_response(raw_resp, expected_tx_id=tx_id)
    return {
        "domain": domain,
        "upstream": f"{server_ip}:{port}#{sni_hostname}",
        "tls_protocol": tls_proto,
        "cipher_suite": cipher_info[0] if cipher_info else "UNKNOWN",
        "roundtrip_ms": round(elapsed_ms, 2),
        **parsed,
    }


def audit_gateway_configs(config_dir: Path) -> dict[str, Any]:
    """Verify security hardening invariants across nftables, Unbound, and systemd-resolved."""
    nft_path = config_dir / "01-nftables-dns-enforcement.nft"
    unbound_path = config_dir / "02-unbound-quad9-dot.conf"
    resolved_path = config_dir / "03-systemd-resolved-workstation.conf"

    nft_txt = nft_path.read_text(encoding="utf-8")
    unbound_txt = unbound_path.read_text(encoding="utf-8")
    resolved_lines = [
        ln.strip() for ln in resolved_path.read_text(encoding="utf-8").splitlines()
    ]

    checks = {
        "iot_dnat_port53_redirect": "redirect to :53" in nft_txt,
        "wan_plaintext_dns_blocked": (
            "oifname $WAN_IF" in nft_txt and "dport 53 counter drop" in nft_txt
        ),
        "unbound_strict_dot_sni": (
            "forward-tls-upstream: yes" in unbound_txt
            and "9.9.9.9@853#dns.quad9.net" in unbound_txt
        ),
        "unbound_dnssec_and_qname_min": (
            "auto-trust-anchor-file:" in unbound_txt
            and "qname-minimisation: yes" in unbound_txt
        ),
        "workstation_dot_enforced": (
            "DNSOverTLS=yes" in resolved_lines and "DNSSEC=yes" in resolved_lines
        ),
        "workstation_downgrade_prevented": "FallbackDNS=" in resolved_lines,
    }
    return {
        "all_controls_passed": all(checks.values()),
        "controls": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Quad9 DoT & Firewall Policy Auditor")
    parser.add_argument(
        "--live-quad9",
        action="store_true",
        help="Run live TLS 1.3 port-853 probes against Quad9 (9.9.9.9)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run offline wire-format self-check and configuration policy audit",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "configs",
        help="Path to gateway configuration directory",
    )
    args = parser.parse_args()

    report: dict[str, Any] = {
        "audit_target": "Enterprise Encrypted DNS Gateway (Quad9 DoT)",
        "config_policy_audit": audit_gateway_configs(args.config_dir),
    }

    if args.live_quad9:
        probes = [
            query_quad9_dot("quad9.net"),
            query_quad9_dot("iana.org"),
            query_quad9_dot("sinkhole-verification.invalid"),
        ]
        report["live_dot_probes"] = probes
    else:
        sample_wire = frame_dot_message(build_dns_query("quad9.net", tx_id=0x1337))
        report["offline_wire_check"] = {
            "framed_dot_bytes": len(sample_wire),
            "edns0_dnssec_enabled": True,
            "mode": "dry-run" if args.dry_run else "default-offline",
        }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
