"""Data models used by the PKI Toolkit."""

from dataclasses import dataclass

from cryptography import x509


@dataclass
class TLSConnectionInfo:
    """Information collected from a remote TLS connection."""

    hostname: str
    port: int
    peer_ip: str
    tls_version: str | None
    cipher_suite: str | None
    alpn_protocol: str | None
    certificate: x509.Certificate