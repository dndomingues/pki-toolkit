"""Fetch X.509 certificates from remote TLS servers."""

import socket
import ssl

from cryptography import x509


class TLSCertificateFetchError(Exception):
    """Raised when a remote TLS certificate cannot be fetched."""


def fetch_certificate(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
) -> x509.Certificate:
    """Fetch the leaf certificate presented by a remote TLS server."""

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as tcp_socket:
            with context.wrap_socket(
                tcp_socket,
                server_hostname=hostname,
            ) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)

    except socket.gaierror as error:
        raise TLSCertificateFetchError(
            f"Unable to resolve hostname: {hostname}"
        ) from error

    except socket.timeout as error:
        raise TLSCertificateFetchError(
            f"Connection timed out: {hostname}:{port}"
        ) from error

    except ConnectionRefusedError as error:
        raise TLSCertificateFetchError(
            f"Connection refused: {hostname}:{port}"
        ) from error

    except ssl.SSLError as error:
        raise TLSCertificateFetchError(
            f"TLS handshake failed for {hostname}:{port}: {error}"
        ) from error

    except OSError as error:
        raise TLSCertificateFetchError(
            f"Unable to connect to {hostname}:{port}: {error}"
        ) from error

    if certificate_der is None:
        raise TLSCertificateFetchError(
            f"No certificate was presented by {hostname}:{port}"
        )

    return x509.load_der_x509_certificate(certificate_der)