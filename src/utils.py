"""Utility functions used by the PKI Toolkit."""

from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)
from cryptography import x509

def get_basic_constraints(
    certificate: x509.Certificate,
) -> tuple[bool | None, int | None]:
    """Return CA status and path length from Basic Constraints."""

    try:
        basic_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return None, None

    return basic_constraints.ca, basic_constraints.path_length


def get_subject_alternative_names(
    certificate: x509.Certificate,
) -> list[str]:
    """Return DNS names from the Subject Alternative Name extension."""

    try:
        san_extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return []

    return san_extension.get_values_for_type(x509.DNSName)


def get_public_key_info(public_key: object) -> tuple[str, int | None]:
    """Return the algorithm name and size of a public key."""

    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC ({public_key.curve.name})", public_key.key_size

    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", None

    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", None

    return type(public_key).__name__, None


def get_key_usage(certificate: x509.Certificate) -> list[str]:
    """Return enabled purposes from the Key Usage extension."""

    try:
        key_usage = certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound:
        return []

    usages: list[str] = []

    if key_usage.digital_signature:
        usages.append("Digital Signature")

    if key_usage.content_commitment:
        usages.append("Content Commitment")

    if key_usage.key_encipherment:
        usages.append("Key Encipherment")

    if key_usage.data_encipherment:
        usages.append("Data Encipherment")

    if key_usage.key_agreement:
        usages.append("Key Agreement")

    if key_usage.key_cert_sign:
        usages.append("Certificate Signing")

    if key_usage.crl_sign:
        usages.append("CRL Signing")

    if key_usage.key_agreement and key_usage.encipher_only:
        usages.append("Encipher Only")

    if key_usage.key_agreement and key_usage.decipher_only:
        usages.append("Decipher Only")

    return usages


def get_extended_key_usage(
    certificate: x509.Certificate,
) -> list[str]:
    """Return purposes from the Extended Key Usage extension."""

    try:
        extended_key_usage = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        return []

    usages: list[str] = []

    for usage_oid in extended_key_usage:
        usage_name = usage_oid._name or usage_oid.dotted_string
        usages.append(usage_name)

    return usages