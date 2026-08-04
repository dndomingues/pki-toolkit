"""Read and display basic information from an X.509 certificate."""

from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from datetime import datetime, timezone

from utils import (
    get_basic_constraints,
    get_extended_key_usage,
    get_key_usage,
    get_public_key_info,
    get_subject_alternative_names,
)


def load_certificate(certificate_path: Path) -> x509.Certificate:
    """Load an X.509 certificate stored in PEM format."""

    if not certificate_path.exists():
        raise FileNotFoundError(
            f"Certificate file not found: {certificate_path}"
        )

    if not certificate_path.is_file():
        raise ValueError(
            f"The supplied path is not a file: {certificate_path}"
        )

    certificate_data = certificate_path.read_bytes()

    try:
        return x509.load_pem_x509_certificate(certificate_data)
    except ValueError as error:
        raise ValueError(
            f"Unable to read PEM certificate: {certificate_path}"
        ) from error


def format_fingerprint(fingerprint: bytes) -> str:
    """Format a fingerprint using colon-separated hexadecimal pairs."""

    return ":".join(f"{byte:02X}" for byte in fingerprint)


def display_certificate(certificate: x509.Certificate) -> None:
    """Display basic information from an X.509 certificate."""

    fingerprint = certificate.fingerprint(hashes.SHA256())
    remaining_time = certificate.not_valid_after_utc - datetime.now(timezone.utc)
    days_remaining = remaining_time.days

    public_key = certificate.public_key()
    public_key_algorithm, public_key_size = get_public_key_info(public_key)

    is_ca, path_length = get_basic_constraints(certificate)
    subject_alternative_names = get_subject_alternative_names(certificate)

    certificate_version = certificate.version.name
    signature_algorithm_oid = certificate.signature_algorithm_oid

    signature_algorithm = (
    signature_algorithm_oid._name
    or signature_algorithm_oid.dotted_string
    )

    key_usages = get_key_usage(certificate)
    extended_key_usages = get_extended_key_usage(certificate)

    print("=" * 60)
    print("PKI Toolkit - Certificate Reader")
    print("=" * 60)
    print(f"Subject.............: {certificate.subject.rfc4514_string()}")
    print(f"Issuer..............: {certificate.issuer.rfc4514_string()}")
    print(f"Version.............: {certificate_version}")
    print(f"Serial Number.......: {certificate.serial_number}")
    print(f"Valid From..........: {certificate.not_valid_before_utc}")
    print(f"Valid Until.........: {certificate.not_valid_after_utc}")
    print(f"Days Remaining......: {days_remaining}")
    print(f"Public Key..........: {public_key_algorithm}")
    
    if public_key_size is not None:
        print(f"Key Size............: {public_key_size} bits")
    else:
        print("Key Size............: Not applicable")

    print(f"Signature Algorithm.: {signature_algorithm}")

    if is_ca is None:
        print("Is CA...............: Extension not present")
    else:
        print(f"Is CA...............: {is_ca}")

    if is_ca:
        path_length_text = (
            str(path_length)
            if path_length is not None
            else "No restriction"
        )
        print(f"CA Path Length......: {path_length_text}")
    
    print("Subject Alt Names...:")
    
    if subject_alternative_names:
        for name in subject_alternative_names:
            print(f"  - {name}")
    else:
        print("  - None")

    print("Key Usage...........:")

    if key_usages:
        for usage in key_usages:
            print(f"  - {usage}")
    else:
        print("  - Extension not present")


    print("Extended Key Usage..:")

    if extended_key_usages:
        for usage in extended_key_usages:
            print(f"  - {usage}")
    else:
        print("  - Extension not present")

    print(f"SHA-256 Fingerprint.: {format_fingerprint(fingerprint)}")

def main() -> None:
    """Run the certificate reader from the command line."""

    if len(sys.argv) != 2:
        program_name = Path(sys.argv[0]).name
        print(f"Usage: python {program_name} <certificate.pem>")
        raise SystemExit(1)

    certificate_path = Path(sys.argv[1])

    try:
        certificate = load_certificate(certificate_path)
        display_certificate(certificate)
    except (FileNotFoundError, ValueError, PermissionError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()