"""Register the AEGIS Emergency Communications Issuer v7."""

from __future__ import annotations

import sys
from datetime import timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
    PersistentCredentialRegistry,
)


ISSUER_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v7"
    / "issuer-cert.pem"
)

REGISTRY_PATH = (
    PROJECT_ROOT
    / "transparency"
    / "credentials.sqlite3"
)


def load_certificate(
    path: Path,
) -> x509.Certificate:
    """Load a PEM certificate."""
    if not path.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {path}"
        )

    return x509.load_pem_x509_certificate(
        path.read_bytes()
    )


def get_subject_attribute(
    certificate: x509.Certificate,
    oid: x509.ObjectIdentifier,
) -> str:
    """Extract a required subject attribute."""
    attributes = certificate.subject.get_attributes_for_oid(
        oid
    )

    if not attributes:
        raise ValueError(
            f"Certificate is missing subject attribute: {oid}"
        )

    return attributes[0].value


def main() -> None:
    print("=" * 64)
    print("AEGIS Credential Registry Bootstrap — Issuer v7")
    print("=" * 64)
    print()

    issuer_certificate = load_certificate(
        ISSUER_CERT_PATH
    )

    issuer_organization = get_subject_attribute(
        issuer_certificate,
        NameOID.ORGANIZATION_NAME,
    )

    issuer_common_name = get_subject_attribute(
        issuer_certificate,
        NameOID.COMMON_NAME,
    )

    serial = str(
        issuer_certificate.serial_number
    )

    issued_at = (
        issuer_certificate.not_valid_before_utc
    )

    expires_at = (
        issuer_certificate.not_valid_after_utc
    )

    print("Issuer:")
    print(
        f"  Organization: {issuer_organization}"
    )
    print(
        f"  Common name:  {issuer_common_name}"
    )
    print(
        f"  Serial:       {serial}"
    )

    print()
    issuer_key_id = input(
        "Enter the v7 issuer key ID printed by rotate_issuer_v7.py: "
    ).strip()

    if not issuer_key_id:
        raise SystemExit(
            "Issuer key ID is required."
        )

    registry = PersistentCredentialRegistry(
        REGISTRY_PATH
    )

    record = CredentialRecord(
        key_id=issuer_key_id,
        certificate_serial_number=serial,
        subject=issuer_certificate.subject.rfc4514_string(),
        common_name=issuer_common_name,
        status=CredentialStatus.ACTIVE,
        issued_at=issued_at.astimezone(
            timezone.utc
        ),
        expires_at=expires_at.astimezone(
            timezone.utc
        ),
    )

    try:
        registry.register(
            record
        )
    except ValueError as exc:
        print()
        print(
            "Credential registration refused:"
        )
        print(f"  {exc}")
        print()
        print(
            "The existing registry entry was not modified."
        )
        raise SystemExit(1)

    print()
    print(
        "Credential registered successfully."
    )
    print(
        f"Registry: {REGISTRY_PATH}"
    )
    print(
        f"Status:   {record.status.value}"
    )
    print(
        f"Serial:   {record.certificate_serial_number}"
    )
    print(
        f"Key ID:   {record.key_id}"
    )
    print(
        f"Expires:  {record.expires_at.isoformat()}"
    )
    print()
    print(
        "Audit chain valid:",
        registry.verify_audit_chain(),
    )


if __name__ == "__main__":
    main()