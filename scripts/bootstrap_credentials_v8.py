"""Register AEGIS Emergency Communications Issuer v8 in Neon."""

from __future__ import annotations

import sys
from datetime import timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from dotenv import dotenv_values


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
)
from packages.trust.storage import (
    PostgreSQLCredentialStore,
)


ISSUER_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v8"
    / "issuer-cert.pem"
)

ENV_FILE = (
    PROJECT_ROOT
    / ".env.local"
)


def load_database_url() -> str:
    """Load the Neon DATABASE_URL."""

    values = dotenv_values(
        ENV_FILE
    )

    database_url = values.get(
        "DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is missing from .env.local."
        )

    return database_url


def load_certificate(
    path: Path,
) -> x509.Certificate:
    """Load a PEM certificate."""

    if not path.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {path}"
        )

    return (
        x509.load_pem_x509_certificate(
            path.read_bytes()
        )
    )


def get_subject_attribute(
    certificate: x509.Certificate,
    oid: x509.ObjectIdentifier,
) -> str:
    """Extract a required certificate subject attribute."""

    attributes = (
        certificate.subject.get_attributes_for_oid(
            oid
        )
    )

    if not attributes:
        raise ValueError(
            f"Certificate is missing subject attribute: {oid}"
        )

    return attributes[0].value


def main() -> None:
    print("=" * 72)
    print(
        "AEGIS Neon Credential Registration — Issuer v8"
    )
    print("=" * 72)
    print()

    issuer_certificate = load_certificate(
        ISSUER_CERT_PATH
    )

    issuer_organization = (
        get_subject_attribute(
            issuer_certificate,
            NameOID.ORGANIZATION_NAME,
        )
    )

    issuer_common_name = (
        get_subject_attribute(
            issuer_certificate,
            NameOID.COMMON_NAME,
        )
    )

    serial = str(
        issuer_certificate.serial_number
    )

    issued_at = (
        issuer_certificate
        .not_valid_before_utc
        .astimezone(timezone.utc)
    )

    expires_at = (
        issuer_certificate
        .not_valid_after_utc
        .astimezone(timezone.utc)
    )

    print(
        "Issuer:"
    )

    print(
        f"  Organization: {issuer_organization}"
    )

    print(
        f"  Common name:  {issuer_common_name}"
    )

    print(
        f"  Serial:       {serial}"
    )

    print(
        f"  Issued:       {issued_at.isoformat()}"
    )

    print(
        f"  Expires:      {expires_at.isoformat()}"
    )

    print()

    issuer_key_id = input(
        "Enter the v8 issuer key ID printed by rotate_issuer_v8.py: "
    ).strip()

    if not issuer_key_id:
        raise SystemExit(
            "Issuer key ID is required."
        )

    database_url = load_database_url()

    registry = PostgreSQLCredentialStore(
        database_url
    )

    record = CredentialRecord(
        key_id=issuer_key_id,
        certificate_serial_number=serial,
        subject=(
            issuer_certificate
            .subject
            .rfc4514_string()
        ),
        common_name=issuer_common_name,
        status=CredentialStatus.ACTIVE,
        issued_at=issued_at,
        expires_at=expires_at,
    )

    print()
    print(
        "Registering v8 credential in Neon..."
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
        print(
            f"  {exc}"
        )
        raise SystemExit(1)

    print()
    print("=" * 72)
    print(
        "V8 CREDENTIAL REGISTERED IN NEON"
    )
    print("=" * 72)
    print()

    print(
        f"Serial:   {record.certificate_serial_number}"
    )

    print(
        f"Key ID:   {record.key_id}"
    )

    print(
        f"Status:   {record.status.value}"
    )

    print(
        f"Expires:  {record.expires_at.isoformat()}"
    )

    print()

    print(
        "Neon audit chain valid:",
        registry.verify_audit_chain(),
    )

    print()
    print(
        "The v8 credential is now ACTIVE in Neon."
    )


if __name__ == "__main__":
    main()