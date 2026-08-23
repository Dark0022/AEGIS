"""X.509 PKI primitives for AEGIS."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID, ObjectIdentifier


ROOT_VALIDITY_DAYS: Final[int] = 3650
ROOT_PATH_LENGTH: Final[int] = 1

INSTITUTION_CA_VALIDITY_DAYS: Final[int] = 1825
INSTITUTION_CA_PATH_LENGTH: Final[int] = 0

ISSUER_VALIDITY_DAYS: Final[int] = 365

# C2PA claim-signing EKU introduced by the C2PA specification.
C2PA_CLAIM_SIGNING_EKU: Final[ObjectIdentifier] = (
    ObjectIdentifier("1.3.6.1.4.1.62558.2.1")
)

# Retained for compatibility with validators using the older
# document-signing EKU convention.
DOCUMENT_SIGNING_EKU: Final[ObjectIdentifier] = (
    ObjectIdentifier("1.3.6.1.5.5.7.3.36")
)


def generate_ed25519_keypair() -> ed25519.Ed25519PrivateKey:
    """Generate a new Ed25519 private key."""
    return ed25519.Ed25519PrivateKey.generate()


def build_root_certificate(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    common_name: str = "AEGIS Root CA",
    organization: str = "AEGIS",
    validity_days: int = ROOT_VALIDITY_DAYS,
) -> x509.Certificate:
    """
    Create a self-signed AEGIS Root CA certificate.

    The root is allowed to sign Institution CA certificates but is
    not intended to sign end-entity certificates or content directly.
    """
    if validity_days <= 0:
        raise ValueError("validity_days must be positive.")

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                "IN",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                organization,
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
        ]
    )

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(
            now + timedelta(days=validity_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=ROOT_PATH_LENGTH,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()
            ),
            critical=False,
        )
    )

    return builder.sign(
        private_key=private_key,
        algorithm=None,
    )


def build_institution_ca_certificate(
    institution_private_key: ed25519.Ed25519PrivateKey,
    root_private_key: ed25519.Ed25519PrivateKey,
    root_certificate: x509.Certificate,
    *,
    common_name: str,
    organization: str,
    validity_days: int = INSTITUTION_CA_VALIDITY_DAYS,
) -> x509.Certificate:
    """
    Create an Institution CA certificate signed by the AEGIS Root CA.

    The Institution CA may issue end-entity certificates but may not
    create another subordinate CA.
    """
    if validity_days <= 0:
        raise ValueError("validity_days must be positive.")

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                "IN",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                organization,
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
        ]
    )

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_certificate.subject)
        .public_key(institution_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(
            now + timedelta(days=validity_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=INSTITUTION_CA_PATH_LENGTH,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                institution_private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_private_key.public_key()
            ),
            critical=False,
        )
    )

    return builder.sign(
        private_key=root_private_key,
        algorithm=None,
    )


def build_issuer_certificate(
    issuer_private_key: ed25519.Ed25519PrivateKey,
    institution_private_key: ed25519.Ed25519PrivateKey,
    institution_certificate: x509.Certificate,
    *,
    common_name: str,
    organization: str,
    organizational_unit: str,
    validity_days: int = ISSUER_VALIDITY_DAYS,
) -> x509.Certificate:
    """
    Create an AEGIS Authorized Issuer certificate.

    The issuer is an end-entity certificate authorized for:
    - digital signatures
    - C2PA claim signing
    - document signing compatibility

    It is explicitly not a CA.
    """
    if validity_days <= 0:
        raise ValueError("validity_days must be positive.")

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                "IN",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                organization,
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                organizational_unit,
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
        ]
    )

    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(institution_certificate.subject)
        .public_key(issuer_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(
            now + timedelta(days=validity_days)
        )
        .add_extension(
            x509.BasicConstraints(
                ca=False,
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    C2PA_CLAIM_SIGNING_EKU,
                    DOCUMENT_SIGNING_EKU,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                issuer_private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                institution_private_key.public_key()
            ),
            critical=False,
        )
    )

    return builder.sign(
        private_key=institution_private_key,
        algorithm=None,
    )


def serialize_private_key(
    private_key: ed25519.Ed25519PrivateKey,
) -> bytes:
    """
    Serialize a private key into raw Ed25519 bytes.

    This function does not encrypt or persist the key.
    Higher-level protected storage must handle that.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )