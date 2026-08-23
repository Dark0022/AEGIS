"""AEGIS-specific X.509 trust-chain validation."""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography import x509


class ChainValidationError(Exception):
    """Raised when an AEGIS certificate chain is invalid."""


def validate_institution_chain(
    institution_certificate: x509.Certificate,
    root_certificate: x509.Certificate,
    *,
    verification_time: datetime | None = None,
) -> None:
    """
    Validate an AEGIS Root CA -> Institution CA chain.

    Performs:
    - issuer/subject relationship validation
    - certificate signature validation
    - validity-period validation
    - root CA constraint validation
    - institution CA constraint validation
    - institution key-usage validation
    """
    if verification_time is None:
        verification_time = datetime.now(timezone.utc)

    _validate_verification_time(verification_time)

    try:
        institution_certificate.verify_directly_issued_by(
            root_certificate
        )
    except (ValueError, TypeError) as exc:
        raise ChainValidationError(
            "Institution certificate is not directly issued by "
            "the provided root certificate."
        ) from exc

    _check_validity(
        root_certificate,
        verification_time,
        "Root certificate",
    )

    _check_validity(
        institution_certificate,
        verification_time,
        "Institution certificate",
    )

    if root_certificate.issuer != root_certificate.subject:
        raise ChainValidationError(
            "Root certificate is not self-issued."
        )

    root_constraints = (
        root_certificate.extensions
        .get_extension_for_class(x509.BasicConstraints)
        .value
    )

    if not root_constraints.ca:
        raise ChainValidationError(
            "Root certificate is not a CA."
        )

    if root_constraints.path_length != 1:
        raise ChainValidationError(
            "AEGIS Root CA must have pathLenConstraint=1."
        )

    institution_constraints = (
        institution_certificate.extensions
        .get_extension_for_class(x509.BasicConstraints)
        .value
    )

    if not institution_constraints.ca:
        raise ChainValidationError(
            "Institution certificate is not a CA."
        )

    if institution_constraints.path_length != 0:
        raise ChainValidationError(
            "Institution CA must have pathLenConstraint=0."
        )

    institution_key_usage = (
        institution_certificate.extensions
        .get_extension_for_class(x509.KeyUsage)
        .value
    )

    if not institution_key_usage.key_cert_sign:
        raise ChainValidationError(
            "Institution CA cannot sign certificates."
        )

    if not institution_key_usage.crl_sign:
        raise ChainValidationError(
            "Institution CA cannot sign CRLs."
        )


def validate_issuer_chain(
    issuer_certificate: x509.Certificate,
    institution_certificate: x509.Certificate,
    root_certificate: x509.Certificate,
    *,
    verification_time: datetime | None = None,
) -> None:
    """
    Validate the complete AEGIS chain:

        Root CA -> Institution CA -> Authorized Issuer
    """
    if verification_time is None:
        verification_time = datetime.now(timezone.utc)

    _validate_verification_time(verification_time)

    validate_institution_chain(
        institution_certificate,
        root_certificate,
        verification_time=verification_time,
    )

    try:
        issuer_certificate.verify_directly_issued_by(
            institution_certificate
        )
    except (ValueError, TypeError) as exc:
        raise ChainValidationError(
            "Issuer certificate is not directly issued by "
            "the provided Institution CA."
        ) from exc

    _check_validity(
        issuer_certificate,
        verification_time,
        "Issuer certificate",
    )

    issuer_constraints = (
        issuer_certificate.extensions
        .get_extension_for_class(x509.BasicConstraints)
        .value
    )

    if issuer_constraints.ca:
        raise ChainValidationError(
            "Authorized Issuer certificate must not be a CA."
        )

    issuer_key_usage = (
        issuer_certificate.extensions
        .get_extension_for_class(x509.KeyUsage)
        .value
    )

    if not issuer_key_usage.digital_signature:
        raise ChainValidationError(
            "Authorized Issuer must allow digital signatures."
        )

    if issuer_key_usage.key_cert_sign:
        raise ChainValidationError(
            "Authorized Issuer must not be allowed to sign certificates."
        )

    if issuer_key_usage.crl_sign:
        raise ChainValidationError(
            "Authorized Issuer must not be allowed to sign CRLs."
        )


def _validate_verification_time(
    verification_time: datetime,
) -> None:
    """Ensure verification time is timezone-aware."""
    if verification_time.tzinfo is None:
        raise ValueError(
            "verification_time must be timezone-aware."
        )


def _check_validity(
    certificate: x509.Certificate,
    verification_time: datetime,
    description: str,
) -> None:
    """Check whether a certificate is valid at a specific time."""
    if not (
        certificate.not_valid_before_utc
        <= verification_time
        <= certificate.not_valid_after_utc
    ):
        raise ChainValidationError(
            f"{description} is not valid at the requested time."
        )