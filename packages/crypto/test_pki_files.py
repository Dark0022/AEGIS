"""Integration tests for the persisted AEGIS PKI hierarchy."""

from pathlib import Path

import pytest

from packages.crypto.chain import (
    ChainValidationError,
    validate_issuer_chain,
)
from packages.crypto.pki_store import load_certificate


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ROOT_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "root"
    / "root-cert.pem"
)

INSTITUTION_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "institutions"
    / "soa-university"
    / "ca-cert.pem"
)

ISSUER_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications"
    / "issuer-cert.pem"
)


def _require_bootstrapped_pki() -> None:
    """Skip integration tests when the development PKI is absent."""
    required_paths = [
        ROOT_CERT_PATH,
        INSTITUTION_CERT_PATH,
        ISSUER_CERT_PATH,
    ]

    missing = [
        str(path)
        for path in required_paths
        if not path.is_file()
    ]

    if missing:
        pytest.skip(
            "Development PKI has not been bootstrapped. "
            "Missing: "
            + ", ".join(missing)
        )


def test_persisted_certificates_load():
    """All generated certificates can be loaded from disk."""
    _require_bootstrapped_pki()

    root_certificate = load_certificate(
        ROOT_CERT_PATH
    )

    institution_certificate = load_certificate(
        INSTITUTION_CERT_PATH
    )

    issuer_certificate = load_certificate(
        ISSUER_CERT_PATH
    )

    assert root_certificate.subject == (
        root_certificate.issuer
    )

    assert institution_certificate.issuer == (
        root_certificate.subject
    )

    assert issuer_certificate.issuer == (
        institution_certificate.subject
    )


def test_persisted_three_level_chain_is_valid():
    """The actual persisted Root -> Institution -> Issuer chain validates."""
    _require_bootstrapped_pki()

    root_certificate = load_certificate(
        ROOT_CERT_PATH
    )

    institution_certificate = load_certificate(
        INSTITUTION_CERT_PATH
    )

    issuer_certificate = load_certificate(
        ISSUER_CERT_PATH
    )

    validate_issuer_chain(
        issuer_certificate,
        institution_certificate,
        root_certificate,
    )


def test_persisted_root_is_aegis_root():
    """The persisted root has the expected AEGIS identity."""
    _require_bootstrapped_pki()

    root_certificate = load_certificate(
        ROOT_CERT_PATH
    )

    subject = root_certificate.subject.rfc4514_string()

    assert "CN=AEGIS Root CA" in subject
    assert "O=AEGIS" in subject


def test_persisted_institution_is_soa_university():
    """The persisted Institution CA belongs to SOA University."""
    _require_bootstrapped_pki()

    certificate = load_certificate(
        INSTITUTION_CERT_PATH
    )

    subject = certificate.subject.rfc4514_string()

    assert "CN=SOA University CA" in subject
    assert "O=SOA University" in subject


def test_persisted_issuer_is_emergency_communications():
    """The persisted issuer has the expected institutional role."""
    _require_bootstrapped_pki()

    certificate = load_certificate(
        ISSUER_CERT_PATH
    )

    subject = certificate.subject.rfc4514_string()

    assert "CN=Emergency Communications Issuer" in subject
    assert "O=SOA University" in subject
    assert (
        "OU=Emergency Management Office"
        in subject
    )


def test_wrong_root_rejects_persisted_chain():
    """The persisted issuer must not validate under another root."""
    _require_bootstrapped_pki()

    root_certificate = load_certificate(
        ROOT_CERT_PATH
    )

    institution_certificate = load_certificate(
        INSTITUTION_CERT_PATH
    )

    issuer_certificate = load_certificate(
        ISSUER_CERT_PATH
    )

    from packages.crypto.pki import (
        build_root_certificate,
        generate_ed25519_keypair,
    )

    wrong_root_key = generate_ed25519_keypair()

    wrong_root_certificate = build_root_certificate(
        wrong_root_key,
        common_name="Untrusted Root CA",
        organization="Untrusted",
    )

    with pytest.raises(ChainValidationError):
        validate_issuer_chain(
            issuer_certificate,
            institution_certificate,
            wrong_root_certificate,
        )