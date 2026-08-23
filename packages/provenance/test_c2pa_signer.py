"""Tests for the AEGIS-to-C2PA signer integration."""

from pathlib import Path

import c2pa
import pytest

from packages.crypto.providers.pki_signer import PKISigner
from packages.provenance.c2pa_signer import (
    AEGISC2PASigner,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

ISSUER_KEY_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v7"
    / "issuer-key.json"
)

ISSUER_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v7"
    / "issuer-cert.pem"
)

INSTITUTION_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "institutions"
    / "soa-university"
    / "ca-cert.pem"
)


def test_c2pa_signer_constructs_from_active_issuer_v7(
    issuer_v7_password: str,
):
    """Build a C2PA signer from the current AEGIS Issuer v7."""
    required_files = (
        ISSUER_KEY_PATH,
        ISSUER_CERT_PATH,
        INSTITUTION_CERT_PATH,
    )

    missing_files = [
        path
        for path in required_files
        if not path.is_file()
    ]

    if missing_files:
        pytest.skip(
            "AEGIS development PKI v7 is not bootstrapped. "
            f"Missing: {missing_files}"
        )

    aegis_signer = PKISigner.load(
        ISSUER_KEY_PATH,
        issuer_v7_password,
    )

    adapter = AEGISC2PASigner(
        aegis_signer,
        issuer_certificate_path=ISSUER_CERT_PATH,
        institution_certificate_path=INSTITUTION_CERT_PATH,
    )

    assert adapter.key_id == (
        aegis_signer.key_id()
    )

    assert adapter.certificate_chain

    assert isinstance(
        adapter.signer,
        c2pa.Signer,
    )