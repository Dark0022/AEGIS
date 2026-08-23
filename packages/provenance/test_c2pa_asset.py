"""Tests for creating AEGIS C2PA-signed assets."""

from pathlib import Path

import pytest

from packages.crypto.providers.pki_signer import PKISigner
from packages.provenance.c2pa_asset import (
    add_created_action,
    create_manifest,
    detect_asset_format,
    sign_asset,
)
from packages.provenance.c2pa_signer import (
    AEGISC2PASigner,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SOURCE_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice.png"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_signed.png"
)

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


def test_detect_png_format():
    """Detect the correct MIME type for the synthetic PNG."""
    if not SOURCE_PATH.is_file():
        pytest.skip(
            f"Missing source asset: {SOURCE_PATH}"
        )

    assert detect_asset_format(
        SOURCE_PATH
    ) == "image/png"


def test_sign_png_with_aegis_issuer_v7(
    issuer_v7_password: str,
):
    """Create a C2PA-signed PNG using AEGIS Issuer v7."""
    required = (
        SOURCE_PATH,
        ISSUER_KEY_PATH,
        ISSUER_CERT_PATH,
        INSTITUTION_CERT_PATH,
    )

    missing = [
        path
        for path in required
        if not path.is_file()
    ]

    if missing:
        pytest.skip(
            "Required AEGIS v7 signing artifacts are missing: "
            f"{missing}"
        )

    if OUTPUT_PATH.exists():
        OUTPUT_PATH.unlink()

    aegis_signer = PKISigner.load(
        ISSUER_KEY_PATH,
        issuer_v7_password,
    )

    c2pa_signer = AEGISC2PASigner(
        aegis_signer,
        issuer_certificate_path=ISSUER_CERT_PATH,
        institution_certificate_path=INSTITUTION_CERT_PATH,
    )

    asset_format = detect_asset_format(
        SOURCE_PATH
    )

    builder = create_manifest(
        claim_generator="AEGIS/0.1",
        asset_format=asset_format,
    )

    add_created_action(
        builder,
    )

    sign_asset(
        builder,
        source_path=SOURCE_PATH,
        destination_path=OUTPUT_PATH,
        signer=c2pa_signer,
    )

    assert OUTPUT_PATH.is_file()
    assert OUTPUT_PATH.stat().st_size > 0