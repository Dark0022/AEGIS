"""Tests for AEGIS C2PA tamper detection."""

from pathlib import Path

import pytest

from packages.provenance.c2pa_verify import (
    create_aegis_context,
    get_validation_results,
    get_validation_state,
    read_manifest,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TRUSTED_ASSET_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_signed.png"
)

TAMPERED_ASSET_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_tampered.png"
)

ROOT_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "root"
    / "root-cert.pem"
)


def test_tampered_asset_is_detected():
    """A modified asset must fail C2PA content verification."""
    required = (
        TRUSTED_ASSET_PATH,
        TAMPERED_ASSET_PATH,
        ROOT_CERT_PATH,
    )

    missing = [
        path
        for path in required
        if not path.is_file()
    ]

    if missing:
        pytest.skip(
            "Required AEGIS attack-lab artifacts are missing: "
            f"{missing}"
        )

    context = create_aegis_context(
        ROOT_CERT_PATH
    )

    trusted_reader = read_manifest(
        TRUSTED_ASSET_PATH,
        context=context,
    )

    tampered_reader = read_manifest(
        TAMPERED_ASSET_PATH,
        context=context,
    )

    assert get_validation_state(
        trusted_reader
    ) == "Trusted"

    assert get_validation_state(
        tampered_reader
    ) == "Invalid"

    results = get_validation_results(
        tampered_reader
    )

    active_manifest = results["activeManifest"]

    failure_codes = {
        item["code"]
        for item in active_manifest["failure"]
    }

    assert "assertion.dataHash.mismatch" in failure_codes


def test_tampered_asset_preserves_trusted_signer_evidence():
    """
    The tampered asset should still retain the original trusted
    signing identity while failing content integrity.
    """
    required = (
        TAMPERED_ASSET_PATH,
        ROOT_CERT_PATH,
    )

    missing = [
        path
        for path in required
        if not path.is_file()
    ]

    if missing:
        pytest.skip(
            "Required AEGIS attack-lab artifacts are missing: "
            f"{missing}"
        )

    context = create_aegis_context(
        ROOT_CERT_PATH
    )

    reader = read_manifest(
        TAMPERED_ASSET_PATH,
        context=context,
    )

    results = get_validation_results(
        reader
    )

    active_manifest = results["activeManifest"]

    success_codes = {
        item["code"]
        for item in active_manifest["success"]
    }

    failure_codes = {
        item["code"]
        for item in active_manifest["failure"]
    }

    assert "signingCredential.trusted" in success_codes
    assert "claimSignature.validated" in success_codes
    assert "assertion.dataHash.mismatch" in failure_codes