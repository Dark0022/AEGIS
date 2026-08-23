"""Tests for verifying AEGIS C2PA-signed assets."""

from pathlib import Path

import pytest

from packages.provenance.c2pa_verify import (
    create_aegis_context,
    get_manifest_json,
    get_validation_results,
    get_validation_state,
    is_valid,
    read_manifest,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SIGNED_ASSET_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_signed.png"
)

ROOT_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "root"
    / "root-cert.pem"
)


def test_signed_asset_contains_c2pa_manifest():
    """The signed PNG contains readable C2PA provenance."""
    if not SIGNED_ASSET_PATH.is_file():
        pytest.skip(
            f"Missing signed asset: {SIGNED_ASSET_PATH}"
        )

    reader = read_manifest(
        SIGNED_ASSET_PATH
    )

    manifest_json = get_manifest_json(
        reader
    )

    assert manifest_json
    assert (
        '"title": "AEGIS Official Communication"'
        in manifest_json
    )
    assert '"label": "c2pa.actions.v2"' in manifest_json
    assert '"action": "c2pa.created"' in manifest_json
    assert '"alg": "Ed25519"' in manifest_json
    assert '"issuer":' in manifest_json


def test_aegis_context_can_be_created():
    """The AEGIS Root can be loaded as a trust anchor."""
    if not ROOT_CERT_PATH.is_file():
        pytest.skip(
            f"Missing AEGIS Root certificate: {ROOT_CERT_PATH}"
        )

    context = create_aegis_context(
        ROOT_CERT_PATH
    )

    assert context.is_valid


def test_signed_asset_is_trusted_by_aegis():
    """The signed PNG passes the AEGIS C2PA trust policy."""
    required = (
        SIGNED_ASSET_PATH,
        ROOT_CERT_PATH,
    )

    missing = [
        path
        for path in required
        if not path.is_file()
    ]

    if missing:
        pytest.skip(
            "Required AEGIS verification artifacts are missing: "
            f"{missing}"
        )

    context = create_aegis_context(
        ROOT_CERT_PATH
    )

    reader = read_manifest(
        SIGNED_ASSET_PATH,
        context=context,
    )

    state = get_validation_state(
        reader
    )

    results = get_validation_results(
        reader
    )

    assert state == "Trusted"
    assert is_valid(reader)

    active_manifest = results["activeManifest"]

    assert active_manifest["failure"] == []

    success_codes = {
        item["code"]
        for item in active_manifest["success"]
    }

    assert "signingCredential.trusted" in success_codes
    assert "claimSignature.insideValidity" in success_codes
    assert "claimSignature.validated" in success_codes
    assert "assertion.dataHash.match" in success_codes