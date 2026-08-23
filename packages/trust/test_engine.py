"""Tests for the AEGIS Trust Engine."""

from datetime import datetime, timezone

from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
)
from packages.trust.engine import (
    evaluate_c2pa_result,
)
from packages.trust.models import (
    AEGISStatus,
)


def make_record() -> CredentialRecord:
    return CredentialRecord(
        key_id="issuer-v4",
        certificate_serial_number=(
            "588662819360910049980569274172896276819088458057"
        ),
        subject="O=SOA University",
        common_name="Emergency Communications Issuer",
        status=CredentialStatus.ACTIVE,
        issued_at=datetime(
            2026,
            8,
            1,
            tzinfo=timezone.utc,
        ),
    )


def trusted_c2pa_result() -> dict:
    return {
        "activeManifest": {
            "success": [
                {
                    "code": "signingCredential.trusted",
                    "explanation": "signing certificate trusted",
                },
                {
                    "code": "claimSignature.validated",
                    "explanation": "claim signature valid",
                },
                {
                    "code": "assertion.dataHash.match",
                    "explanation": "data hash valid",
                },
            ],
            "failure": [],
        }
    }


def test_trusted_c2pa_with_active_credential_is_trusted():
    result = evaluate_c2pa_result(
        validation_state="Trusted",
        validation_results=trusted_c2pa_result(),
        credential_status=CredentialStatus.ACTIVE,
        credential_record=make_record(),
    )

    assert result.status is AEGISStatus.TRUSTED
    assert result.is_trusted
    assert result.issuer_trusted
    assert result.signature_valid
    assert result.content_integrity is True
    assert result.provenance_valid
    assert result.credential_active is True


def test_trusted_c2pa_with_revoked_credential_is_revoked():
    result = evaluate_c2pa_result(
        validation_state="Trusted",
        validation_results=trusted_c2pa_result(),
        credential_status=CredentialStatus.REVOKED,
        credential_record=make_record(),
    )

    assert (
        result.status
        is AEGISStatus.REVOKED_CREDENTIAL
    )

    assert result.issuer_trusted
    assert result.signature_valid
    assert result.content_integrity is True
    assert result.credential_active is False
    assert not result.is_trusted


def test_trusted_c2pa_with_expired_credential_is_expired():
    result = evaluate_c2pa_result(
        validation_state="Trusted",
        validation_results=trusted_c2pa_result(),
        credential_status=CredentialStatus.EXPIRED,
        credential_record=make_record(),
    )

    assert (
        result.status
        is AEGISStatus.EXPIRED_CREDENTIAL
    )

    assert result.credential_active is False


def test_hash_mismatch_still_beats_active_credential():
    result = evaluate_c2pa_result(
        validation_state="Invalid",
        validation_results={
            "activeManifest": {
                "success": [
                    {
                        "code": "signingCredential.trusted",
                        "explanation": "signing certificate trusted",
                    },
                    {
                        "code": "claimSignature.validated",
                        "explanation": "claim signature valid",
                    },
                ],
                "failure": [
                    {
                        "code": "assertion.dataHash.mismatch",
                        "explanation": "Hashes do not match",
                    },
                ],
            }
        },
        credential_status=CredentialStatus.ACTIVE,
        credential_record=make_record(),
    )

    assert (
        result.status
        is AEGISStatus.INTEGRITY_FAILURE
    )


def test_untrusted_issuer_becomes_untrusted_issuer():
    result = evaluate_c2pa_result(
        validation_state="Invalid",
        validation_results={
            "activeManifest": {
                "success": [
                    {
                        "code": "claimSignature.validated",
                        "explanation": "claim signature valid",
                    },
                ],
                "failure": [
                    {
                        "code": "signingCredential.untrusted",
                        "explanation": "signing certificate untrusted",
                    },
                ],
            }
        },
        credential_status=None,
    )

    assert (
        result.status
        is AEGISStatus.UNTRUSTED_ISSUER
    )


def test_malformed_provenance_is_detected():
    result = evaluate_c2pa_result(
        validation_state="Invalid",
        validation_results={
            "activeManifest": {
                "success": [],
                "failure": [
                    {
                        "code": "assertion.action.malformed",
                        "explanation": "Malformed action",
                    },
                ],
            }
        },
        credential_status=CredentialStatus.ACTIVE,
    )

    assert (
        result.status
        is AEGISStatus.MALFORMED_PROVENANCE
    )