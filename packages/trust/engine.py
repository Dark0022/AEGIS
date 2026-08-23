"""AEGIS Trust Engine."""

from __future__ import annotations

from packages.trust.credentials import CredentialStatus
from packages.trust.models import (
    AEGISStatus,
    AEGISVerificationResult,
    VerificationEvidence,
)


def evaluate_c2pa_result(
    *,
    validation_state: str,
    validation_results: dict,
    credential_status: CredentialStatus | None = None,
    credential_record: object | None = None,
) -> AEGISVerificationResult:
    """
    Convert C2PA evidence plus credential lifecycle state into
    an AEGIS trust decision.

    Credential lifecycle state is retained in the result even when
    content integrity or provenance has failed. The dominant verdict
    still reflects the highest-priority failure.
    """
    active_manifest = validation_results.get(
        "activeManifest",
        {},
    )

    success_items = active_manifest.get(
        "success",
        [],
    )

    failure_items = active_manifest.get(
        "failure",
        [],
    )

    evidence: list[VerificationEvidence] = []

    for item in success_items:
        evidence.append(
            VerificationEvidence(
                code=item.get(
                    "code",
                    "unknown",
                ),
                message=item.get(
                    "explanation",
                    "",
                ),
                source="C2PA",
            )
        )

    for item in failure_items:
        evidence.append(
            VerificationEvidence(
                code=item.get(
                    "code",
                    "unknown",
                ),
                message=item.get(
                    "explanation",
                    "",
                ),
                source="C2PA",
            )
        )

    if credential_record is not None:
        common_name = getattr(
            credential_record,
            "common_name",
            None,
        )

        certificate_serial = getattr(
            credential_record,
            "certificate_serial_number",
            None,
        )

        if common_name:
            evidence.append(
                VerificationEvidence(
                    code="credential.identity",
                    message=str(common_name),
                    source="AEGIS",
                )
            )

        if certificate_serial:
            evidence.append(
                VerificationEvidence(
                    code="credential.serial",
                    message=str(certificate_serial),
                    source="AEGIS",
                )
            )

    if credential_status is not None:
        evidence.append(
            VerificationEvidence(
                code="credential.status",
                message=credential_status.value,
                source="AEGIS",
            )
        )

    success_codes = {
        item.get("code")
        for item in success_items
    }

    failure_codes = {
        item.get("code")
        for item in failure_items
    }

    issuer_trusted = (
        "signingCredential.trusted"
        in success_codes
    )

    signature_valid = (
        "claimSignature.validated"
        in success_codes
    )

    integrity_validated = (
        "assertion.dataHash.match"
        in success_codes
    )

    integrity_failed = (
        "assertion.dataHash.mismatch"
        in failure_codes
    )

    malformed_provenance = any(
        str(code).startswith(
            "assertion.action.malformed"
        )
        for code in failure_codes
        if code is not None
    )

    signature_failed = any(
        str(code).startswith(
            "claimSignature."
        )
        for code in failure_codes
        if code is not None
    )

    content_integrity = (
        True
        if integrity_validated
        else False
        if integrity_failed
        else None
    )

    provenance_valid = (
        not malformed_provenance
        and not signature_failed
    )

    credential_active = (
        credential_status
        is CredentialStatus.ACTIVE
    )

    credential_status_value = (
        credential_status.value
        if credential_status is not None
        else None
    )

    # Failure precedence:
    #
    # 1. malformed provenance
    # 2. content integrity failure
    # 3. invalid signature
    # 4. untrusted issuer
    # 5. credential lifecycle state
    # 6. trusted / unverified fallback
    #
    # Credential state is deliberately NOT allowed to disappear from
    # the result when a higher-priority cryptographic failure occurs.

    if malformed_provenance:
        status = AEGISStatus.MALFORMED_PROVENANCE

    elif integrity_failed:
        status = AEGISStatus.INTEGRITY_FAILURE

    elif signature_failed and not signature_valid:
        status = AEGISStatus.INVALID_SIGNATURE

    elif not issuer_trusted:
        status = AEGISStatus.UNTRUSTED_ISSUER

    elif credential_status is CredentialStatus.REVOKED:
        status = AEGISStatus.REVOKED_CREDENTIAL

    elif credential_status is CredentialStatus.EXPIRED:
        status = AEGISStatus.EXPIRED_CREDENTIAL

    elif credential_status is CredentialStatus.ACTIVE:
        if validation_state == "Trusted":
            status = AEGISStatus.TRUSTED
        else:
            status = AEGISStatus.UNVERIFIED

    else:
        status = AEGISStatus.UNTRUSTED_ISSUER

    return AEGISVerificationResult(
        status=status,
        issuer_trusted=issuer_trusted,
        signature_valid=signature_valid,
        content_integrity=content_integrity,
        provenance_valid=provenance_valid,
        credential_active=credential_active,
        credential_status=credential_status_value,
        evidence=tuple(evidence),
    )