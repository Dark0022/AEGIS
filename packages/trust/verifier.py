"""End-to-end AEGIS asset verification."""

from __future__ import annotations

from pathlib import Path

from packages.provenance.c2pa_verify import (
    create_aegis_context,
    get_signature_info,
    get_validation_results,
    get_validation_state,
    read_manifest,
)
from packages.trust.credentials import (
    CredentialRegistry,
)
from packages.trust.engine import (
    evaluate_c2pa_result,
)
from packages.trust.models import (
    AEGISVerificationResult,
)


class AEGISVerifierError(Exception):
    """Raised when AEGIS verification cannot be completed."""


def verify_asset(
    asset_path: str | Path,
    *,
    root_certificate_path: str | Path,
    credential_registry: CredentialRegistry | None = None,
) -> AEGISVerificationResult:
    """
    Verify an asset through C2PA and the AEGIS Trust Engine.

    When a credential registry is supplied, the C2PA certificate serial
    is resolved against the current credential lifecycle state.
    """
    asset = Path(asset_path)

    if not asset.is_file():
        raise FileNotFoundError(
            f"Asset not found: {asset}"
        )

    root_certificate = Path(
        root_certificate_path
    )

    if not root_certificate.is_file():
        raise FileNotFoundError(
            "AEGIS Root certificate not found: "
            f"{root_certificate}"
        )

    try:
        context = create_aegis_context(
            root_certificate
        )

        reader = read_manifest(
            asset,
            context=context,
        )

        validation_state = get_validation_state(
            reader
        )

        validation_results = get_validation_results(
            reader
        )

        signature_info = get_signature_info(
            reader
        )

        credential_status = None
        credential_record = None

        if credential_registry is not None:
            try:
                credential_record = (
                    credential_registry.get_by_serial(
                        signature_info[
                            "cert_serial_number"
                        ]
                    )
                )

                credential_status = (
                    credential_registry.status_at(
                        signature_info[
                            "cert_serial_number"
                        ]
                    )
                )

            except KeyError:
                credential_status = None
                credential_record = None

        result = evaluate_c2pa_result(
            validation_state=validation_state,
            validation_results=validation_results,
            credential_status=credential_status,
            credential_record=credential_record,
        )

        return result

    except Exception as exc:
        raise AEGISVerifierError(
            f"Unable to verify asset: {asset}"
        ) from exc