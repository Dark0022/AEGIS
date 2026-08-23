"""C2PA verification helpers for AEGIS."""

from __future__ import annotations

import json
from pathlib import Path

import c2pa


class C2PAVerificationError(Exception):
    """Raised when C2PA verification cannot be performed."""


def create_aegis_context(
    root_certificate_path: str | Path,
) -> c2pa.Context:
    """Create a C2PA context that trusts the AEGIS Root CA."""
    root_path = Path(root_certificate_path)

    if not root_path.is_file():
        raise FileNotFoundError(
            f"AEGIS Root certificate not found: {root_path}"
        )

    try:
        root_pem = root_path.read_text(
            encoding="ascii"
        )
    except OSError as exc:
        raise C2PAVerificationError(
            f"Unable to read AEGIS Root certificate: {root_path}"
        ) from exc

    if (
        "-----BEGIN CERTIFICATE-----"
        not in root_pem
    ):
        raise C2PAVerificationError(
            "AEGIS Root certificate is not PEM encoded."
        )

    settings = c2pa.Settings.from_dict(
        {
            "verify": {
                "verify_after_reading": True,
                "verify_trust": True,
            },
            "trust": {
                "verify_trust_list": True,
                "trust_anchors": root_pem,
            },
        }
    )

    try:
        return (
            c2pa.ContextBuilder()
            .with_settings(settings)
            .build()
        )
    except Exception as exc:
        raise C2PAVerificationError(
            "Unable to create AEGIS C2PA verification context."
        ) from exc


def read_manifest(
    asset_path: str | Path,
    *,
    context: c2pa.Context | None = None,
) -> c2pa.Reader:
    """Read C2PA provenance from an asset."""
    path = Path(asset_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Asset not found: {path}"
        )

    try:
        return c2pa.Reader(
            path,
            context=context,
        )
    except Exception as exc:
        raise C2PAVerificationError(
            f"Unable to read C2PA provenance from: {path}"
        ) from exc


def get_manifest_json(
    reader: c2pa.Reader,
) -> str:
    """Return the C2PA manifest store as JSON text."""
    try:
        return reader.json()
    except Exception as exc:
        raise C2PAVerificationError(
            "Unable to extract C2PA manifest JSON."
        ) from exc


def get_validation_state(
    reader: c2pa.Reader,
) -> str:
    """Return the C2PA validation state."""
    try:
        return reader.get_validation_state()
    except Exception as exc:
        raise C2PAVerificationError(
            "Unable to read C2PA validation state."
        ) from exc


def get_validation_results(
    reader: c2pa.Reader,
) -> dict:
    """Return detailed C2PA validation results."""
    try:
        return reader.get_validation_results()
    except Exception as exc:
        raise C2PAVerificationError(
            "Unable to read C2PA validation results."
        ) from exc


def is_valid(
    reader: c2pa.Reader,
) -> bool:
    """Return the C2PA validity property."""
    try:
        return bool(reader.is_valid)
    except Exception as exc:
        raise C2PAVerificationError(
            "Unable to determine C2PA validity."
        ) from exc


def get_signature_info(
    reader: c2pa.Reader,
) -> dict:
    """
    Extract the active manifest's signature_info.

    The current c2pa-python API exposes certificate serial number,
    issuer, common name, and signing algorithm here.
    """
    try:
        document = json.loads(
            reader.json()
        )
    except (
        OSError,
        ValueError,
        TypeError,
    ) as exc:
        raise C2PAVerificationError(
            "Unable to decode C2PA manifest JSON."
        ) from exc

    active_manifest_id = document.get(
        "active_manifest"
    )

    if not active_manifest_id:
        raise C2PAVerificationError(
            "C2PA manifest does not identify an active manifest."
        )

    manifests = document.get(
        "manifests"
    )

    if not isinstance(
        manifests,
        dict,
    ):
        raise C2PAVerificationError(
            "C2PA manifest store has no manifest collection."
        )

    active_manifest = manifests.get(
        active_manifest_id
    )

    if not isinstance(
        active_manifest,
        dict,
    ):
        raise C2PAVerificationError(
            "Active C2PA manifest was not found."
        )

    signature_info = active_manifest.get(
        "signature_info"
    )

    if not isinstance(
        signature_info,
        dict,
    ):
        raise C2PAVerificationError(
            "C2PA signature information is missing."
        )

    required_fields = (
        "issuer",
        "common_name",
        "cert_serial_number",
        "alg",
    )

    missing = [
        field
        for field in required_fields
        if not signature_info.get(field)
    ]

    if missing:
        raise C2PAVerificationError(
            "C2PA signature information is missing fields: "
            f"{missing}"
        )

    return {
        "issuer": signature_info["issuer"],
        "common_name": signature_info["common_name"],
        "cert_serial_number": str(
            signature_info["cert_serial_number"]
        ),
        "alg": signature_info["alg"],
    }