"""AEGIS C2PA asset signing helpers."""

from __future__ import annotations

import json
import mimetypes
from pathlib import Path

import c2pa

from packages.provenance.c2pa_signer import AEGISC2PASigner


class C2PAAssetError(Exception):
    """Raised when an AEGIS C2PA asset operation fails."""


C2PA_EMPTY_DIGITAL_SOURCE = (
    "http://c2pa.org/digitalsourcetype/empty"
)


def create_manifest(
    *,
    claim_generator: str,
    asset_format: str,
) -> c2pa.Builder:
    """Create a minimal C2PA manifest builder."""
    if not claim_generator.strip():
        raise ValueError(
            "claim_generator must not be empty."
        )

    if not asset_format.strip():
        raise ValueError(
            "asset_format must not be empty."
        )

    manifest = {
        "claim_generator": claim_generator,
        "title": "AEGIS Official Communication",
        "format": asset_format,
        "assertions": [],
    }

    try:
        return c2pa.Builder.from_json(
            json.dumps(manifest)
        )
    except Exception as exc:
        raise C2PAAssetError(
            "Unable to create C2PA manifest builder."
        ) from exc


def add_created_action(
    builder: c2pa.Builder,
    *,
    digital_source_type: str = C2PA_EMPTY_DIGITAL_SOURCE,
) -> None:
    """
    Add a C2PA creation action.

    This explicitly supplies digitalSourceType because the C2PA
    validator requires it for c2pa.created.
    """
    if not digital_source_type.strip():
        raise ValueError(
            "digital_source_type must not be empty."
        )

    action = {
        "action": "c2pa.created",
        "digitalSourceType": digital_source_type,
    }

    try:
        builder.add_action(action)
    except Exception as exc:
        raise C2PAAssetError(
            "Unable to add creation action."
        ) from exc


def detect_asset_format(
    asset_path: str | Path,
) -> str:
    """Determine the MIME type of a supported asset."""
    path = Path(asset_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Asset not found: {path}"
        )

    asset_format, _ = mimetypes.guess_type(
        path.name
    )

    if not asset_format:
        raise C2PAAssetError(
            f"Unable to determine MIME type: {path}"
        )

    return asset_format


def sign_asset(
    builder: c2pa.Builder,
    *,
    source_path: str | Path,
    destination_path: str | Path,
    signer: AEGISC2PASigner,
) -> None:
    """Sign a supported media asset with the supplied AEGIS signer."""
    source = Path(source_path)
    destination = Path(destination_path)

    if not source.is_file():
        raise FileNotFoundError(
            f"Source asset not found: {source}"
        )

    if destination.exists():
        raise FileExistsError(
            f"Destination asset already exists: {destination}"
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        builder.sign_file(
            source,
            destination,
            signer.signer,
        )
    except Exception as exc:
        raise C2PAAssetError(
            f"Unable to sign asset: {source}"
        ) from exc