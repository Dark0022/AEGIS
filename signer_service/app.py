"""AEGIS isolated signing service.

Only this process has access to the issuer private key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
)
from pydantic import BaseModel, Field

from packages.provenance.notice_signing import (
    NoticeSigningError,
    sign_notice_asset,
)

from packages.storage_b2 import (
    B2ObjectStore,
    B2StorageError,
)


app = FastAPI(
    title="AEGIS Signing Service",
    version="1.0.0",
)


class SignRequest(BaseModel):
    """Request to sign an asset stored in B2."""

    notice_id: str = Field(
        min_length=1,
        max_length=128,
    )

    source_key: str = Field(
        min_length=1,
        max_length=500,
    )

    signed_key: str = Field(
        min_length=1,
        max_length=500,
    )


def required_env(
    name: str,
) -> str:
    value = os.environ.get(
        name
    )

    if not value:
        raise RuntimeError(
            f"{name} is not configured."
        )

    return value


def require_signer_auth(
    authorization: str | None,
) -> None:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Signer authentication required.",
        )

    scheme, _, token = (
        authorization.partition(" ")
    )

    if (
        scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid signer authorization.",
        )

    expected = required_env(
        "AEGIS_SIGNER_SERVICE_TOKEN"
    )

    if not hmac.compare_digest(
        token,
        expected,
    ):
        raise HTTPException(
            status_code=403,
            detail="Signer authentication failed.",
        )


def validate_object_key(
    key: str,
    *,
    notice_id: str,
    section: str,
) -> None:
    expected_prefix = (
        f"notices/"
        f"{notice_id}/"
        f"{section}/"
    )

    if not key.startswith(
        expected_prefix
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid B2 object key.",
        )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "aegis-signing-service",
    }


@app.post("/sign")
def sign(
    request: SignRequest,
    authorization: str | None = Header(
        default=None,
    ),
) -> dict:
    """Download, sign, verify metadata, and re-upload an asset."""

    require_signer_auth(
        authorization
    )

    validate_object_key(
        request.source_key,
        notice_id=request.notice_id,
        section="source",
    )

    validate_object_key(
        request.signed_key,
        notice_id=request.notice_id,
        section="published",
    )

    store = B2ObjectStore()

    with TemporaryDirectory(
        prefix="aegis-signer-"
    ) as temp_dir:

        temp_root = Path(
            temp_dir
        )

        suffix = Path(
            request.source_key
        ).suffix.lower()

        if suffix not in {
            ".png",
            ".jpg",
            ".jpeg",
            ".pdf",
        }:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Unsupported signing asset type."
                ),
            )

        source_path = (
            temp_root
            / f"source{suffix}"
        )

        signed_path = (
            temp_root
            / f"signed{suffix}"
        )

        try:
            store.download_file(
                request.source_key,
                source_path,
            )

            signing_result = (
                sign_notice_asset(
                    source_path=source_path,
                    destination_path=signed_path,
                )
            )

            signed_sha256 = (
                hashlib.sha256(
                    signed_path.read_bytes()
                ).hexdigest()
            )

            content_type = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".pdf": "application/pdf",
            }[suffix]

            store.upload_file(
                signed_path,
                request.signed_key,
                content_type=content_type,
            )

        except (
            B2StorageError,
            NoticeSigningError,
        ) as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
            ) from exc

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Signing service could not "
                    "create the signed asset."
                ),
            ) from exc

    return {
        "status": "SIGNED",
        "notice_id": request.notice_id,
        "signed_key": request.signed_key,
        "signed_asset_sha256": signed_sha256,
        "key_id": signing_result.key_id,
        "certificate_serial_number": (
            signing_result.certificate_serial_number
        ),
    }