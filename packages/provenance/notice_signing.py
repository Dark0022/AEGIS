"""AEGIS C2PA signing support for official communications."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

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


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]


class NoticeSigningError(Exception):
    """Raised when an official notice cannot be signed."""


@dataclass(frozen=True)
class NoticeSigningResult:
    """Result of a successful C2PA signing operation."""

    key_id: str
    certificate_serial_number: str


def _private_pki_root() -> Path:
    """Resolve the private AEGIS PKI root."""

    configured = os.environ.get(
        "AEGIS_PRIVATE_PKI_ROOT"
    )

    if configured:
        return (
            Path(configured)
            .expanduser()
            .resolve()
        )

    return (
        PROJECT_ROOT.parent
        / "AEGIS-SECRETS"
        / "pki"
    )


def _issuer_key_path() -> Path:
    configured = os.environ.get(
        "AEGIS_ISSUER_KEY_PATH"
    )

    if configured:
        return (
            Path(configured)
            .expanduser()
            .resolve()
        )

    return (
        _private_pki_root()
        / "issuers"
        / "emergency-communications-v8"
        / "issuer-key.json"
    )


def _issuer_certificate_path() -> Path:
    configured = os.environ.get(
        "AEGIS_ISSUER_CERT_PATH"
    )

    if configured:
        return (
            Path(configured)
            .expanduser()
            .resolve()
        )

    return (
        PROJECT_ROOT
        / "pki"
        / "issuers"
        / "emergency-communications-v8"
        / "issuer-cert.pem"
    )


def _institution_certificate_path() -> Path:
    configured = os.environ.get(
        "AEGIS_INSTITUTION_CERT_PATH"
    )

    if configured:
        return (
            Path(configured)
            .expanduser()
            .resolve()
        )

    return (
        PROJECT_ROOT
        / "pki"
        / "institutions"
        / "soa-university"
        / "ca-cert.pem"
    )


def _issuer_password() -> str:
    password = os.environ.get(
        "AEGIS_ISSUER_KEY_PASSWORD"
    )

    if not password:
        raise NoticeSigningError(
            "AEGIS_ISSUER_KEY_PASSWORD is not configured."
        )

    return password


def _certificate_serial_number(
    certificate_path: Path,
) -> str:
    """Read the decimal certificate serial number."""

    try:
        certificate = (
            x509.load_pem_x509_certificate(
                certificate_path.read_bytes()
            )
        )

    except OSError as exc:
        raise NoticeSigningError(
            f"Unable to read issuer certificate: "
            f"{certificate_path}"
        ) from exc

    except ValueError as exc:
        raise NoticeSigningError(
            f"Invalid issuer certificate: "
            f"{certificate_path}"
        ) from exc

    return str(
        certificate.serial_number
    )


def sign_notice_asset(
    *,
    source_path: str | Path,
    destination_path: str | Path,
) -> NoticeSigningResult:
    """
    Sign an official communication using the configured AEGIS issuer.

    The private key stays inside the AEGIS PKI signer abstraction.
    """

    source = Path(
        source_path
    ).resolve()

    destination = Path(
        destination_path
    ).resolve()

    issuer_key_path = (
        _issuer_key_path()
    )

    issuer_certificate_path = (
        _issuer_certificate_path()
    )

    institution_certificate_path = (
        _institution_certificate_path()
    )

    required = (
        source,
        issuer_key_path,
        issuer_certificate_path,
        institution_certificate_path,
    )

    missing = [
        path
        for path in required
        if not path.is_file()
    ]

    if missing:
        message = (
            "Missing required signing artifact(s):"
            "\n"
            + "\n".join(
                f"  {path}"
                for path in missing
            )
        )

        raise NoticeSigningError(
            message
        )

    if destination.exists():
        raise NoticeSigningError(
            f"Destination already exists: "
            f"{destination}"
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        signer = PKISigner.load(
            issuer_key_path,
            _issuer_password(),
        )

        c2pa_signer = AEGISC2PASigner(
            signer,
            issuer_certificate_path=(
                issuer_certificate_path
            ),
            institution_certificate_path=(
                institution_certificate_path
            ),
        )

        asset_format = detect_asset_format(
            source
        )

        builder = create_manifest(
            claim_generator="AEGIS/0.1",
            asset_format=asset_format,
        )

        add_created_action(
            builder
        )

        sign_asset(
            builder,
            source_path=source,
            destination_path=destination,
            signer=c2pa_signer,
        )

    except NoticeSigningError:
        raise

    except Exception as exc:
        raise NoticeSigningError(
            "Unable to create the C2PA-signed "
            "official communication."
        ) from exc

    return NoticeSigningResult(
        key_id=signer.key_id(),
        certificate_serial_number=(
            _certificate_serial_number(
                issuer_certificate_path
            )
        ),
    )