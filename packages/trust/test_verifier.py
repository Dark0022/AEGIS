"""End-to-end tests for the AEGIS verifier."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from packages.provenance.c2pa_verify import (
    create_aegis_context,
    get_signature_info,
    read_manifest,
)
from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
    PersistentCredentialRegistry,
)
from packages.trust.models import AEGISStatus
from packages.trust.verifier import verify_asset


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


def _require_assets() -> None:
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
            "Required AEGIS verification assets are missing: "
            f"{missing}"
        )


def _load_signed_asset_serial() -> str:
    """Extract the real certificate serial from the signed asset."""
    context = create_aegis_context(
        ROOT_CERT_PATH
    )

    reader = read_manifest(
        TRUSTED_ASSET_PATH,
        context=context,
    )

    return get_signature_info(
        reader
    )["cert_serial_number"]


def _register_active_issuer(
    registry: PersistentCredentialRegistry,
    serial: str,
) -> None:
    """Register the active AEGIS Issuer v4."""
    record = CredentialRecord(
        key_id="6ad2cd50a4836966",
        certificate_serial_number=serial,
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

    registry.register(record)


def test_real_signed_asset_is_trusted_with_persistent_registry(
    tmp_path: Path,
):
    _require_assets()

    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    serial = _load_signed_asset_serial()

    registry = PersistentCredentialRegistry(
        database_path
    )

    _register_active_issuer(
        registry,
        serial,
    )

    result = verify_asset(
        TRUSTED_ASSET_PATH,
        root_certificate_path=ROOT_CERT_PATH,
        credential_registry=registry,
    )

    assert result.status is AEGISStatus.TRUSTED
    assert result.is_trusted
    assert result.issuer_trusted
    assert result.signature_valid
    assert result.content_integrity is True
    assert result.credential_active is True


def test_revocation_persists_and_changes_real_asset_result(
    tmp_path: Path,
):
    _require_assets()

    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    serial = _load_signed_asset_serial()

    registry = PersistentCredentialRegistry(
        database_path
    )

    _register_active_issuer(
        registry,
        serial,
    )

    trusted_result = verify_asset(
        TRUSTED_ASSET_PATH,
        root_certificate_path=ROOT_CERT_PATH,
        credential_registry=registry,
    )

    assert (
        trusted_result.status
        is AEGISStatus.TRUSTED
    )

    registry.revoke(
        serial,
        reason="Development key compromise",
    )

    # Simulate an application restart by creating a completely new
    # registry object against the same SQLite database.
    restarted_registry = PersistentCredentialRegistry(
        database_path
    )

    revoked_result = verify_asset(
        TRUSTED_ASSET_PATH,
        root_certificate_path=ROOT_CERT_PATH,
        credential_registry=restarted_registry,
    )

    assert (
        revoked_result.status
        is AEGISStatus.REVOKED_CREDENTIAL
    )

    assert revoked_result.issuer_trusted
    assert revoked_result.signature_valid
    assert revoked_result.content_integrity is True
    assert revoked_result.credential_active is False
    assert not revoked_result.is_trusted


def test_tampered_asset_still_fails_with_persistent_registry(
    tmp_path: Path,
):
    _require_assets()

    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    serial = _load_signed_asset_serial()

    registry = PersistentCredentialRegistry(
        database_path
    )

    _register_active_issuer(
        registry,
        serial,
    )

    result = verify_asset(
        TAMPERED_ASSET_PATH,
        root_certificate_path=ROOT_CERT_PATH,
        credential_registry=registry,
    )

    assert (
        result.status
        is AEGISStatus.INTEGRITY_FAILURE
    )

    assert result.issuer_trusted
    assert result.signature_valid
    assert result.content_integrity is False
    assert result.credential_active is True
    assert not result.is_trusted


def test_registry_audit_history_records_revocation(
    tmp_path: Path,
):
    _require_assets()

    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    serial = _load_signed_asset_serial()

    registry = PersistentCredentialRegistry(
        database_path
    )

    _register_active_issuer(
        registry,
        serial,
    )

    registry.revoke(
        serial,
        reason="Development key compromise",
    )

    events = registry.audit_events()

    assert len(events) == 2
    assert events[0]["event_type"] == "REGISTERED"
    assert events[1]["event_type"] == "REVOKED"

    assert (
        events[1]["certificate_serial_number"]
        == serial
    )

    assert registry.verify_audit_chain()