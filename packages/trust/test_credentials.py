"""Tests for AEGIS credential lifecycle management."""

from datetime import datetime, timedelta, timezone

import pytest

from packages.trust.credentials import (
    CredentialRecord,
    CredentialRegistry,
    CredentialStatus,
)


TEST_SERIAL = (
    "588662819360910049980569274172896276819088458057"
)


def make_record(
    key_id: str = "issuer-v4",
    serial: str = TEST_SERIAL,
    *,
    expires_at: datetime | None = None,
) -> CredentialRecord:
    return CredentialRecord(
        key_id=key_id,
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
        expires_at=expires_at,
    )


def test_register_and_get_credential():
    registry = CredentialRegistry()

    record = make_record()

    registry.register(record)

    assert registry.get_by_serial(
        record.certificate_serial_number
    ) == record


def test_duplicate_registration_is_rejected():
    registry = CredentialRegistry()

    registry.register(
        make_record()
    )

    with pytest.raises(ValueError):
        registry.register(
            make_record()
        )


def test_active_credential_reports_active():
    registry = CredentialRegistry()

    registry.register(
        make_record()
    )

    assert (
        registry.status_at(TEST_SERIAL)
        is CredentialStatus.ACTIVE
    )


def test_revocation_changes_status():
    registry = CredentialRegistry()

    registry.register(
        make_record()
    )

    revoked = registry.revoke(
        TEST_SERIAL,
        reason="Private key compromise",
    )

    assert (
        revoked.status
        is CredentialStatus.REVOKED
    )

    assert (
        registry.status_at(TEST_SERIAL)
        is CredentialStatus.REVOKED
    )

    assert revoked.revocation_reason == (
        "Private key compromise"
    )


def test_expired_credential_reports_expired():
    registry = CredentialRegistry()

    now = datetime.now(timezone.utc)

    registry.register(
        make_record(
            expires_at=now - timedelta(days=1)
        )
    )

    assert (
        registry.status_at(TEST_SERIAL)
        is CredentialStatus.EXPIRED
    )


def test_revocation_takes_precedence_over_expiration():
    registry = CredentialRegistry()

    now = datetime.now(timezone.utc)

    registry.register(
        make_record(
            expires_at=now - timedelta(days=1)
        )
    )

    registry.revoke(
        TEST_SERIAL,
        reason="Credential compromised",
    )

    assert (
        registry.status_at(TEST_SERIAL)
        is CredentialStatus.REVOKED
    )


def test_unknown_credential_is_rejected():
    registry = CredentialRegistry()

    with pytest.raises(KeyError):
        registry.status_at(
            "does-not-exist"
        )


def test_revocation_requires_reason():
    registry = CredentialRegistry()

    registry.register(
        make_record()
    )

    with pytest.raises(ValueError):
        registry.revoke(
            TEST_SERIAL,
            reason="",
        )