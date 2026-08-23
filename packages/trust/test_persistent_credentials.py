"""Tests for the persistent AEGIS credential registry."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
    PersistentCredentialRegistry,
)


TEST_SERIAL = (
    "588662819360910049980569274172896276819088458057"
)


def make_record(
    *,
    status: CredentialStatus = CredentialStatus.ACTIVE,
    expires_at: datetime | None = None,
) -> CredentialRecord:
    return CredentialRecord(
        key_id="6ad2cd50a4836966",
        certificate_serial_number=TEST_SERIAL,
        subject="O=SOA University",
        common_name="Emergency Communications Issuer",
        status=status,
        issued_at=datetime(
            2026,
            8,
            1,
            tzinfo=timezone.utc,
        ),
        expires_at=expires_at,
    )


def test_register_persists_across_instances(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry_one = PersistentCredentialRegistry(
        database_path
    )

    record = make_record()

    registry_one.register(record)

    registry_two = PersistentCredentialRegistry(
        database_path
    )

    loaded = registry_two.get_by_serial(
        TEST_SERIAL
    )

    assert loaded == record


def test_duplicate_registration_is_rejected(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry = PersistentCredentialRegistry(
        database_path
    )

    registry.register(
        make_record()
    )

    with pytest.raises(ValueError):
        registry.register(
            make_record()
        )


def test_persistent_revocation_survives_restart(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry_one = PersistentCredentialRegistry(
        database_path
    )

    registry_one.register(
        make_record()
    )

    registry_one.revoke(
        TEST_SERIAL,
        reason="Private key compromise",
    )

    registry_two = PersistentCredentialRegistry(
        database_path
    )

    assert (
        registry_two.status_at(TEST_SERIAL)
        is CredentialStatus.REVOKED
    )

    record = registry_two.get_by_serial(
        TEST_SERIAL
    )

    assert record.revocation_reason == (
        "Private key compromise"
    )


def test_expired_credential_is_reported(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry = PersistentCredentialRegistry(
        database_path
    )

    registry.register(
        make_record(
            expires_at=(
                datetime.now(timezone.utc)
                - timedelta(days=1)
            )
        )
    )

    assert (
        registry.status_at(TEST_SERIAL)
        is CredentialStatus.EXPIRED
    )


def test_audit_chain_is_valid(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry = PersistentCredentialRegistry(
        database_path
    )

    registry.register(
        make_record()
    )

    registry.revoke(
        TEST_SERIAL,
        reason="Development rotation",
    )

    assert registry.verify_audit_chain()

    events = registry.audit_events()

    assert len(events) == 2
    assert events[0]["event_type"] == "REGISTERED"
    assert events[1]["event_type"] == "REVOKED"

    assert events[0]["previous_hash"] == ""
    assert events[1]["previous_hash"] == (
        events[0]["event_hash"]
    )


def test_audit_chain_detects_tampering(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry = PersistentCredentialRegistry(
        database_path
    )

    registry.register(
        make_record()
    )

    registry.revoke(
        TEST_SERIAL,
        reason="Development rotation",
    )

    assert registry.verify_audit_chain()

    import sqlite3

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            UPDATE audit_events
            SET payload_json = ?
            WHERE sequence = 2
            """,
            ('{"tampered":true}',),
        )

    reopened = PersistentCredentialRegistry(
        database_path
    )

    assert not reopened.verify_audit_chain()


def test_unknown_credential_is_rejected(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry = PersistentCredentialRegistry(
        database_path
    )

    with pytest.raises(KeyError):
        registry.status_at(
            "does-not-exist"
        )


def test_revocation_requires_reason(
    tmp_path: Path,
):
    database_path = (
        tmp_path / "credentials.sqlite3"
    )

    registry = PersistentCredentialRegistry(
        database_path
    )

    registry.register(
        make_record()
    )

    with pytest.raises(ValueError):
        registry.revoke(
            TEST_SERIAL,
            reason="",
        )