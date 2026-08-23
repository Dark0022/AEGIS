"""Integration tests for the AEGIS PostgreSQL storage backend."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from packages.trust.admin_auth import (
    AdminAuthenticationError,
    AdminRole,
)
from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
)
from packages.trust.storage import (
    PostgreSQLAdminStore,
    PostgreSQLCredentialStore,
)


DATABASE_URL = os.environ.get(
    "AEGIS_DATABASE_URL"
)


pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason=(
        "AEGIS_DATABASE_URL is required "
        "for PostgreSQL integration tests."
    ),
)


def _unique_value(
    prefix: str,
) -> str:
    import uuid

    return (
        f"{prefix}-"
        f"{uuid.uuid4().hex}"
    )


def _make_credential(
    serial: str,
) -> CredentialRecord:
    now = datetime.now(
        timezone.utc
    )

    return CredentialRecord(
        key_id=_unique_value(
            "postgres-key"
        ),
        certificate_serial_number=serial,
        subject=(
            "CN=PostgreSQL Test Issuer,"
            "OU=Development,"
            "O=AEGIS"
        ),
        common_name=(
            "PostgreSQL Test Issuer"
        ),
        status=CredentialStatus.ACTIVE,
        issued_at=now,
        expires_at=(
            now + timedelta(days=30)
        ),
    )


def test_postgres_credential_registration_persists():
    """Credential registration survives a new store instance."""

    serial = _unique_value(
        "credential"
    )

    first_store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    record = _make_credential(
        serial
    )

    first_store.register(
        record
    )

    second_store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    loaded = second_store.get_by_serial(
        serial
    )

    assert (
        loaded.certificate_serial_number
        == serial
    )

    assert (
        loaded.common_name
        == "PostgreSQL Test Issuer"
    )

    assert (
        loaded.status
        is CredentialStatus.ACTIVE
    )


def test_postgres_revocation_persists():
    """Credential revocation survives a new store instance."""

    serial = _unique_value(
        "revocation"
    )

    first_store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    first_store.register(
        _make_credential(
            serial
        )
    )

    revoked = first_store.revoke(
        serial,
        reason="PostgreSQL lifecycle test",
    )

    assert (
        revoked.status
        is CredentialStatus.REVOKED
    )

    second_store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    loaded = second_store.get_by_serial(
        serial
    )

    assert (
        loaded.status
        is CredentialStatus.REVOKED
    )

    assert (
        loaded.revocation_reason
        == "PostgreSQL lifecycle test"
    )


def test_postgres_revocation_survives_restart():
    """Effective credential status remains revoked after reloading."""

    serial = _unique_value(
        "restart"
    )

    store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    store.register(
        _make_credential(
            serial
        )
    )

    store.revoke(
        serial,
        reason="Restart persistence test",
    )

    reloaded = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    status = reloaded.status_at(
        serial
    )

    assert (
        status
        is CredentialStatus.REVOKED
    )


def test_postgres_audit_chain_is_valid():
    """PostgreSQL credential audit history has a valid hash chain."""

    serial = _unique_value(
        "audit"
    )

    store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    store.register(
        _make_credential(
            serial
        )
    )

    store.revoke(
        serial,
        reason="Audit chain test",
    )

    assert (
        store.verify_audit_chain()
        is True
    )

    events = (
        store.audit_events()
    )

    matching = [
        event
        for event in events
        if (
            event[
                "certificate_serial_number"
            ]
            == serial
        )
    ]

    assert len(
        matching
    ) == 2

    assert (
        matching[0]["event_type"]
        == "REGISTERED"
    )

    assert (
        matching[1]["event_type"]
        == "REVOKED"
    )


def test_postgres_admin_registration_and_authentication():
    """Administrator registration and password authentication work in Postgres."""

    username = _unique_value(
        "admin"
    )

    store = PostgreSQLAdminStore(
        DATABASE_URL
    )

    administrator = store.register(
        administrator_id=_unique_value(
            "postgres-admin"
        ),
        username=username,
        display_name="PostgreSQL Test Administrator",
        role=AdminRole.ADMIN,
        password="PostgreSQL-Test-Password-123!",
    )

    assert (
        administrator.username
        == username
    )

    authenticated = store.authenticate(
        username=username,
        password="PostgreSQL-Test-Password-123!",
    )

    assert (
        authenticated.username
        == username
    )


def test_postgres_wrong_admin_password_is_rejected():
    """Wrong administrator passwords are rejected."""

    username = _unique_value(
        "wrong-password"
    )

    store = PostgreSQLAdminStore(
        DATABASE_URL
    )

    store.register(
        administrator_id=_unique_value(
            "postgres-admin"
        ),
        username=username,
        display_name="Password Test Administrator",
        role=AdminRole.OPERATOR,
        password="Correct-Postgres-Password-123!",
    )

    with pytest.raises(
        AdminAuthenticationError
    ):
        store.authenticate(
            username=username,
            password="Wrong-Password-123!",
        )


def test_postgres_admin_session_persists_between_store_instances():
    """Administrator sessions can be resolved by another store instance."""

    username = _unique_value(
        "session"
    )

    first_store = PostgreSQLAdminStore(
        DATABASE_URL
    )

    administrator = first_store.register(
        administrator_id=_unique_value(
            "session-admin"
        ),
        username=username,
        display_name="PostgreSQL Session Administrator",
        role=AdminRole.ADMIN,
        password="Session-Postgres-Password-123!",
    )

    token, session = (
        first_store.create_session(
            administrator
        )
    )

    assert session.username == username

    second_store = PostgreSQLAdminStore(
        DATABASE_URL
    )

    resolved = (
        second_store.resolve_session(
            token
        )
    )

    assert (
        resolved.administrator_id
        == administrator.administrator_id
    )

    assert (
        resolved.username
        == username
    )

    assert (
        resolved.role
        == AdminRole.ADMIN
    )


def test_postgres_admin_session_can_be_revoked():
    """PostgreSQL administrator sessions can be revoked."""

    username = _unique_value(
        "revocation-session"
    )

    store = PostgreSQLAdminStore(
        DATABASE_URL
    )

    administrator = store.register(
        administrator_id=_unique_value(
            "session-admin"
        ),
        username=username,
        display_name="Session Revocation Administrator",
        role=AdminRole.ADMIN,
        password="Session-Revoke-Password-123!",
    )

    token, _ = (
        store.create_session(
            administrator
        )
    )

    assert (
        store.revoke_session(
            token
        )
        is True
    )

    with pytest.raises(
        AdminAuthenticationError
    ):
        store.resolve_session(
            token
        )


def test_postgres_role_permissions_are_enforced():
    """PostgreSQL-backed administrator sessions preserve RBAC."""

    username = _unique_value(
        "viewer"
    )

    store = PostgreSQLAdminStore(
        DATABASE_URL
    )

    administrator = store.register(
        administrator_id=_unique_value(
            "viewer-admin"
        ),
        username=username,
        display_name="PostgreSQL Viewer",
        role=AdminRole.VIEWER,
        password="Viewer-Postgres-Password-123!",
    )

    token, session = (
        store.create_session(
            administrator
        )
    )

    resolved = (
        store.resolve_session(
            token
        )
    )

    assert (
        resolved.role
        == AdminRole.VIEWER
    )

    store.assert_permission(
        resolved,
        "credential.read",
    )

    with pytest.raises(
        Exception
    ):
        store.assert_permission(
            resolved,
            "credential.revoke",
        )