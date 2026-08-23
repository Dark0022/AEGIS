"""End-to-end FastAPI tests using PostgreSQL storage."""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

from apps.api import main

from packages.trust.admin_auth import (
    AdminRole,
)

from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
)

from packages.trust.storage import (
    PostgreSQLCredentialStore,
)


DATABASE_URL = os.environ.get(
    "AEGIS_DATABASE_URL"
)


pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason=(
        "AEGIS_DATABASE_URL is required "
        "for PostgreSQL API integration tests."
    ),
)


PASSWORD = (
    "PostgreSQL-API-Test-Password-123!"
)


def _unique_value(
    prefix: str,
) -> str:
    return (
        f"{prefix}-"
        f"{uuid.uuid4().hex}"
    )


def _register_admin(
    *,
    username: str,
    role: str,
) -> None:
    from packages.trust.storage import (
        PostgreSQLAdminStore,
    )

    registry = PostgreSQLAdminStore(
        DATABASE_URL
    )
    registry.register(
        administrator_id=_unique_value(
            "api-admin"
        ),
        username=username,
        display_name=f"PostgreSQL {role}",
        role=role,
        password=PASSWORD,
    )


def _login(
    client: TestClient,
    username: str,
) -> str:
    response = client.post(
        "/admin/login",
        json={
            "username": username,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["authenticated"] is True
    assert payload["role"]

    return payload["session_token"]


def _authorization(
    token: str,
) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def _make_credential(
    serial: str,
) -> CredentialRecord:
    from datetime import (
        datetime,
        timedelta,
        timezone,
    )

    now = datetime.now(
        timezone.utc
    )

    return CredentialRecord(
        key_id=_unique_value(
            "postgres-api-key"
        ),
        certificate_serial_number=serial,
        subject=(
            "CN=PostgreSQL API Test Issuer,"
            "OU=Development,"
            "O=AEGIS"
        ),
        common_name=(
            "PostgreSQL API Test Issuer"
        ),
        status=CredentialStatus.ACTIVE,
        issued_at=now,
        expires_at=(
            now
            + timedelta(
                days=30
            )
        ),
    )


def test_postgres_api_login_and_session_validation():
    """Login and session validation work through the real API."""

    username = _unique_value(
        "api-viewer"
    )

    _register_admin(
        username=username,
        role=AdminRole.VIEWER,
    )

    with TestClient(
        main.app
    ) as client:
        token = _login(
            client,
            username,
        )

        response = client.post(
            "/admin/session/validate",
            headers=_authorization(
                token
            ),
        )

    assert response.status_code == 200

    payload = response.json()

    assert payload["authenticated"] is True
    assert payload["username"] == username
    assert payload["role"] == AdminRole.VIEWER


def test_postgres_api_credential_lookup():
    """Credential lookup works through PostgreSQL-backed API storage."""

    username = _unique_value(
        "api-auditor"
    )

    serial = _unique_value(
        "api-credential"
    )

    _register_admin(
        username=username,
        role=AdminRole.AUDITOR,
    )

    store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    store.register(
        _make_credential(
            serial
        )
    )

    with TestClient(
        main.app
    ) as client:
        token = _login(
            client,
            username,
        )

        response = client.get(
            f"/credentials/{serial}",
            headers=_authorization(
                token
            ),
        )

    assert response.status_code == 200

    credential = (
        response.json()["credential"]
    )

    assert (
        credential[
            "certificate_serial_number"
        ]
        == serial
    )

    assert (
        credential["status"]
        == "ACTIVE"
    )


def test_postgres_api_operator_revoke_and_history():
    """Operator revocation and credential history work through the API."""

    username = _unique_value(
        "api-operator"
    )

    serial = _unique_value(
        "api-revoke"
    )

    _register_admin(
        username=username,
        role=AdminRole.OPERATOR,
    )

    store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    store.register(
        _make_credential(
            serial
        )
    )

    with TestClient(
        main.app
    ) as client:
        token = _login(
            client,
            username,
        )

        revoke_response = client.post(
            f"/credentials/{serial}/revoke",
            headers=_authorization(
                token
            ),
            json={
                "reason": (
                    "PostgreSQL API lifecycle test"
                )
            },
        )

        assert (
            revoke_response.status_code
            == 200
        )

        credential = (
            revoke_response.json()[
                "credential"
            ]
        )

        assert (
            credential["status"]
            == "REVOKED"
        )

        history_response = client.get(
            f"/credentials/{serial}/history",
            headers=_authorization(
                token
            ),
        )

    assert (
        history_response.status_code
        == 200
    )

    history = (
        history_response.json()
    )

    assert (
        history["audit_chain_valid"]
        is True
    )

    assert (
        len(history["events"])
        >= 2
    )


def test_postgres_api_viewer_cannot_revoke():
    """VIEWER cannot revoke through PostgreSQL-backed API."""

    username = _unique_value(
        "api-viewer-revoke"
    )

    serial = _unique_value(
        "api-viewer-credential"
    )

    _register_admin(
        username=username,
        role=AdminRole.VIEWER,
    )

    store = PostgreSQLCredentialStore(
        DATABASE_URL
    )

    store.register(
        _make_credential(
            serial
        )
    )

    with TestClient(
        main.app
    ) as client:
        token = _login(
            client,
            username,
        )

        response = client.post(
            f"/credentials/{serial}/revoke",
            headers=_authorization(
                token
            ),
            json={
                "reason": (
                    "Viewer authorization test"
                )
            },
        )

    assert response.status_code == 403

    assert (
        "does not permit credential.revoke"
        in response.json()["detail"]
    )


def test_postgres_api_admin_audit():
    """Administrator audit events are persisted through the API."""

    username = _unique_value(
        "api-admin-audit"
    )

    _register_admin(
        username=username,
        role=AdminRole.ADMIN,
    )

    with TestClient(
        main.app
    ) as client:
        token = _login(
            client,
            username,
        )

        response = client.get(
            "/admin/audit",
            headers=_authorization(
                token
            ),
        )

    assert response.status_code == 200

    payload = response.json()

    assert (
        payload["audit_chain_valid"]
        is True
    )

    events = payload["events"]

    matching = [
        event
        for event in events
        if event.get(
            "username"
        )
        == username
    ]

    assert matching

    assert any(
        event["event_type"]
        == "LOGIN"
        for event in matching
    )