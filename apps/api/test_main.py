"""Integration tests for the AEGIS administrator API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.trust.admin_auth import (
    AdminRole,
    PersistentAdminRegistry,
)
from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
    PersistentCredentialRegistry,
)


TEST_SERIAL = "999999999999999999999999999999999999999999"
TEST_DB_NAME = "api-test-credentials.sqlite3"


@pytest.fixture()
def isolated_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Replace the API's persistent stores with temporary databases."""
    credential_db = (
        tmp_path / "credentials.sqlite3"
    )

    admin_db = (
        tmp_path / "administrators.sqlite3"
    )

    audit_path = (
        tmp_path / "admin_audit.jsonl"
    )

    monkeypatch.setattr(
        main,
        "CREDENTIAL_DATABASE_PATH",
        credential_db,
    )

    monkeypatch.setattr(
        main,
        "ADMIN_DATABASE_PATH",
        admin_db,
    )

    monkeypatch.setattr(
        main,
        "ADMIN_AUDIT_PATH",
        audit_path,
    )

    main.admin_registry = (
        PersistentAdminRegistry(
            admin_db
        )
    )

    registry = (
        PersistentCredentialRegistry(
            credential_db
        )
    )

    registry.register(
        CredentialRecord(
            key_id="api-test-key",
            certificate_serial_number=TEST_SERIAL,
            subject="O=AEGIS Test",
            common_name="AEGIS API Test Issuer",
            status=CredentialStatus.ACTIVE,
            issued_at=__import__(
                "datetime"
            ).datetime.now(
                __import__(
                    "datetime"
                ).timezone.utc
            ),
        )
    )

    return {
        "credential_db": credential_db,
        "admin_db": admin_db,
        "audit_path": audit_path,
    }


def create_admin(
    *,
    database_path: Path,
    username: str,
    role: str,
    password: str = "development-password-123",
):
    """Create one test administrator."""
    registry = (
        PersistentAdminRegistry(
            database_path
        )
    )

    return registry.register(
        administrator_id=(
            f"{role.lower()}-{username}"
        ),
        username=username,
        display_name=(
            f"AEGIS {role.title()}"
        ),
        role=role,
        password=password,
    )


def login(
    client: TestClient,
    username: str,
    password: str = "development-password-123",
) -> dict:
    """Log in through the real API."""
    response = client.post(
        "/admin/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["authenticated"] is True
    assert payload["session_token"]

    return payload


def auth_header(
    session_token: str,
) -> dict[str, str]:
    """Build an authorization header."""
    return {
        "Authorization":
            f"Bearer {session_token}",
    }


def test_unauthenticated_credential_lookup_is_401(
    isolated_api,
):
    with TestClient(
        main.app
    ) as client:
        response = client.get(
            f"/credentials/{TEST_SERIAL}"
        )

    assert response.status_code == 401
    assert (
        response.json()["detail"]
        == "Administrator session is required."
    )


def test_viewer_authorization_matrix(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="viewer",
        role=AdminRole.VIEWER,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "viewer",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        credential_response = client.get(
            f"/credentials/{TEST_SERIAL}",
            headers=headers,
        )

        audit_response = client.get(
            "/admin/audit",
            headers=headers,
        )

        revoke_response = client.post(
            f"/credentials/{TEST_SERIAL}/revoke",
            headers=headers,
            json={
                "reason": "viewer test",
            },
        )

    assert credential_response.status_code == 200

    assert audit_response.status_code == 403
    assert "audit.read" in (
        audit_response.json()["detail"]
    )

    assert revoke_response.status_code == 403
    assert "credential.revoke" in (
        revoke_response.json()["detail"]
    )


def test_auditor_authorization_matrix(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="auditor",
        role=AdminRole.AUDITOR,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "auditor",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        credential_response = client.get(
            f"/credentials/{TEST_SERIAL}",
            headers=headers,
        )

        audit_response = client.get(
            "/admin/audit",
            headers=headers,
        )

        revoke_response = client.post(
            f"/credentials/{TEST_SERIAL}/revoke",
            headers=headers,
            json={
                "reason": "auditor test",
            },
        )

    assert credential_response.status_code == 200
    assert audit_response.status_code == 200

    assert revoke_response.status_code == 403
    assert "credential.revoke" in (
        revoke_response.json()["detail"]
    )


def test_operator_can_revoke_active_credential(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="operator",
        role=AdminRole.OPERATOR,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "operator",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        credential_response = client.get(
            f"/credentials/{TEST_SERIAL}",
            headers=headers,
        )

        audit_response = client.get(
            "/admin/audit",
            headers=headers,
        )

        revoke_response = client.post(
            f"/credentials/{TEST_SERIAL}/revoke",
            headers=headers,
            json={
                "reason": "operator integration test",
            },
        )

    assert credential_response.status_code == 200
    assert audit_response.status_code == 200
    assert revoke_response.status_code == 200

    credential = (
        revoke_response.json()["credential"]
    )

    assert credential["status"] == "REVOKED"
    assert (
        credential["revocation_reason"]
        == "operator integration test"
    )

    assert (
        revoke_response.json()[
            "audit_chain_valid"
        ]
        is True
    )


def test_admin_can_read_and_revoke(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="admin",
        role=AdminRole.ADMIN,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "admin",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        credential_response = client.get(
            f"/credentials/{TEST_SERIAL}",
            headers=headers,
        )

        audit_response = client.get(
            "/admin/audit",
            headers=headers,
        )

        revoke_response = client.post(
            f"/credentials/{TEST_SERIAL}/revoke",
            headers=headers,
            json={
                "reason": "admin integration test",
            },
        )

    assert credential_response.status_code == 200
    assert audit_response.status_code == 200
    assert revoke_response.status_code == 200


def test_revoking_already_revoked_credential_is_409(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="operator",
        role=AdminRole.OPERATOR,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "operator",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        first = client.post(
            f"/credentials/{TEST_SERIAL}/revoke",
            headers=headers,
            json={
                "reason": "first revocation",
            },
        )

        second = client.post(
            f"/credentials/{TEST_SERIAL}/revoke",
            headers=headers,
            json={
                "reason": "second revocation",
            },
        )

    assert first.status_code == 200
    assert second.status_code == 409


def test_session_can_be_revoked(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="admin-session",
        role=AdminRole.ADMIN,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "admin-session",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        revoke_response = client.post(
            "/admin/session/revoke",
            headers=headers,
        )

        validate_response = client.post(
            "/admin/session/validate",
            headers=headers,
        )

    assert revoke_response.status_code == 200
    assert revoke_response.json()["revoked"] is True

    assert validate_response.status_code == 401


def test_admin_audit_contains_identity(
    isolated_api,
):
    create_admin(
        database_path=isolated_api["admin_db"],
        username="audit-admin",
        role=AdminRole.ADMIN,
    )

    with TestClient(
        main.app
    ) as client:
        login_result = login(
            client,
            "audit-admin",
        )

        headers = auth_header(
            login_result["session_token"]
        )

        response = client.get(
            "/admin/audit",
            headers=headers,
        )

    assert response.status_code == 200

    events = response.json()["events"]

    assert events

    login_events = [
        event
        for event in events
        if event["event_type"] == "LOGIN"
    ]

    assert login_events

    latest = login_events[-1]

    assert (
        latest["administrator_id"]
        == "admin-audit-admin"
    )

    assert (
        latest["username"]
        == "audit-admin"
    )

    assert (
        latest["role"]
        == AdminRole.ADMIN
    )