"""Tests for AEGIS administrator authentication and authorization."""

from pathlib import Path

import pytest

from packages.trust.admin_auth import (
    AdminAuthenticationError,
    AdminAuthorizationError,
    AdminRole,
    PersistentAdminRegistry,
    ROLE_PERMISSIONS,
)


def register_admin(
    registry: PersistentAdminRegistry,
    *,
    administrator_id: str,
    username: str,
    role: str,
):
    return registry.register(
        administrator_id=administrator_id,
        username=username,
        display_name=f"AEGIS {role.title()}",
        role=role,
        password="development-password-123",
    )


def test_register_and_authenticate_admin(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="admin-001",
        username="operator",
        role=AdminRole.ADMIN,
    )

    authenticated = registry.authenticate(
        username="operator",
        password="development-password-123",
    )

    assert record.username == "operator"
    assert record.role == AdminRole.ADMIN

    assert (
        authenticated.administrator_id
        == "admin-001"
    )


def test_wrong_password_is_rejected(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    register_admin(
        registry,
        administrator_id="admin-001",
        username="operator",
        role=AdminRole.ADMIN,
    )

    with pytest.raises(
        AdminAuthenticationError
    ):
        registry.authenticate(
            username="operator",
            password="wrong-password-456",
        )


def test_viewer_permissions(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="viewer-001",
        username="viewer",
        role=AdminRole.VIEWER,
    )

    _, session = registry.create_session(
        record
    )

    registry.assert_permission(
        session,
        "credential.read",
    )

    with pytest.raises(
        AdminAuthorizationError
    ):
        registry.assert_permission(
            session,
            "audit.read",
        )

    with pytest.raises(
        AdminAuthorizationError
    ):
        registry.assert_permission(
            session,
            "credential.revoke",
        )


def test_auditor_permissions(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="auditor-001",
        username="auditor",
        role=AdminRole.AUDITOR,
    )

    _, session = registry.create_session(
        record
    )

    registry.assert_permission(
        session,
        "credential.read",
    )

    registry.assert_permission(
        session,
        "audit.read",
    )

    with pytest.raises(
        AdminAuthorizationError
    ):
        registry.assert_permission(
            session,
            "credential.revoke",
        )


def test_operator_permissions(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="operator-001",
        username="operator",
        role=AdminRole.OPERATOR,
    )

    _, session = registry.create_session(
        record
    )

    registry.assert_permission(
        session,
        "credential.read",
    )

    registry.assert_permission(
        session,
        "audit.read",
    )

    registry.assert_permission(
        session,
        "credential.revoke",
    )


def test_admin_permissions(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="admin-001",
        username="admin",
        role=AdminRole.ADMIN,
    )

    _, session = registry.create_session(
        record
    )

    for permission in (
        "credential.read",
        "audit.read",
        "credential.revoke",
        "admin.manage",
    ):
        registry.assert_permission(
            session,
            permission,
        )


def test_session_can_be_resolved(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="admin-001",
        username="operator",
        role=AdminRole.OPERATOR,
    )

    token, session = registry.create_session(
        record
    )

    resolved = registry.resolve_session(
        token
    )

    assert (
        resolved.administrator_id
        == session.administrator_id
    )

    assert (
        resolved.username
        == session.username
    )

    assert (
        resolved.display_name
        == session.display_name
    )

    assert (
        resolved.role
        == AdminRole.OPERATOR
    )


def test_session_can_be_revoked(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    record = register_admin(
        registry,
        administrator_id="admin-001",
        username="operator",
        role=AdminRole.OPERATOR,
    )

    token, _ = registry.create_session(
        record
    )

    assert registry.resolve_session(
        token
    )

    assert registry.revoke_session(
        token
    )

    with pytest.raises(
        AdminAuthenticationError
    ):
        registry.resolve_session(
            token
        )


def test_duplicate_username_is_rejected(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    register_admin(
        registry,
        administrator_id="admin-001",
        username="operator",
        role=AdminRole.OPERATOR,
    )

    with pytest.raises(
        ValueError
    ):
        register_admin(
            registry,
            administrator_id="admin-002",
            username="operator",
            role=AdminRole.ADMIN,
        )


def test_duplicate_administrator_id_is_rejected(
    tmp_path: Path,
):
    registry = PersistentAdminRegistry(
        tmp_path / "admins.sqlite3"
    )

    register_admin(
        registry,
        administrator_id="admin-001",
        username="operator",
        role=AdminRole.OPERATOR,
    )

    with pytest.raises(
        ValueError
    ):
        register_admin(
            registry,
            administrator_id="admin-001",
            username="another",
            role=AdminRole.ADMIN,
        )


def test_role_permission_matrix_is_explicit():
    assert ROLE_PERMISSIONS[
        AdminRole.VIEWER
    ] == frozenset(
        {
            "credential.read",
        }
    )

    assert ROLE_PERMISSIONS[
        AdminRole.AUDITOR
    ] == frozenset(
        {
            "credential.read",
            "audit.read",
        }
    )

    assert ROLE_PERMISSIONS[
        AdminRole.OPERATOR
    ] == frozenset(
        {
            "credential.read",
            "audit.read",
            "credential.revoke",
        }
    )

    assert ROLE_PERMISSIONS[
        AdminRole.ADMIN
    ] == frozenset(
        {
            "credential.read",
            "audit.read",
            "credential.revoke",
            "admin.manage",
        }
    )