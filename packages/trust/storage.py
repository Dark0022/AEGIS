"""AEGIS storage abstraction layer.

SQLite remains the local/test backend.

PostgreSQL is the production backend and stores:
    - credentials
    - credential audit events
    - administrators
    - administrator sessions
    - administrator audit events

Important:
    PostgreSQL migrations are NOT run when a store is instantiated.

Migrations are explicit and are handled by:
    packages.trust.migrations.PostgreSQLMigrationManager

Normal PostgreSQL operations use the shared pooled runtime from:
    packages.trust.postgres_runtime
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Protocol

from packages.trust.admin_auth import (
    AdminAuthenticationError,
    AdminAuthorizationError,
    AdminRecord,
    AdminSession,
    ROLE_PERMISSIONS,
)
from packages.trust.credentials import (
    CredentialRecord,
    CredentialStatus,
    PersistentCredentialRegistry,
)

try:
    import psycopg
except ImportError:  # pragma: no cover
    psycopg = None


# ============================================================================
# Public protocols
# ============================================================================


class CredentialStore(Protocol):
    """Persistent credential storage contract."""

    def register(
        self,
        record: CredentialRecord,
    ) -> None:
        ...

    def get_by_serial(
        self,
        certificate_serial_number: str,
    ) -> CredentialRecord:
        ...

    def revoke(
        self,
        certificate_serial_number: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> CredentialRecord:
        ...

    def status_at(
        self,
        certificate_serial_number: str,
        *,
        at: datetime | None = None,
    ) -> CredentialStatus:
        ...

    def audit_events(
        self,
    ) -> list[dict[str, object]]:
        ...

    def verify_audit_chain(
        self,
    ) -> bool:
        ...


class AdminStore(Protocol):
    """Persistent administrator/session storage contract."""

    def register(
        self,
        *,
        administrator_id: str,
        username: str,
        display_name: str,
        role: str,
        password: str,
    ) -> AdminRecord:
        ...

    def get_by_username(
        self,
        username: str,
    ) -> AdminRecord:
        ...

    def authenticate(
        self,
        *,
        username: str,
        password: str,
    ) -> AdminRecord:
        ...

    def create_session(
        self,
        administrator: AdminRecord,
    ) -> tuple[str, AdminSession]:
        ...

    def resolve_session(
        self,
        token: str,
    ) -> AdminSession:
        ...

    def revoke_session(
        self,
        token: str,
    ) -> bool:
        ...

    def assert_permission(
        self,
        session: AdminSession,
        permission: str,
    ) -> None:
        ...


class AdminAuditStore(Protocol):
    """Persistent administrator audit storage contract."""

    def append_event(
        self,
        *,
        event_type: str,
        administrator_id: str,
        username: str,
        identity: str,
        role: str,
        certificate_serial_number: str | None,
        reason: str | None,
        event_time: datetime | None = None,
    ) -> dict[str, object]:
        ...

    def events(
        self,
    ) -> list[dict[str, object]]:
        ...

    def verify_chain(
        self,
    ) -> bool:
        ...


# ============================================================================
# SQLite implementations
# ============================================================================


class SQLiteCredentialStore:
    """CredentialStore backed by SQLite."""

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self._registry = PersistentCredentialRegistry(
            database_path
        )

    def register(
        self,
        record: CredentialRecord,
    ) -> None:
        self._registry.register(
            record
        )

    def get_by_serial(
        self,
        certificate_serial_number: str,
    ) -> CredentialRecord:
        return self._registry.get_by_serial(
            certificate_serial_number
        )

    def revoke(
        self,
        certificate_serial_number: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> CredentialRecord:
        return self._registry.revoke(
            certificate_serial_number,
            reason=reason,
            revoked_at=revoked_at,
        )

    def status_at(
        self,
        certificate_serial_number: str,
        *,
        at: datetime | None = None,
    ) -> CredentialStatus:
        return self._registry.status_at(
            certificate_serial_number,
            at=at,
        )

    def audit_events(
        self,
    ) -> list[dict[str, object]]:
        return self._registry.audit_events()

    def verify_audit_chain(
        self,
    ) -> bool:
        return self._registry.verify_audit_chain()


class SQLiteAdminStore:
    """Administrator store backed by SQLite."""

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        from packages.trust.admin_auth import (
            PersistentAdminRegistry,
        )

        self._registry = PersistentAdminRegistry(
            database_path
        )

    def register(
        self,
        *,
        administrator_id: str,
        username: str,
        display_name: str,
        role: str,
        password: str,
    ) -> AdminRecord:
        return self._registry.register(
            administrator_id=administrator_id,
            username=username,
            display_name=display_name,
            role=role,
            password=password,
        )

    def get_by_username(
        self,
        username: str,
    ) -> AdminRecord:
        return self._registry.get_by_username(
            username
        )

    def authenticate(
        self,
        *,
        username: str,
        password: str,
    ) -> AdminRecord:
        return self._registry.authenticate(
            username=username,
            password=password,
        )

    def create_session(
        self,
        administrator: AdminRecord,
    ) -> tuple[str, AdminSession]:
        return self._registry.create_session(
            administrator
        )

    def resolve_session(
        self,
        token: str,
    ) -> AdminSession:
        return self._registry.resolve_session(
            token
        )

    def revoke_session(
        self,
        token: str,
    ) -> bool:
        return self._registry.revoke_session(
            token
        )

    def assert_permission(
        self,
        session: AdminSession,
        permission: str,
    ) -> None:
        self._registry.assert_permission(
            session,
            permission,
        )


class SQLiteAdminAuditStore:
    """Administrator audit chain backed by JSONL."""

    def __init__(
        self,
        audit_path: str | Path,
    ) -> None:
        self._audit_path = Path(
            audit_path
        )

        self._audit_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._lock = Lock()

    def append_event(
        self,
        *,
        event_type: str,
        administrator_id: str,
        username: str,
        identity: str,
        role: str,
        certificate_serial_number: str | None,
        reason: str | None,
        event_time: datetime | None = None,
    ) -> dict[str, object]:
        timestamp = _ensure_aware_datetime(
            event_time
            or datetime.now(
                timezone.utc
            )
        )

        with self._lock:
            events = self.events()

            previous_hash = (
                str(
                    events[-1]["event_hash"]
                )
                if events
                else ""
            )

            event = {
                "sequence": len(events) + 1,
                "event_type": event_type,
                "event_time": timestamp.isoformat(),
                "administrator_id": administrator_id,
                "username": username,
                "identity": identity,
                "role": role,
                "certificate_serial_number": (
                    certificate_serial_number
                ),
                "reason": reason,
                "previous_hash": previous_hash,
            }

            event["event_hash"] = (
                _calculate_audit_hash(
                    event
                )
            )

            with self._audit_path.open(
                "a",
                encoding="utf-8",
            ) as destination:
                destination.write(
                    json.dumps(
                        event,
                        sort_keys=True,
                    )
                    + "\n"
                )

            return event

    def events(
        self,
    ) -> list[dict[str, object]]:
        if not self._audit_path.is_file():
            return []

        events: list[
            dict[str, object]
        ] = []

        try:
            with self._audit_path.open(
                "r",
                encoding="utf-8",
            ) as source:
                for line in source:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        events.append(
                            json.loads(
                                line
                            )
                        )
                    except json.JSONDecodeError:
                        continue

        except OSError:
            return []

        return events

    def verify_chain(
        self,
    ) -> bool:
        events = self.events()

        previous_hash = ""

        for expected_sequence, event in enumerate(
            events,
            start=1,
        ):
            if event.get(
                "sequence"
            ) != expected_sequence:
                return False

            if event.get(
                "previous_hash"
            ) != previous_hash:
                return False

            supplied_hash = event.get(
                "event_hash"
            )

            if not isinstance(
                supplied_hash,
                str,
            ):
                return False

            comparable = dict(event)

            comparable.pop(
                "event_hash",
                None,
            )

            expected_hash = (
                _calculate_audit_hash(
                    comparable
                )
            )

            if not hmac.compare_digest(
                expected_hash,
                supplied_hash,
            ):
                return False

            previous_hash = supplied_hash

        return True


# ============================================================================
# PostgreSQL
# ============================================================================


class PostgreSQLUnavailableError(
    RuntimeError
):
    """Raised when PostgreSQL support is unavailable."""


class PostgreSQLBase:
    """Shared PostgreSQL runtime support.

    This class intentionally DOES NOT run migrations.

    Migrations are explicit and should be run separately using
    PostgreSQLMigrationManager.
    """

    _migration_lock = Lock()

    def __init__(
        self,
        database_url: str,
    ) -> None:
        if psycopg is None:
            raise PostgreSQLUnavailableError(
                "PostgreSQL support requires "
                "'psycopg[binary,pool]'."
            )

        if not database_url.strip():
            raise ValueError(
                "PostgreSQL database URL must not be empty."
            )

        self._database_url = (
            database_url.strip()
        )

    def _runtime(self):
        """Return the shared PostgreSQL runtime."""

        from packages.trust.postgres_runtime import (
            get_postgres_runtime,
        )

        return get_postgres_runtime(
            self._database_url
        )

    def _connection(self):
        """Return a pooled connection context manager."""

        return self._runtime().connection()


class PostgreSQLCredentialStore(
    PostgreSQLBase
):
    """CredentialStore backed by pooled PostgreSQL."""

    def register(
        self,
        record: CredentialRecord,
    ) -> None:
        with self._connection() as connection:
            existing = connection.execute(
                """
                SELECT 1
                FROM aegis_credentials
                WHERE certificate_serial_number = %s
                """,
                (
                    record.certificate_serial_number,
                ),
            ).fetchone()

            if existing is not None:
                raise ValueError(
                    "Credential certificate serial is already registered: "
                    f"{record.certificate_serial_number}"
                )

            connection.execute(
                """
                INSERT INTO aegis_credentials (
                    certificate_serial_number,
                    key_id,
                    subject,
                    common_name,
                    status,
                    issued_at,
                    expires_at,
                    revoked_at,
                    revocation_reason
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    record.certificate_serial_number,
                    record.key_id,
                    record.subject,
                    record.common_name,
                    record.status.value,
                    record.issued_at,
                    record.expires_at,
                    record.revoked_at,
                    record.revocation_reason,
                ),
            )

            self._append_audit_event(
                connection,
                event_type="REGISTERED",
                record=record,
            )

    def get_by_serial(
        self,
        certificate_serial_number: str,
    ) -> CredentialRecord:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT
                    key_id,
                    certificate_serial_number,
                    subject,
                    common_name,
                    status,
                    issued_at,
                    expires_at,
                    revoked_at,
                    revocation_reason
                FROM aegis_credentials
                WHERE certificate_serial_number = %s
                """,
                (
                    certificate_serial_number,
                ),
            ).fetchone()

        if row is None:
            raise KeyError(
                "Unknown credential certificate serial: "
                f"{certificate_serial_number}"
            )

        return CredentialRecord(
            key_id=str(row[0]),
            certificate_serial_number=str(row[1]),
            subject=str(row[2]),
            common_name=str(row[3]),
            status=CredentialStatus(
                str(row[4])
            ),
            issued_at=_ensure_aware_datetime(
                row[5]
            ),
            expires_at=(
                _ensure_aware_datetime(
                    row[6]
                )
                if row[6] is not None
                else None
            ),
            revoked_at=(
                _ensure_aware_datetime(
                    row[7]
                )
                if row[7] is not None
                else None
            ),
            revocation_reason=(
                str(row[8])
                if row[8] is not None
                else None
            ),
        )

    def revoke(
        self,
        certificate_serial_number: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> CredentialRecord:
        if not reason.strip():
            raise ValueError(
                "Revocation reason must not be empty."
            )

        record = self.get_by_serial(
            certificate_serial_number
        )

        if record.status is CredentialStatus.REVOKED:
            return record

        revoked_at = _ensure_aware_datetime(
            revoked_at
            or datetime.now(
                timezone.utc
            )
        )

        updated = CredentialRecord(
            key_id=record.key_id,
            certificate_serial_number=(
                record.certificate_serial_number
            ),
            subject=record.subject,
            common_name=record.common_name,
            status=CredentialStatus.REVOKED,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            revoked_at=revoked_at,
            revocation_reason=reason,
        )

        with self._connection() as connection:
            connection.execute(
                """
                UPDATE aegis_credentials
                SET
                    status = %s,
                    revoked_at = %s,
                    revocation_reason = %s
                WHERE certificate_serial_number = %s
                """,
                (
                    updated.status.value,
                    updated.revoked_at,
                    updated.revocation_reason,
                    certificate_serial_number,
                ),
            )

            self._append_audit_event(
                connection,
                event_type="REVOKED",
                record=updated,
            )

        return updated

    def status_at(
        self,
        certificate_serial_number: str,
        *,
        at: datetime | None = None,
    ) -> CredentialStatus:
        at = _ensure_aware_datetime(
            at
            or datetime.now(
                timezone.utc
            )
        )

        record = self.get_by_serial(
            certificate_serial_number
        )

        if record.status is CredentialStatus.REVOKED:
            return CredentialStatus.REVOKED

        if (
            record.expires_at is not None
            and at > record.expires_at
        ):
            return CredentialStatus.EXPIRED

        return CredentialStatus.ACTIVE

    def audit_events(
        self,
    ) -> list[dict[str, object]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    event_type,
                    certificate_serial_number,
                    event_time,
                    payload_json,
                    previous_hash,
                    event_hash
                FROM aegis_credential_audit
                ORDER BY sequence ASC
                """
            ).fetchall()

        return [
            {
                "sequence": row[0],
                "event_type": row[1],
                "certificate_serial_number": row[2],
                "event_time": (
                    _ensure_aware_datetime(
                        row[3]
                    )
                ),
                "payload_json": row[4],
                "previous_hash": row[5],
                "event_hash": row[6],
            }
            for row in rows
        ]

    def verify_audit_chain(
        self,
    ) -> bool:
        events = self.audit_events()

        previous_hash = ""

        for expected_sequence, event in enumerate(
            events,
            start=1,
        ):
            if (
                event["sequence"]
                != expected_sequence
            ):
                return False

            if (
                event["previous_hash"]
                != previous_hash
            ):
                return False

            canonical = {
                "sequence": event["sequence"],
                "event_type": event["event_type"],
                "certificate_serial_number": (
                    event[
                        "certificate_serial_number"
                    ]
                ),
                "event_time": (
                    _ensure_aware_datetime(
                        event["event_time"]
                    ).isoformat()
                ),
                "payload_json": (
                    event["payload_json"]
                ),
                "previous_hash": (
                    event["previous_hash"]
                ),
            }

            expected_hash = hashlib.sha256(
                json.dumps(
                    canonical,
                    sort_keys=True,
                    separators=(
                        ",",
                        ":",
                    ),
                ).encode(
                    "utf-8"
                )
            ).hexdigest()

            supplied_hash = str(
                event["event_hash"]
            )

            if not hmac.compare_digest(
                expected_hash,
                supplied_hash,
            ):
                return False

            previous_hash = supplied_hash

        return True

    @staticmethod
    def _append_audit_event(
        connection,
        *,
        event_type: str,
        record: CredentialRecord,
    ) -> None:
        last_event = connection.execute(
            """
            SELECT event_hash
            FROM aegis_credential_audit
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()

        previous_hash = (
            ""
            if last_event is None
            else str(
                last_event[0]
            )
        )

        event_time = datetime.now(
            timezone.utc
        )

        payload = {
            "key_id": record.key_id,
            "certificate_serial_number": (
                record.certificate_serial_number
            ),
            "subject": record.subject,
            "common_name": record.common_name,
            "status": record.status.value,
            "issued_at": (
                record.issued_at.isoformat()
            ),
            "expires_at": (
                record.expires_at.isoformat()
                if record.expires_at
                else None
            ),
            "revoked_at": (
                record.revoked_at.isoformat()
                if record.revoked_at
                else None
            ),
            "revocation_reason": (
                record.revocation_reason
            ),
        }

        payload_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
        )

        sequence = int(
            connection.execute(
                """
                SELECT
                    COALESCE(
                        MAX(sequence),
                        0
                    ) + 1
                FROM aegis_credential_audit
                """
            ).fetchone()[0]
        )

        canonical = {
            "sequence": sequence,
            "event_type": event_type,
            "certificate_serial_number": (
                record.certificate_serial_number
            ),
            "event_time": (
                event_time.isoformat()
            ),
            "payload_json": payload_json,
            "previous_hash": previous_hash,
        }

        event_hash = hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(
                    ",",
                    ":",
                ),
            ).encode(
                "utf-8"
            )
        ).hexdigest()

        connection.execute(
            """
            INSERT INTO aegis_credential_audit (
                event_type,
                certificate_serial_number,
                event_time,
                payload_json,
                previous_hash,
                event_hash
            )
            VALUES (
                %s, %s, %s, %s, %s, %s
            )
            """,
            (
                event_type,
                record.certificate_serial_number,
                event_time,
                payload_json,
                previous_hash,
                event_hash,
            ),
        )


class PostgreSQLAdminStore(
    PostgreSQLBase
):
    """Administrator identities and sessions backed by PostgreSQL."""

    PASSWORD_ITERATIONS = 310_000
    SESSION_TTL_SECONDS = 15 * 60

    def register(
        self,
        *,
        administrator_id: str,
        username: str,
        display_name: str,
        role: str,
        password: str,
    ) -> AdminRecord:
        administrator_id = (
            administrator_id.strip()
        )

        username = username.strip()

        display_name = (
            display_name.strip()
        )

        if not administrator_id:
            raise ValueError(
                "administrator_id must not be empty."
            )

        if not username:
            raise ValueError(
                "username must not be empty."
            )

        if not display_name:
            raise ValueError(
                "display_name must not be empty."
            )

        role_value = (
            role.value
            if hasattr(
                role,
                "value",
            )
            else str(role)
        )

        if role_value not in ROLE_PERMISSIONS:
            raise ValueError(
                "Unsupported administrator role: "
                f"{role_value}"
            )

        if len(password) < 12:
            raise ValueError(
                "Administrator password must be at least 12 characters."
            )

        salt = secrets.token_bytes(
            16
        )

        password_hash = (
            self._hash_password(
                password,
                salt,
            )
        )

        created_at = int(
            time.time()
        )

        try:
            with self._connection() as connection:
                connection.execute(
                    """
                    INSERT INTO aegis_administrators (
                        administrator_id,
                        username,
                        display_name,
                        role,
                        password_salt,
                        password_hash,
                        enabled,
                        created_at,
                        disabled_at
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        administrator_id,
                        username,
                        display_name,
                        role_value,
                        salt,
                        password_hash,
                        True,
                        created_at,
                        None,
                    ),
                )

        except Exception as exc:
            if (
                psycopg is not None
                and isinstance(
                    exc,
                    psycopg.errors.UniqueViolation,
                )
            ):
                raise ValueError(
                    "Administrator ID or username is already registered."
                ) from exc

            raise

        return self.get_by_username(
            username
        )

    def get_by_username(
        self,
        username: str,
    ) -> AdminRecord:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT
                    administrator_id,
                    username,
                    display_name,
                    role,
                    password_salt,
                    password_hash,
                    enabled,
                    created_at,
                    disabled_at
                FROM aegis_administrators
                WHERE username = %s
                """,
                (
                    username,
                ),
            ).fetchone()

        if row is None:
            raise KeyError(
                "Unknown administrator username: "
                f"{username}"
            )

        return self._row_to_admin(
            row
        )

    def authenticate(
        self,
        *,
        username: str,
        password: str,
    ) -> AdminRecord:
        try:
            record = self.get_by_username(
                username
            )

        except KeyError as exc:
            raise AdminAuthenticationError(
                "Invalid administrator credentials."
            ) from exc

        if not record.enabled:
            raise AdminAuthenticationError(
                "Administrator account is disabled."
            )

        candidate = self._hash_password(
            password,
            record.password_salt,
        )

        if not hmac.compare_digest(
            candidate,
            record.password_hash,
        ):
            raise AdminAuthenticationError(
                "Invalid administrator credentials."
            )

        return record

    def create_session(
        self,
        administrator: AdminRecord,
    ) -> tuple[str, AdminSession]:
        token = secrets.token_urlsafe(
            32
        )

        now = int(
            time.time()
        )

        role_value = (
            administrator.role.value
            if hasattr(
                administrator.role,
                "value",
            )
            else str(
                administrator.role
            )
        )

        session = AdminSession(
            session_hash=(
                self._hash_session(
                    token
                )
            ),
            administrator_id=(
                administrator.administrator_id
            ),
            username=administrator.username,
            display_name=(
                administrator.display_name
            ),
            role=role_value,
            created_at=now,
            expires_at=(
                now
                + self.SESSION_TTL_SECONDS
            ),
        )

        with self._connection() as connection:
            connection.execute(
                """
                DELETE FROM aegis_admin_sessions
                WHERE expires_at <= %s
                """,
                (
                    now,
                ),
            )

            connection.execute(
                """
                INSERT INTO aegis_admin_sessions (
                    session_hash,
                    administrator_id,
                    username,
                    display_name,
                    role,
                    created_at,
                    expires_at
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s
                )
                """,
                (
                    session.session_hash,
                    session.administrator_id,
                    session.username,
                    session.display_name,
                    session.role,
                    session.created_at,
                    session.expires_at,
                ),
            )

        return token, session

    def resolve_session(
        self,
        token: str,
    ) -> AdminSession:
        session_hash = (
            self._hash_session(
                token
            )
        )

        now = int(
            time.time()
        )

        with self._connection() as connection:
            connection.execute(
                """
                DELETE FROM aegis_admin_sessions
                WHERE expires_at <= %s
                """,
                (
                    now,
                ),
            )

            row = connection.execute(
                """
                SELECT
                    session_hash,
                    administrator_id,
                    username,
                    display_name,
                    role,
                    created_at,
                    expires_at
                FROM aegis_admin_sessions
                WHERE session_hash = %s
                """,
                (
                    session_hash,
                ),
            ).fetchone()

        if row is None:
            raise AdminAuthenticationError(
                "Administrator session is invalid or expired."
            )

        return AdminSession(
            session_hash=str(
                row[0]
            ),
            administrator_id=str(
                row[1]
            ),
            username=str(
                row[2]
            ),
            display_name=str(
                row[3]
            ),
            role=str(
                row[4]
            ),
            created_at=int(
                row[5]
            ),
            expires_at=int(
                row[6]
            ),
        )

    def revoke_session(
        self,
        token: str,
    ) -> bool:
        session_hash = (
            self._hash_session(
                token
            )
        )

        with self._connection() as connection:
            result = connection.execute(
                """
                DELETE FROM aegis_admin_sessions
                WHERE session_hash = %s
                """,
                (
                    session_hash,
                ),
            )

        return (
            result.rowcount > 0
        )

    def assert_permission(
        self,
        session: AdminSession,
        permission: str,
    ) -> None:
        permissions = ROLE_PERMISSIONS.get(
            session.role,
            frozenset(),
        )

        if permission not in permissions:
            raise AdminAuthorizationError(
                f"Administrator role {session.role} "
                f"does not permit {permission}."
            )

    @classmethod
    def _hash_password(
        cls,
        password: str,
        salt: bytes,
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(
                "utf-8"
            ),
            salt,
            cls.PASSWORD_ITERATIONS,
        )

    @staticmethod
    def _hash_session(
        token: str,
    ) -> str:
        return hashlib.sha256(
            token.encode(
                "utf-8"
            )
        ).hexdigest()

    @staticmethod
    def _row_to_admin(
        row,
    ) -> AdminRecord:
        return AdminRecord(
            administrator_id=str(
                row[0]
            ),
            username=str(
                row[1]
            ),
            display_name=str(
                row[2]
            ),
            role=str(
                row[3]
            ),
            password_salt=bytes(
                row[4]
            ),
            password_hash=bytes(
                row[5]
            ),
            enabled=bool(
                row[6]
            ),
            created_at=int(
                row[7]
            ),
            disabled_at=(
                int(
                    row[8]
                )
                if row[8] is not None
                else None
            ),
        )


class PostgreSQLAdminAuditStore(
    PostgreSQLBase
):
    """Administrator audit chain backed by PostgreSQL."""

    def append_event(
        self,
        *,
        event_type: str,
        administrator_id: str,
        username: str,
        identity: str,
        role: str,
        certificate_serial_number: str | None,
        reason: str | None,
        event_time: datetime | None = None,
    ) -> dict[str, object]:
        timestamp = _ensure_aware_datetime(
            event_time
            or datetime.now(
                timezone.utc
            )
        )

        with self._connection() as connection:
            last_event = connection.execute(
                """
                SELECT event_hash
                FROM aegis_admin_audit
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()

            previous_hash = (
                ""
                if last_event is None
                else str(
                    last_event[0]
                )
            )

            sequence = int(
                connection.execute(
                    """
                    SELECT
                        COALESCE(
                            MAX(sequence),
                            0
                        ) + 1
                    FROM aegis_admin_audit
                    """
                ).fetchone()[0]
            )

            event = {
                "sequence": sequence,
                "event_type": event_type,
                "event_time": timestamp.isoformat(),
                "administrator_id": (
                    administrator_id
                ),
                "username": username,
                "identity": identity,
                "role": role,
                "certificate_serial_number": (
                    certificate_serial_number
                ),
                "reason": reason,
                "previous_hash": previous_hash,
            }

            event_hash = _calculate_audit_hash(
                event
            )

            event["event_hash"] = (
                event_hash
            )

            connection.execute(
                """
                INSERT INTO aegis_admin_audit (
                    sequence,
                    event_type,
                    event_time,
                    administrator_id,
                    username,
                    identity,
                    role,
                    certificate_serial_number,
                    reason,
                    previous_hash,
                    event_hash
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                )
                """,
                (
                    sequence,
                    event_type,
                    timestamp,
                    administrator_id,
                    username,
                    identity,
                    role,
                    certificate_serial_number,
                    reason,
                    previous_hash,
                    event_hash,
                ),
            )

            return event

    def events(
        self,
    ) -> list[dict[str, object]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    event_type,
                    event_time,
                    administrator_id,
                    username,
                    identity,
                    role,
                    certificate_serial_number,
                    reason,
                    previous_hash,
                    event_hash
                FROM aegis_admin_audit
                ORDER BY sequence ASC
                """
            ).fetchall()

        return [
            {
                "sequence": row[0],
                "event_type": row[1],
                "event_time": (
                    _ensure_aware_datetime(
                        row[2]
                    ).isoformat()
                ),
                "administrator_id": row[3],
                "username": row[4],
                "identity": row[5],
                "role": row[6],
                "certificate_serial_number": row[7],
                "reason": row[8],
                "previous_hash": row[9],
                "event_hash": row[10],
            }
            for row in rows
        ]

    def verify_chain(
        self,
    ) -> bool:
        events = self.events()

        previous_hash = ""

        for expected_sequence, event in enumerate(
            events,
            start=1,
        ):
            if event.get(
                "sequence"
            ) != expected_sequence:
                return False

            if event.get(
                "previous_hash"
            ) != previous_hash:
                return False

            supplied_hash = event.get(
                "event_hash"
            )

            if not isinstance(
                supplied_hash,
                str,
            ):
                return False

            comparable = dict(
                event
            )

            comparable.pop(
                "event_hash",
                None,
            )

            expected_hash = (
                _calculate_audit_hash(
                    comparable
                )
            )

            if not hmac.compare_digest(
                expected_hash,
                supplied_hash,
            ):
                return False

            previous_hash = supplied_hash

        return True


# ============================================================================
# Helpers
# ============================================================================


def _ensure_aware_datetime(
    value: datetime,
) -> datetime:
    """Normalize a datetime to UTC."""

    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


def _calculate_audit_hash(
    event_without_hash: dict,
) -> str:
    """Calculate the deterministic audit hash."""

    canonical = json.dumps(
        event_without_hash,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )

    return hashlib.sha256(
        canonical.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================================
# Backend factories
# ============================================================================


def create_credential_store(
    database_path: str | Path | None = None,
    *,
    backend: str = "sqlite",
    database_url: str | None = None,
) -> CredentialStore:
    """Create the configured credential store."""

    normalized_backend = (
        backend.strip().lower()
    )

    if normalized_backend == "sqlite":
        if database_path is None:
            raise ValueError(
                "SQLite credential store requires database_path."
            )

        return SQLiteCredentialStore(
            database_path
        )

    if normalized_backend in {
        "postgres",
        "postgresql",
    }:
        if not database_url:
            raise ValueError(
                "PostgreSQL credential store requires database_url."
            )

        return PostgreSQLCredentialStore(
            database_url
        )

    raise ValueError(
        "Unsupported credential storage backend: "
        f"{backend}"
    )


def create_admin_store(
    database_path: str | Path | None = None,
    *,
    backend: str = "sqlite",
    database_url: str | None = None,
) -> AdminStore:
    """Create the configured administrator store."""

    normalized_backend = (
        backend.strip().lower()
    )

    if normalized_backend == "sqlite":
        if database_path is None:
            raise ValueError(
                "SQLite administrator store requires database_path."
            )

        return SQLiteAdminStore(
            database_path
        )

    if normalized_backend in {
        "postgres",
        "postgresql",
    }:
        if not database_url:
            raise ValueError(
                "PostgreSQL administrator store requires database_url."
            )

        return PostgreSQLAdminStore(
            database_url
        )

    raise ValueError(
        "Unsupported administrator storage backend: "
        f"{backend}"
    )


def create_admin_audit_store(
    audit_path: str | Path | None = None,
    *,
    backend: str = "sqlite",
    database_url: str | None = None,
) -> AdminAuditStore:
    """Create the configured administrator audit store."""

    normalized_backend = (
        backend.strip().lower()
    )

    if normalized_backend == "sqlite":
        if audit_path is None:
            raise ValueError(
                "SQLite administrator audit store requires audit_path."
            )

        return SQLiteAdminAuditStore(
            audit_path
        )

    if normalized_backend in {
        "postgres",
        "postgresql",
    }:
        if not database_url:
            raise ValueError(
                "PostgreSQL administrator audit store requires database_url."
            )

        return PostgreSQLAdminAuditStore(
            database_url
        )

    raise ValueError(
        "Unsupported administrator audit backend: "
        f"{backend}"
    )