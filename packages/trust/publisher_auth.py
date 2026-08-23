"""AEGIS official-communications publisher identities and sessions."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone


PUBLISHER_SESSION_TTL_SECONDS = 15 * 60


class PublisherRole:
    """Supported official-communications roles."""

    PUBLISHER = "PUBLISHER"
    APPROVER = "APPROVER"
    NOTICE_ADMIN = "NOTICE_ADMIN"


PUBLISHER_PERMISSIONS = {
    PublisherRole.PUBLISHER: frozenset(
        {
            "notice.create",
            "notice.read",
            "notice.update",
            "notice.submit",
            "notice.publish",
        }
    ),
    PublisherRole.APPROVER: frozenset(
        {
            "notice.read",
            "notice.approve",
            "notice.publish",
            "notice.revoke",
            "notice.audit",
        }
    ),
    PublisherRole.NOTICE_ADMIN: frozenset(
        {
            "notice.create",
            "notice.read",
            "notice.update",
            "notice.submit",
            "notice.approve",
            "notice.publish",
            "notice.revoke",
            "notice.audit",
            "publisher.manage",
        }
    ),
}


@dataclass(frozen=True)
class PublisherRecord:
    """Persistent official-communications identity."""

    publisher_id: str
    username: str
    display_name: str
    role: str
    organization: str
    password_salt: bytes
    password_hash: bytes
    enabled: bool
    created_at: int
    disabled_at: int | None = None


@dataclass(frozen=True)
class PublisherSession:
    """Short-lived server-side publisher session."""

    session_hash: str
    publisher_id: str
    username: str
    display_name: str
    role: str
    organization: str
    created_at: int
    expires_at: int


class PublisherAuthError(Exception):
    """Base publisher authentication error."""


class PublisherAuthenticationError(PublisherAuthError):
    """Publisher authentication failed."""


class PublisherAuthorizationError(PublisherAuthError):
    """Publisher lacks the requested permission."""


class PublisherRegistry:
    """PostgreSQL-backed publisher identity and session registry."""

    PASSWORD_ITERATIONS = 310_000

    def __init__(
        self,
        database_url: str,
        *,
        psycopg_module,
        session_ttl_seconds: int = (
            PUBLISHER_SESSION_TTL_SECONDS
        ),
    ) -> None:
        if not database_url.strip():
            raise ValueError(
                "PostgreSQL database URL must not be empty."
            )

        if psycopg_module is None:
            raise RuntimeError(
                "Publisher authentication requires psycopg."
            )

        if session_ttl_seconds < 60:
            raise ValueError(
                "Publisher session TTL must be at least 60 seconds."
            )

        self._database_url = database_url
        self._psycopg = psycopg_module
        self._session_ttl_seconds = session_ttl_seconds

    def _connect(self):
        return self._psycopg.connect(
            self._database_url
        )

    def register(
        self,
        *,
        publisher_id: str,
        username: str,
        display_name: str,
        role: str,
        organization: str,
        password: str,
    ) -> PublisherRecord:
        """Register one publisher identity."""

        publisher_id = publisher_id.strip()
        username = username.strip()
        display_name = display_name.strip()
        role = role.strip().upper()
        organization = organization.strip()

        if not publisher_id:
            raise ValueError(
                "publisher_id must not be empty."
            )

        if not username:
            raise ValueError(
                "username must not be empty."
            )

        if not display_name:
            raise ValueError(
                "display_name must not be empty."
            )

        if not organization:
            raise ValueError(
                "organization must not be empty."
            )

        if role not in PUBLISHER_PERMISSIONS:
            raise ValueError(
                f"Unsupported publisher role: {role}"
            )

        if len(password) < 12:
            raise ValueError(
                "Publisher password must be at least 12 characters."
            )

        salt = secrets.token_bytes(16)

        password_hash = self._hash_password(
            password,
            salt,
        )

        created_at = int(time.time())

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO aegis_publishers (
                        publisher_id,
                        username,
                        display_name,
                        role,
                        organization,
                        password_salt,
                        password_hash,
                        enabled,
                        created_at,
                        disabled_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        publisher_id,
                        username,
                        display_name,
                        role,
                        organization,
                        salt,
                        password_hash,
                        True,
                        created_at,
                        None,
                    ),
                )
        except Exception as exc:
            message = str(exc).lower()

            if (
                "duplicate" in message
                or "unique" in message
            ):
                raise ValueError(
                    "Publisher ID or username is already registered."
                ) from exc

            raise

        return self.get_by_username(
            username
        )

    def get_by_username(
        self,
        username: str,
    ) -> PublisherRecord:
        """Load a publisher identity by username."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    publisher_id,
                    username,
                    display_name,
                    role,
                    organization,
                    password_salt,
                    password_hash,
                    enabled,
                    created_at,
                    disabled_at
                FROM aegis_publishers
                WHERE username = %s
                """,
                (username.strip(),),
            ).fetchone()

        if row is None:
            raise KeyError(
                f"Unknown publisher username: {username}"
            )

        return self._row_to_record(
            row
        )

    def authenticate(
        self,
        *,
        username: str,
        password: str,
    ) -> PublisherRecord:
        """Authenticate an enabled publisher."""

        try:
            record = self.get_by_username(
                username
            )

        except KeyError as exc:
            raise PublisherAuthenticationError(
                "Invalid publisher credentials."
            ) from exc

        if not record.enabled:
            raise PublisherAuthenticationError(
                "Publisher account is disabled."
            )

        candidate = self._hash_password(
            password,
            record.password_salt,
        )

        if not hmac.compare_digest(
            candidate,
            record.password_hash,
        ):
            raise PublisherAuthenticationError(
                "Invalid publisher credentials."
            )

        return record

    def create_session(
        self,
        publisher: PublisherRecord,
    ) -> tuple[str, PublisherSession]:
        """Create and persist a short-lived publisher session."""

        token = secrets.token_urlsafe(32)

        now = int(time.time())

        expires_at = (
            now
            + self._session_ttl_seconds
        )

        session_hash = self._hash_session(
            token
        )

        session = PublisherSession(
            session_hash=session_hash,
            publisher_id=publisher.publisher_id,
            username=publisher.username,
            display_name=publisher.display_name,
            role=publisher.role,
            organization=publisher.organization,
            created_at=now,
            expires_at=expires_at,
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO aegis_publisher_sessions (
                    session_hash,
                    publisher_id,
                    username,
                    display_name,
                    role,
                    created_at,
                    expires_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    session.session_hash,
                    session.publisher_id,
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
    ) -> PublisherSession:
        """Resolve a valid publisher session."""

        session_hash = self._hash_session(
            token
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    s.session_hash,
                    s.publisher_id,
                    s.username,
                    s.display_name,
                    s.role,
                    p.organization,
                    s.created_at,
                    s.expires_at,
                    p.enabled
                FROM aegis_publisher_sessions AS s
                JOIN aegis_publishers AS p
                  ON p.publisher_id = s.publisher_id
                WHERE s.session_hash = %s
                """,
                (session_hash,),
            ).fetchone()

            if row is None:
                raise PublisherAuthenticationError(
                    "Publisher session is invalid or expired."
                )

            expires_at = int(
                row[7]
            )

            if expires_at <= int(
                time.time()
            ):
                connection.execute(
                    """
                    DELETE FROM aegis_publisher_sessions
                    WHERE session_hash = %s
                    """,
                    (session_hash,),
                )

                raise PublisherAuthenticationError(
                    "Publisher session is expired."
                )

            if not bool(
                row[8]
            ):
                connection.execute(
                    """
                    DELETE FROM aegis_publisher_sessions
                    WHERE session_hash = %s
                    """,
                    (session_hash,),
                )

                raise PublisherAuthenticationError(
                    "Publisher account is disabled."
                )

        return PublisherSession(
            session_hash=str(row[0]),
            publisher_id=str(row[1]),
            username=str(row[2]),
            display_name=str(row[3]),
            role=str(row[4]),
            organization=str(row[5]),
            created_at=int(row[6]),
            expires_at=int(row[7]),
        )

    def revoke_session(
        self,
        token: str,
    ) -> bool:
        """Invalidate a publisher session immediately."""

        session_hash = self._hash_session(
            token
        )

        with self._connect() as connection:
            result = connection.execute(
                """
                DELETE FROM aegis_publisher_sessions
                WHERE session_hash = %s
                """,
                (session_hash,),
            )

        return result.rowcount > 0

    @staticmethod
    def assert_permission(
        session: PublisherSession,
        permission: str,
    ) -> None:
        """Require a publisher permission."""

        permissions = PUBLISHER_PERMISSIONS.get(
            session.role,
            frozenset(),
        )

        if permission not in permissions:
            raise PublisherAuthorizationError(
                f"Publisher role {session.role} "
                f"does not permit {permission}."
            )

    def append_audit_event(
        self,
        *,
        session: PublisherSession,
        event_type: str,
        notice_id: str | None = None,
        reason: str | None = None,
    ) -> dict:
        """Append a chained publisher audit event."""

        with self._connect() as connection:
            previous = connection.execute(
                """
                SELECT event_hash
                FROM aegis_publisher_audit
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()

            previous_hash = (
                ""
                if previous is None
                else str(previous[0])
            )

            event_time = datetime.now(
                timezone.utc
            )

            event_without_hash = {
                "event_type": event_type,
                "event_time": event_time.isoformat(),
                "publisher_id": session.publisher_id,
                "username": session.username,
                "identity": session.display_name,
                "role": session.role,
                "notice_id": notice_id,
                "reason": reason,
                "previous_hash": previous_hash,
            }

            next_sequence = int(
                connection.execute(
                    """
                    SELECT COALESCE(
                        MAX(sequence),
                        0
                    ) + 1
                    FROM aegis_publisher_audit
                    """
                ).fetchone()[0]
            )

            event_without_hash[
                "sequence"
            ] = next_sequence

            event_hash = (
                self.calculate_audit_hash(
                    event_without_hash
                )
            )

            connection.execute(
                """
                INSERT INTO aegis_publisher_audit (
                    sequence,
                    event_type,
                    event_time,
                    publisher_id,
                    username,
                    identity,
                    role,
                    notice_id,
                    reason,
                    previous_hash,
                    event_hash
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    next_sequence,
                    event_type,
                    event_time,
                    session.publisher_id,
                    session.username,
                    session.display_name,
                    session.role,
                    notice_id,
                    reason,
                    previous_hash,
                    event_hash,
                ),
            )

        return {
            **event_without_hash,
            "event_hash": event_hash,
        }

    def verify_audit_chain(
        self,
    ) -> bool:
        """Verify the complete publisher audit hash chain."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    event_type,
                    event_time,
                    publisher_id,
                    username,
                    identity,
                    role,
                    notice_id,
                    reason,
                    previous_hash,
                    event_hash
                FROM aegis_publisher_audit
                ORDER BY sequence ASC
                """
            ).fetchall()

        previous_hash = ""

        for expected_sequence, row in enumerate(
            rows,
            start=1,
        ):
            (
                sequence,
                event_type,
                event_time,
                publisher_id,
                username,
                identity,
                role,
                notice_id,
                reason,
                supplied_previous_hash,
                supplied_hash,
            ) = row

            if int(sequence) != expected_sequence:
                return False

            if (
                supplied_previous_hash
                != previous_hash
            ):
                return False

            comparable = {
                "sequence": int(sequence),
                "event_type": str(event_type),
                "event_time": (
                    event_time.isoformat()
                    if hasattr(
                        event_time,
                        "isoformat",
                    )
                    else str(event_time)
                ),
                "publisher_id": str(
                    publisher_id
                ),
                "username": str(
                    username
                ),
                "identity": str(
                    identity
                ),
                "role": str(
                    role
                ),
                "notice_id": notice_id,
                "reason": reason,
                "previous_hash": str(
                    supplied_previous_hash
                ),
            }

            expected_hash = (
                self.calculate_audit_hash(
                    comparable
                )
            )

            if not hmac.compare_digest(
                expected_hash,
                str(supplied_hash),
            ):
                return False

            previous_hash = str(
                supplied_hash
            )

        return True

    @staticmethod
    def calculate_audit_hash(
        event_without_hash: dict,
    ) -> str:
        """Calculate a deterministic publisher audit hash."""

        canonical = json.dumps(
            event_without_hash,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )

        return hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    @classmethod
    def _hash_password(
        cls,
        password: str,
        salt: bytes,
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            cls.PASSWORD_ITERATIONS,
        )

    @staticmethod
    def _hash_session(
        token: str,
    ) -> str:
        return hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _row_to_record(
        row,
    ) -> PublisherRecord:
        return PublisherRecord(
            publisher_id=str(row[0]),
            username=str(row[1]),
            display_name=str(row[2]),
            role=str(row[3]),
            organization=str(row[4]),
            password_salt=bytes(row[5]),
            password_hash=bytes(row[6]),
            enabled=bool(row[7]),
            created_at=int(row[8]),
            disabled_at=(
                int(row[9])
                if row[9] is not None
                else None
            ),
        )