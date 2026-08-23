"""AEGIS administrator identity, authentication, and sessions."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock


SESSION_TTL_SECONDS = 15 * 60


class AdminRole:
    """Supported administrator roles."""

    VIEWER = "VIEWER"
    AUDITOR = "AUDITOR"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


ROLE_PERMISSIONS = {
    AdminRole.VIEWER: frozenset(
        {
            "credential.read",
        }
    ),
    AdminRole.AUDITOR: frozenset(
        {
            "credential.read",
            "audit.read",
        }
    ),
    AdminRole.OPERATOR: frozenset(
        {
            "credential.read",
            "audit.read",
            "credential.revoke",
        }
    ),
    AdminRole.ADMIN: frozenset(
        {
            "credential.read",
            "audit.read",
            "credential.revoke",
            "admin.manage",
        }
    ),
}


@dataclass(frozen=True)
class AdminRecord:
    """Persistent administrator identity."""

    administrator_id: str
    username: str
    display_name: str
    role: str
    password_salt: bytes
    password_hash: bytes
    enabled: bool
    created_at: int
    disabled_at: int | None = None


@dataclass(frozen=True)
class AdminSession:
    """Short-lived server-side administrator session."""

    session_hash: str
    administrator_id: str
    username: str
    display_name: str
    role: str
    created_at: int
    expires_at: int


class AdminAuthError(Exception):
    """Base administrator authentication error."""


class AdminAuthenticationError(AdminAuthError):
    """Administrator authentication failed."""


class AdminAuthorizationError(AdminAuthError):
    """Administrator lacks the requested permission."""


class PersistentAdminRegistry:
    """SQLite-backed administrator identity registry."""

    SCHEMA_VERSION = 1

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self._database_path = Path(
            database_path
        )

        self._database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._sessions: dict[
            str,
            AdminSession,
        ] = {}

        self._session_lock = Lock()

        self._initialize_database()

    def register(
        self,
        *,
        administrator_id: str,
        username: str,
        display_name: str,
        role: str,
        password: str,
    ) -> AdminRecord:
        """Register one administrator identity."""
        administrator_id = administrator_id.strip()
        username = username.strip()
        display_name = display_name.strip()

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

        if role not in ROLE_PERMISSIONS:
            raise ValueError(
                f"Unsupported administrator role: {role}"
            )

        if len(password) < 12:
            raise ValueError(
                "Administrator password must be at least 12 characters."
            )

        salt = secrets.token_bytes(16)

        password_hash = self._hash_password(
            password,
            salt,
        )

        created_at = int(
            time.time()
        )

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO administrators (
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        administrator_id,
                        username,
                        display_name,
                        role,
                        salt,
                        password_hash,
                        1,
                        created_at,
                        None,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "Administrator ID or username is already registered."
            ) from exc

        return self.get_by_username(
            username
        )

    def get_by_username(
        self,
        username: str,
    ) -> AdminRecord:
        """Load an administrator by username."""
        with self._connect() as connection:
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
                FROM administrators
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

        if row is None:
            raise KeyError(
                f"Unknown administrator username: {username}"
            )

        return self._row_to_record(row)

    def authenticate(
        self,
        *,
        username: str,
        password: str,
    ) -> AdminRecord:
        """Authenticate an enabled administrator."""
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
        """Create a short-lived session."""
        token = secrets.token_urlsafe(
            32
        )

        now = int(
            time.time()
        )

        session = AdminSession(
            session_hash=self._hash_session(
                token
            ),
            administrator_id=(
                administrator.administrator_id
            ),
            username=administrator.username,
            display_name=administrator.display_name,
            role=administrator.role,
            created_at=now,
            expires_at=(
                now
                + SESSION_TTL_SECONDS
            ),
        )

        with self._session_lock:
            self._sessions[
                session.session_hash
            ] = session

        return token, session

    def resolve_session(
        self,
        token: str,
    ) -> AdminSession:
        """Resolve a valid session token."""
        self._remove_expired_sessions()

        session_hash = self._hash_session(
            token
        )

        with self._session_lock:
            session = self._sessions.get(
                session_hash
            )

        if session is None:
            raise AdminAuthenticationError(
                "Administrator session is invalid or expired."
            )

        if (
            session.expires_at
            <= int(time.time())
        ):
            with self._session_lock:
                self._sessions.pop(
                    session_hash,
                    None,
                )

            raise AdminAuthenticationError(
                "Administrator session is expired."
            )

        return session

    def revoke_session(
        self,
        token: str,
    ) -> bool:
        """Invalidate a session immediately."""
        session_hash = self._hash_session(
            token
        )

        with self._session_lock:
            return (
                self._sessions.pop(
                    session_hash,
                    None,
                )
                is not None
            )

    @staticmethod
    def assert_permission(
        session: AdminSession,
        permission: str,
    ) -> None:
        """Require a specific administrator permission."""
        permissions = ROLE_PERMISSIONS.get(
            session.role,
            frozenset(),
        )

        if permission not in permissions:
            raise AdminAuthorizationError(
                f"Administrator role {session.role} "
                f"does not permit {permission}."
            )

    def _remove_expired_sessions(
        self,
    ) -> None:
        now = int(
            time.time()
        )

        with self._session_lock:
            expired = [
                session_hash
                for (
                    session_hash,
                    session,
                )
                in self._sessions.items()
                if session.expires_at <= now
            ]

            for session_hash in expired:
                self._sessions.pop(
                    session_hash,
                    None,
                )

    def _initialize_database(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS administrators (
                    administrator_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    enabled INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    disabled_at INTEGER
                )
                """
            )

            connection.execute(
                """
                INSERT OR IGNORE INTO metadata (
                    key,
                    value
                )
                VALUES (?, ?)
                """,
                (
                    "schema_version",
                    str(self.SCHEMA_VERSION),
                ),
            )

    def _connect(
        self,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path
        )

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    @staticmethod
    def _hash_password(
        password: str,
        salt: bytes,
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            310_000,
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
        row: tuple[object, ...],
    ) -> AdminRecord:
        return AdminRecord(
            administrator_id=str(row[0]),
            username=str(row[1]),
            display_name=str(row[2]),
            role=str(row[3]),
            password_salt=bytes(row[4]),
            password_hash=bytes(row[5]),
            enabled=bool(row[6]),
            created_at=int(row[7]),
            disabled_at=(
                int(row[8])
                if row[8] is not None
                else None
            ),
        )