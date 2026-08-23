"""AEGIS PostgreSQL schema migrations.

The production database schema is versioned explicitly.

Migration application is idempotent:
    - already-applied migrations are skipped
    - migrations are recorded transactionally
    - schema upgrades occur in deterministic order

SQLite is intentionally not managed by this module. The existing SQLite
backend remains the local/test implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock

from packages.trust.storage import PostgreSQLUnavailableError


@dataclass(frozen=True)
class Migration:
    """One PostgreSQL schema migration."""

    version: int
    name: str
    sql: str


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="initial_aegis_schema",
        sql="""
        CREATE TABLE IF NOT EXISTS aegis_credentials (
            certificate_serial_number TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            common_name TEXT NOT NULL,
            status TEXT NOT NULL,
            issued_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            revocation_reason TEXT
        );

        CREATE TABLE IF NOT EXISTS aegis_credential_audit (
            sequence BIGSERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            certificate_serial_number TEXT NOT NULL,
            event_time TIMESTAMPTZ NOT NULL,
            payload_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS aegis_administrators (
            administrator_id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            password_salt BYTEA NOT NULL,
            password_hash BYTEA NOT NULL,
            enabled BOOLEAN NOT NULL,
            created_at BIGINT NOT NULL,
            disabled_at BIGINT
        );

        CREATE TABLE IF NOT EXISTS aegis_admin_sessions (
            session_hash TEXT PRIMARY KEY,
            administrator_id TEXT NOT NULL,
            username TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS aegis_admin_audit (
            sequence BIGSERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            event_time TIMESTAMPTZ NOT NULL,
            administrator_id TEXT NOT NULL,
            username TEXT NOT NULL,
            identity TEXT NOT NULL,
            role TEXT NOT NULL,
            certificate_serial_number TEXT,
            reason TEXT,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE
        );

        CREATE INDEX IF NOT EXISTS
        idx_aegis_admin_sessions_expiry
        ON aegis_admin_sessions (expires_at);

        CREATE INDEX IF NOT EXISTS
        idx_aegis_credential_audit_serial
        ON aegis_credential_audit (
            certificate_serial_number
        );

        CREATE INDEX IF NOT EXISTS
        idx_aegis_admin_audit_serial
        ON aegis_admin_audit (
            certificate_serial_number
        );
        """,
    ),
    Migration(
        version=2,
        name="official_communications_schema",
        sql="""
        CREATE TABLE IF NOT EXISTS aegis_notices (
            notice_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            notice_type TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            content TEXT NOT NULL,
            author_id TEXT NOT NULL,
            author_name TEXT NOT NULL,
            audience TEXT NOT NULL DEFAULT 'ALL',
            status TEXT NOT NULL DEFAULT 'DRAFT',
            version BIGINT NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            published_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ,
            signed_asset_url TEXT,
            signed_asset_sha256 TEXT,
            credential_serial_number TEXT,
            CONSTRAINT aegis_notices_status_check
                CHECK (
                    status IN (
                        'DRAFT',
                        'READY_FOR_APPROVAL',
                        'APPROVED',
                        'PUBLISHED',
                        'EXPIRED',
                        'REVOKED'
                    )
                ),
            CONSTRAINT aegis_notices_version_check
                CHECK (version >= 1)
        );

        CREATE INDEX IF NOT EXISTS aegis_notices_status_idx
            ON aegis_notices (status);

        CREATE INDEX IF NOT EXISTS aegis_notices_author_idx
            ON aegis_notices (author_id);

        CREATE INDEX IF NOT EXISTS aegis_notices_published_idx
            ON aegis_notices (published_at DESC);

        CREATE INDEX IF NOT EXISTS aegis_notices_expires_idx
            ON aegis_notices (expires_at);

        CREATE TABLE IF NOT EXISTS aegis_notice_audit (
            sequence BIGSERIAL PRIMARY KEY,
            notice_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            actor_name TEXT NOT NULL,
            event_time TIMESTAMPTZ NOT NULL,
            payload_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE,
            CONSTRAINT aegis_notice_audit_notice_fk
                FOREIGN KEY (notice_id)
                REFERENCES aegis_notices (notice_id)
                ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS
        aegis_notice_audit_notice_idx
            ON aegis_notice_audit (
                notice_id,
                sequence
            );

        CREATE INDEX IF NOT EXISTS
        aegis_notice_audit_event_time_idx
            ON aegis_notice_audit (
                event_time DESC
            );
        """,
    ),
    Migration(
        version=3,
        name="official_communications_identities",
        sql="""
        CREATE TABLE IF NOT EXISTS aegis_publishers (
            publisher_id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            organization TEXT NOT NULL,
            password_salt BYTEA NOT NULL,
            password_hash BYTEA NOT NULL,
            enabled BOOLEAN NOT NULL,
            created_at BIGINT NOT NULL,
            disabled_at BIGINT
        );

        CREATE INDEX IF NOT EXISTS
        aegis_publishers_role_idx
        ON aegis_publishers (role);

        CREATE INDEX IF NOT EXISTS
        aegis_publishers_enabled_idx
        ON aegis_publishers (enabled);

        CREATE TABLE IF NOT EXISTS aegis_publisher_sessions (
            session_hash TEXT PRIMARY KEY,
            publisher_id TEXT NOT NULL,
            username TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL,
            CONSTRAINT aegis_publisher_sessions_publisher_fk
                FOREIGN KEY (publisher_id)
                REFERENCES aegis_publishers (publisher_id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS
        aegis_publisher_sessions_expiry_idx
        ON aegis_publisher_sessions (expires_at);

        CREATE INDEX IF NOT EXISTS
        aegis_publisher_sessions_publisher_idx
        ON aegis_publisher_sessions (publisher_id);

        CREATE TABLE IF NOT EXISTS aegis_publisher_audit (
            sequence BIGSERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            event_time TIMESTAMPTZ NOT NULL,
            publisher_id TEXT NOT NULL,
            username TEXT NOT NULL,
            identity TEXT NOT NULL,
            role TEXT NOT NULL,
            notice_id TEXT,
            reason TEXT,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE,
            CONSTRAINT aegis_publisher_audit_publisher_fk
                FOREIGN KEY (publisher_id)
                REFERENCES aegis_publishers (publisher_id)
                ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS
        aegis_publisher_audit_publisher_idx
        ON aegis_publisher_audit (publisher_id);

        CREATE INDEX IF NOT EXISTS
        aegis_publisher_audit_notice_idx
        ON aegis_publisher_audit (notice_id);

        CREATE INDEX IF NOT EXISTS
        aegis_publisher_audit_time_idx
        ON aegis_publisher_audit (event_time DESC);
        """,
    ),
    Migration(
        version=4,
        name="official_communications_publication_policy",
        sql="""
        ALTER TABLE aegis_notices
        ADD COLUMN IF NOT EXISTS publication_policy TEXT;

        UPDATE aegis_notices
        SET publication_policy = CASE
            WHEN LOWER(notice_type) IN (
                'emergency',
                'safety',
                'general',
                'general announcement'
            )
            THEN 'DIRECT'
            ELSE 'APPROVAL_REQUIRED'
        END
        WHERE publication_policy IS NULL;

        ALTER TABLE aegis_notices
        ALTER COLUMN publication_policy
        SET DEFAULT 'APPROVAL_REQUIRED';

        ALTER TABLE aegis_notices
        ALTER COLUMN publication_policy
        SET NOT NULL;

        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname =
                    'aegis_notices_publication_policy_check'
            ) THEN
                ALTER TABLE aegis_notices
                ADD CONSTRAINT
                    aegis_notices_publication_policy_check
                CHECK (
                    publication_policy IN (
                        'DIRECT',
                        'APPROVAL_REQUIRED'
                    )
                );
            END IF;
        END
        $$;

        CREATE INDEX IF NOT EXISTS
        aegis_notices_publication_policy_idx
        ON aegis_notices (
            publication_policy
        );
        """,
    ),
)


class PostgreSQLMigrationManager:
    """Apply and inspect PostgreSQL schema migrations."""

    _lock = Lock()

    def __init__(
        self,
        database_url: str,
        *,
        psycopg_module,
    ) -> None:
        if not database_url.strip():
            raise ValueError(
                "PostgreSQL database URL must not be empty."
            )

        if psycopg_module is None:
            raise PostgreSQLUnavailableError(
                "PostgreSQL support requires "
                "'psycopg[binary]'."
            )

        self._database_url = database_url
        self._psycopg = psycopg_module

    def _connect(self):
        return self._psycopg.connect(
            self._database_url
        )

    def initialize_metadata_table(
        self,
    ) -> None:
        """Create the migration bookkeeping table."""

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                aegis_schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL
                )
                """
            )

    def applied_versions(
        self,
    ) -> tuple[int, ...]:
        """Return applied migration versions."""

        self.initialize_metadata_table()

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT version
                FROM aegis_schema_migrations
                ORDER BY version ASC
                """
            ).fetchall()

        return tuple(
            int(row[0])
            for row in rows
        )

    def current_version(
        self,
    ) -> int:
        """Return the highest applied migration version."""

        versions = self.applied_versions()

        if not versions:
            return 0

        return versions[-1]

    def migrate(
        self,
    ) -> int:
        """Apply every pending migration."""

        with self._lock:
            self.initialize_metadata_table()

            applied = set(
                self.applied_versions()
            )

            for migration in MIGRATIONS:
                if migration.version in applied:
                    continue

                self._apply(
                    migration
                )

            return self.current_version()

    def _apply(
        self,
        migration: Migration,
    ) -> None:
        applied_at = datetime.now(
            timezone.utc
        )

        with self._connect() as connection:
            connection.execute(
                migration.sql
            )

            connection.execute(
                """
                INSERT INTO aegis_schema_migrations (
                    version,
                    name,
                    applied_at
                )
                VALUES (
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    migration.version,
                    migration.name,
                    applied_at,
                ),
            )

    def pending(
        self,
    ) -> tuple[Migration, ...]:
        """Return migrations that have not been applied."""

        applied = set(
            self.applied_versions()
        )

        return tuple(
            migration
            for migration in MIGRATIONS
            if migration.version not in applied
        )


def apply_postgres_migrations(
    database_url: str,
    *,
    psycopg_module,
) -> int:
    """Apply all known PostgreSQL migrations."""

    manager = PostgreSQLMigrationManager(
        database_url,
        psycopg_module=psycopg_module,
    )

    return manager.migrate()