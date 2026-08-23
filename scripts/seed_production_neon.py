"""Seed the production Neon database from the existing local registries.

This script intentionally copies CURRENT STATE rather than attempting to
reconstruct the historical SQLite audit hash chain. The Neon database starts
with a clean audit history and receives the existing administrator and
credential state.

Source:
    transparency/administrators.sqlite3
    transparency/credentials.sqlite3

Destination:
    DATABASE_URL from .env.local
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import psycopg
from dotenv import dotenv_values


PROJECT_ROOT = Path(__file__).resolve().parents[1]

ADMIN_DB = (
    PROJECT_ROOT
    / "transparency"
    / "administrators.sqlite3"
)

CREDENTIAL_DB = (
    PROJECT_ROOT
    / "transparency"
    / "credentials.sqlite3"
)

ENV_FILE = (
    PROJECT_ROOT / ".env.local"
)


def load_database_url() -> str:
    """Load the Neon connection string from .env.local."""

    values = dotenv_values(ENV_FILE)

    url = values.get("DATABASE_URL")

    if not url:
        raise RuntimeError(
            "DATABASE_URL was not found in .env.local."
        )

    return url


def sqlite_rows(
    database: Path,
    table: str,
) -> tuple[list[str], list[tuple]]:
    """Return column names and rows from a SQLite table."""

    if not database.exists():
        raise FileNotFoundError(
            f"SQLite database does not exist: {database}"
        )

    connection = sqlite3.connect(database)

    try:
        cursor = connection.execute(
            f"SELECT * FROM {table}"
        )

        columns = [
            description[0]
            for description in cursor.description
        ]

        rows = cursor.fetchall()

        return columns, rows

    finally:
        connection.close()


def require_columns(
    actual: list[str],
    required: set[str],
    table: str,
) -> None:
    """Validate that a source table contains required fields."""

    missing = sorted(
        required - set(actual)
    )

    if missing:
        raise RuntimeError(
            f"{table} is missing required columns: "
            + ", ".join(missing)
        )


def table_count(
    connection,
    table: str,
) -> int:
    """Return the number of rows in a PostgreSQL table."""

    return connection.execute(
        f"SELECT COUNT(*) FROM {table}"
    ).fetchone()[0]


def main() -> None:
    print("=" * 72)
    print(
        "AEGIS Production Neon Seed"
    )
    print("=" * 72)
    print()

    database_url = load_database_url()

    print(
        "Source administrator database:"
    )
    print(
        f"  {ADMIN_DB}"
    )

    print(
        "Source credential database:"
    )
    print(
        f"  {CREDENTIAL_DB}"
    )

    print()

    admin_columns, admin_rows = (
        sqlite_rows(
            ADMIN_DB,
            "administrators",
        )
    )

    credential_columns, credential_rows = (
        sqlite_rows(
            CREDENTIAL_DB,
            "credentials",
        )
    )

    require_columns(
        admin_columns,
        {
            "administrator_id",
            "username",
            "display_name",
            "role",
            "password_salt",
            "password_hash",
            "enabled",
            "created_at",
            "disabled_at",
        },
        "administrators",
    )

    require_columns(
        credential_columns,
        {
            "certificate_serial_number",
            "key_id",
            "subject",
            "common_name",
            "status",
            "issued_at",
            "expires_at",
            "revoked_at",
            "revocation_reason",
        },
        "credentials",
    )

    print(
        f"Local administrators found: {len(admin_rows)}"
    )

    print(
        f"Local credentials found: {len(credential_rows)}"
    )

    print()

    admin_index = {
        column: index
        for index, column in enumerate(
            admin_columns
        )
    }

    credential_index = {
        column: index
        for index, column in enumerate(
            credential_columns
        )
    }

    print(
        "Connecting to Neon..."
    )

    with psycopg.connect(
        database_url
    ) as connection:

        # ------------------------------------------------------------------
        # Safety confirmation
        # ------------------------------------------------------------------

        existing_counts = {
            "administrators": table_count(
                connection,
                "aegis_administrators",
            ),
            "admin_sessions": table_count(
                connection,
                "aegis_admin_sessions",
            ),
            "admin_audit": table_count(
                connection,
                "aegis_admin_audit",
            ),
            "credentials": table_count(
                connection,
                "aegis_credentials",
            ),
            "credential_audit": table_count(
                connection,
                "aegis_credential_audit",
            ),
        }

        print()
        print(
            "Existing Neon rows:"
        )

        for table, count in existing_counts.items():
            print(
                f"  {table}: {count}"
            )

        print()

        print(
            "This operation will replace the current Neon "
            "administrator/credential state."
        )

        confirmation = input(
            "Type SEED-NEON to continue: "
        ).strip()

        if confirmation != "SEED-NEON":
            print(
                "Aborted. Neon was not modified."
            )
            return

        print()

        # ------------------------------------------------------------------
        # Clear test/runtime state
        # ------------------------------------------------------------------

        print(
            "Clearing Neon runtime/test state..."
        )

        connection.execute(
            "DELETE FROM aegis_admin_audit"
        )

        connection.execute(
            "DELETE FROM aegis_admin_sessions"
        )

        connection.execute(
            "DELETE FROM aegis_administrators"
        )

        connection.execute(
            "DELETE FROM aegis_credential_audit"
        )

        connection.execute(
            "DELETE FROM aegis_credentials"
        )

        # ------------------------------------------------------------------
        # Seed administrators
        # ------------------------------------------------------------------

        print(
            "Importing existing administrators..."
        )

        for row in admin_rows:

            administrator_id = row[
                admin_index[
                    "administrator_id"
                ]
            ]

            username = row[
                admin_index[
                    "username"
                ]
            ]

            display_name = row[
                admin_index[
                    "display_name"
                ]
            ]

            role = row[
                admin_index[
                    "role"
                ]
            ]

            password_salt = row[
                admin_index[
                    "password_salt"
                ]
            ]

            password_hash = row[
                admin_index[
                    "password_hash"
                ]
            ]

            enabled = bool(
                row[
                    admin_index[
                        "enabled"
                    ]
                ]
            )

            created_at = row[
                admin_index[
                    "created_at"
                ]
            ]

            disabled_at = row[
                admin_index[
                    "disabled_at"
                ]
            ]

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
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    administrator_id,
                    username,
                    display_name,
                    role,
                    password_salt,
                    password_hash,
                    enabled,
                    created_at,
                    disabled_at,
                ),
            )

            print(
                f"  imported administrator: {username} "
                f"({role})"
            )

        # ------------------------------------------------------------------
        # Seed credentials
        # ------------------------------------------------------------------

        print()
        print(
            "Importing existing credential state..."
        )

        for row in credential_rows:

            serial = row[
                credential_index[
                    "certificate_serial_number"
                ]
            ]

            key_id = row[
                credential_index[
                    "key_id"
                ]
            ]

            subject = row[
                credential_index[
                    "subject"
                ]
            ]

            common_name = row[
                credential_index[
                    "common_name"
                ]
            ]

            status = row[
                credential_index[
                    "status"
                ]
            ]

            issued_at = row[
                credential_index[
                    "issued_at"
                ]
            ]

            expires_at = row[
                credential_index[
                    "expires_at"
                ]
            ]

            revoked_at = row[
                credential_index[
                    "revoked_at"
                ]
            ]

            revocation_reason = row[
                credential_index[
                    "revocation_reason"
                ]
            ]

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
                    serial,
                    key_id,
                    subject,
                    common_name,
                    status,
                    issued_at,
                    expires_at,
                    revoked_at,
                    revocation_reason,
                ),
            )

            print(
                f"  imported credential: {serial} "
                f"({status})"
            )

        connection.commit()

        # ------------------------------------------------------------------
        # Verify
        # ------------------------------------------------------------------

        print()
        print(
            "Verifying Neon state..."
        )

        admin_count = table_count(
            connection,
            "aegis_administrators",
        )

        credential_count = table_count(
            connection,
            "aegis_credentials",
        )

        audit_count = table_count(
            connection,
            "aegis_credential_audit",
        )

        print(
            f"  administrators: {admin_count}"
        )

        print(
            f"  credentials:    {credential_count}"
        )

        print(
            f"  credential audit rows: {audit_count}"
        )

        if audit_count != 0:
            raise RuntimeError(
                "Expected a clean credential audit history "
                "after seeding."
            )

        # Confirm the v7 credential specifically.
        v7_serial = (
            "131311662991183651165592619990782028378540647145"
        )

        v7 = connection.execute(
            """
            SELECT
                certificate_serial_number,
                status,
                revoked_at,
                revocation_reason
            FROM aegis_credentials
            WHERE certificate_serial_number = %s
            """,
            (v7_serial,),
        ).fetchone()

        print()

        if v7 is None:
            raise RuntimeError(
                "The existing v7 credential was not imported."
            )

        print(
            "Existing v7 credential:"
        )
        print(
            f"  serial: {v7[0]}"
        )
        print(
            f"  status: {v7[1]}"
        )
        print(
            f"  revoked_at: {v7[2]}"
        )
        print(
            f"  reason: {v7[3]}"
        )

        print()
        print("=" * 72)
        print(
            "NEON SEED COMPLETED"
        )
        print("=" * 72)
        print()
        print(
            "Note: historical SQLite audit events were "
            "not copied because Neon uses a different audit "
            "schema/hash-chain implementation."
        )
        print(
            "Neon starts with a clean credential audit history."
        )


if __name__ == "__main__":
    main()