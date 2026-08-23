"""AEGIS credential lifecycle management."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class CredentialStatus(str, Enum):
    """Lifecycle state of an AEGIS signing credential."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class CredentialRecord:
    """Metadata describing an AEGIS signing credential."""

    key_id: str
    certificate_serial_number: str
    subject: str
    common_name: str
    status: CredentialStatus
    issued_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


class CredentialRegistry:
    """In-memory development registry for AEGIS credentials."""

    def __init__(self) -> None:
        self._records_by_serial: dict[
            str,
            CredentialRecord,
        ] = {}

    def register(
        self,
        record: CredentialRecord,
    ) -> None:
        """Register a credential exactly once."""
        serial = record.certificate_serial_number

        if serial in self._records_by_serial:
            raise ValueError(
                "Credential certificate serial is already registered: "
                f"{serial}"
            )

        self._records_by_serial[serial] = record

    def get_by_serial(
        self,
        certificate_serial_number: str,
    ) -> CredentialRecord:
        """Get a credential by X.509 certificate serial number."""
        try:
            return self._records_by_serial[
                certificate_serial_number
            ]
        except KeyError as exc:
            raise KeyError(
                "Unknown credential certificate serial: "
                f"{certificate_serial_number}"
            ) from exc

    def revoke(
        self,
        certificate_serial_number: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> CredentialRecord:
        """Revoke an active credential."""
        if not reason.strip():
            raise ValueError(
                "Revocation reason must not be empty."
            )

        record = self.get_by_serial(
            certificate_serial_number
        )

        if record.status is CredentialStatus.REVOKED:
            return record

        if revoked_at is None:
            revoked_at = datetime.now(timezone.utc)

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

        self._records_by_serial[
            certificate_serial_number
        ] = updated

        return updated

    def status_at(
        self,
        certificate_serial_number: str,
        *,
        at: datetime | None = None,
    ) -> CredentialStatus:
        """Determine effective credential status at a given time."""
        if at is None:
            at = datetime.now(timezone.utc)

        if at.tzinfo is None:
            raise ValueError(
                "at must be timezone-aware."
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


class PersistentCredentialRegistry:
    """
    Persistent AEGIS credential registry backed by SQLite.

    The audit log is append-only and hash-chained. This makes ordinary
    history tampering detectable, but does not by itself make the database
    cryptographically unforgeable against an attacker who can rewrite the
    entire database. Signed checkpoints can be added later.
    """

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

        self._initialize_database()

    def register(
        self,
        record: CredentialRecord,
    ) -> None:
        """Persist a new credential and create an audit event."""
        serial = record.certificate_serial_number

        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT 1
                FROM credentials
                WHERE certificate_serial_number = ?
                """,
                (serial,),
            ).fetchone()

            if existing is not None:
                raise ValueError(
                    "Credential certificate serial is already registered: "
                    f"{serial}"
                )

            connection.execute(
                """
                INSERT INTO credentials (
                    key_id,
                    certificate_serial_number,
                    subject,
                    common_name,
                    status,
                    issued_at,
                    expires_at,
                    revoked_at,
                    revocation_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._record_to_row(record),
            )

            self._append_event(
                connection,
                event_type="REGISTERED",
                record=record,
            )

    def get_by_serial(
        self,
        certificate_serial_number: str,
    ) -> CredentialRecord:
        """Load a credential from persistent storage."""
        with self._connect() as connection:
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
                FROM credentials
                WHERE certificate_serial_number = ?
                """,
                (certificate_serial_number,),
            ).fetchone()

        if row is None:
            raise KeyError(
                "Unknown credential certificate serial: "
                f"{certificate_serial_number}"
            )

        return self._row_to_record(row)

    def revoke(
        self,
        certificate_serial_number: str,
        *,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> CredentialRecord:
        """Persist credential revocation and create an audit event."""
        if not reason.strip():
            raise ValueError(
                "Revocation reason must not be empty."
            )

        record = self.get_by_serial(
            certificate_serial_number
        )

        if record.status is CredentialStatus.REVOKED:
            return record

        if revoked_at is None:
            revoked_at = datetime.now(timezone.utc)

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

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE credentials
                SET
                    status = ?,
                    revoked_at = ?,
                    revocation_reason = ?
                WHERE certificate_serial_number = ?
                """,
                (
                    updated.status.value,
                    _datetime_to_text(updated.revoked_at),
                    updated.revocation_reason,
                    certificate_serial_number,
                ),
            )

            self._append_event(
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
        """Determine effective persistent credential status."""
        if at is None:
            at = datetime.now(timezone.utc)

        if at.tzinfo is None:
            raise ValueError(
                "at must be timezone-aware."
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

    def audit_events(self) -> list[dict[str, object]]:
        """
        Return the complete audit event history.

        Events are returned in sequence order.
        """
        with self._connect() as connection:
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
                FROM audit_events
                ORDER BY sequence ASC
                """
            ).fetchall()

        return [
            {
                "sequence": row[0],
                "event_type": row[1],
                "certificate_serial_number": row[2],
                "event_time": row[3],
                "payload_json": row[4],
                "previous_hash": row[5],
                "event_hash": row[6],
            }
            for row in rows
        ]

    def verify_audit_chain(self) -> bool:
        """
        Verify the entire audit hash chain.

        Returns False when any event has been altered, reordered, or
        replaced without recomputing every subsequent event.
        """
        events = self.audit_events()

        previous_hash = ""

        for expected_sequence, event in enumerate(
            events,
            start=1,
        ):
            if event["sequence"] != expected_sequence:
                return False

            if event["previous_hash"] != previous_hash:
                return False

            canonical = {
                "sequence": event["sequence"],
                "event_type": event["event_type"],
                "certificate_serial_number": (
                    event["certificate_serial_number"]
                ),
                "event_time": event["event_time"],
                "payload_json": event["payload_json"],
                "previous_hash": event["previous_hash"],
            }

            expected_hash = _hash_event(
                canonical
            )

            if event["event_hash"] != expected_hash:
                return False

            previous_hash = str(
                event["event_hash"]
            )

        return True

    def _initialize_database(self) -> None:
        """Create the persistent registry schema."""
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
                CREATE TABLE IF NOT EXISTS credentials (
                    key_id TEXT NOT NULL,
                    certificate_serial_number TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    common_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT,
                    revoked_at TEXT,
                    revocation_reason TEXT
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    certificate_serial_number TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                )
                """
            )

            connection.execute(
                """
                INSERT OR IGNORE INTO metadata (
                    key,
                    value
                )
                VALUES ('schema_version', ?)
                """,
                (str(self.SCHEMA_VERSION),),
            )

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        record: CredentialRecord,
    ) -> None:
        """Append one event to the hash chain."""
        last_event = connection.execute(
            """
            SELECT event_hash
            FROM audit_events
            ORDER BY sequence DESC
            LIMIT 1
            """
        ).fetchone()

        previous_hash = (
            ""
            if last_event is None
            else str(last_event[0])
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
            "issued_at": _datetime_to_text(
                record.issued_at
            ),
            "expires_at": _datetime_to_text(
                record.expires_at
            ),
            "revoked_at": _datetime_to_text(
                record.revoked_at
            ),
            "revocation_reason": record.revocation_reason,
        }

        payload_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        connection.execute(
            """
            INSERT INTO audit_events (
                event_type,
                certificate_serial_number,
                event_time,
                payload_json,
                previous_hash,
                event_hash
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                record.certificate_serial_number,
                _datetime_to_text(
                    event_time
                ),
                payload_json,
                previous_hash,
                _hash_event(
                    {
                        "sequence": _next_sequence(
                            connection
                        ),
                        "event_type": event_type,
                        "certificate_serial_number": (
                            record.certificate_serial_number
                        ),
                        "event_time": _datetime_to_text(
                            event_time
                        ),
                        "payload_json": payload_json,
                        "previous_hash": previous_hash,
                    }
                ),
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        """Open a SQLite connection."""
        connection = sqlite3.connect(
            self._database_path
        )

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    @staticmethod
    def _record_to_row(
        record: CredentialRecord,
    ) -> tuple[object, ...]:
        return (
            record.key_id,
            record.certificate_serial_number,
            record.subject,
            record.common_name,
            record.status.value,
            _datetime_to_text(
                record.issued_at
            ),
            _datetime_to_text(
                record.expires_at
            ),
            _datetime_to_text(
                record.revoked_at
            ),
            record.revocation_reason,
        )

    @staticmethod
    def _row_to_record(
        row: tuple[object, ...],
    ) -> CredentialRecord:
        return CredentialRecord(
            key_id=str(row[0]),
            certificate_serial_number=str(row[1]),
            subject=str(row[2]),
            common_name=str(row[3]),
            status=CredentialStatus(
                str(row[4])
            ),
            issued_at=_text_to_datetime(
                str(row[5])
            ),
            expires_at=(
                _text_to_datetime(
                    str(row[6])
                )
                if row[6] is not None
                else None
            ),
            revoked_at=(
                _text_to_datetime(
                    str(row[7])
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


def _next_sequence(
    connection: sqlite3.Connection,
) -> int:
    """Calculate the sequence number for the next audit event."""
    row = connection.execute(
        """
        SELECT COALESCE(MAX(sequence), 0) + 1
        FROM audit_events
        """
    ).fetchone()

    return int(row[0])


def _hash_event(
    canonical_event: dict[str, object],
) -> str:
    """Hash a canonical audit event."""
    data = json.dumps(
        canonical_event,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        data
    ).hexdigest()


def _datetime_to_text(
    value: datetime | None,
) -> str | None:
    """Serialize a datetime as UTC ISO-8601 text."""
    if value is None:
        return None

    if value.tzinfo is None:
        raise ValueError(
            "datetime must be timezone-aware."
        )

    return (
        value.astimezone(
            timezone.utc
        ).isoformat()
    )


def _text_to_datetime(
    value: str,
) -> datetime:
    """Parse serialized ISO-8601 datetime text."""
    parsed = datetime.fromisoformat(
        value
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed