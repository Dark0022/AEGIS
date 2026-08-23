"""AEGIS Official Communications notice persistence."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone


NOTICE_STATUSES = frozenset(
    {
        "DRAFT",
        "READY_FOR_APPROVAL",
        "APPROVED",
        "PUBLISHED",
        "EXPIRED",
        "REVOKED",
    }
)


PUBLICATION_POLICIES = frozenset(
    {
        "DIRECT",
        "APPROVAL_REQUIRED",
    }
)


@dataclass(frozen=True)
class NoticeRecord:
    """Persistent official communication."""

    notice_id: str
    title: str
    notice_type: str
    summary: str
    content: str
    author_id: str
    author_name: str
    audience: str
    status: str
    version: int
    created_at: datetime
    updated_at: datetime
    published_at: datetime | None
    expires_at: datetime | None
    signed_asset_url: str | None
    signed_asset_sha256: str | None
    credential_serial_number: str | None
    publication_policy: str


class NoticeError(Exception):
    """Base notice-store error."""


class NoticeNotFoundError(NoticeError):
    """Requested notice does not exist."""


class NoticeStateError(NoticeError):
    """Requested notice transition is invalid."""


class NoticeAuthorizationError(NoticeError):
    """Actor is not allowed to modify the notice."""


class NoticeStore:
    """PostgreSQL-backed official communications notice store."""

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
            raise RuntimeError(
                "Notice storage requires psycopg."
            )

        self._database_url = database_url
        self._psycopg = psycopg_module

    def _connect(self):
        return self._psycopg.connect(
            self._database_url
        )

    @staticmethod
    def publication_policy_for_type(
        notice_type: str,
    ) -> str:
        """
        Determine the default publication policy for a notice type.

        Emergency, safety, and general communications are direct.

        Academic, examination, finance, policy/regulation, admissions,
        and other notice types require approval.
        """

        normalized = (
            notice_type
            .strip()
            .lower()
        )

        if normalized in {
            "emergency",
            "safety",
            "general",
            "general announcement",
        }:
            return "DIRECT"

        return "APPROVAL_REQUIRED"

    def create(
        self,
        *,
        title: str,
        notice_type: str,
        summary: str,
        content: str,
        author_id: str,
        author_name: str,
        audience: str,
        expires_at: datetime | None,
    ) -> NoticeRecord:
        """Create a new draft notice."""

        title = title.strip()
        notice_type = notice_type.strip()
        summary = summary.strip()
        content = content.strip()
        author_id = author_id.strip()
        author_name = author_name.strip()
        audience = audience.strip()

        if not title:
            raise ValueError(
                "title must not be empty."
            )

        if not notice_type:
            raise ValueError(
                "notice_type must not be empty."
            )

        if not content:
            raise ValueError(
                "content must not be empty."
            )

        if not author_id:
            raise ValueError(
                "author_id must not be empty."
            )

        if not author_name:
            raise ValueError(
                "author_name must not be empty."
            )

        if not audience:
            raise ValueError(
                "audience must not be empty."
            )

        now = datetime.now(
            timezone.utc
        )

        notice_id = self._new_notice_id()

        publication_policy = (
            self.publication_policy_for_type(
                notice_type
            )
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO aegis_notices (
                    notice_id,
                    title,
                    notice_type,
                    summary,
                    content,
                    author_id,
                    author_name,
                    audience,
                    status,
                    version,
                    created_at,
                    updated_at,
                    published_at,
                    expires_at,
                    signed_asset_url,
                    signed_asset_sha256,
                    credential_serial_number,
                    publication_policy
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    notice_id,
                    title,
                    notice_type,
                    summary,
                    content,
                    author_id,
                    author_name,
                    audience,
                    "DRAFT",
                    1,
                    now,
                    now,
                    None,
                    expires_at,
                    None,
                    None,
                    None,
                    publication_policy,
                ),
            )

        return self.get(
            notice_id
        )

    def list_for_actor(
        self,
        *,
        actor_id: str,
        role: str,
    ) -> list[NoticeRecord]:
        """List notices visible to the current publisher role."""

        with self._connect() as connection:
            if role == "PUBLISHER":
                rows = connection.execute(
                    """
                    SELECT
                        notice_id,
                        title,
                        notice_type,
                        summary,
                        content,
                        author_id,
                        author_name,
                        audience,
                        status,
                        version,
                        created_at,
                        updated_at,
                        published_at,
                        expires_at,
                        signed_asset_url,
                        signed_asset_sha256,
                        credential_serial_number,
                        publication_policy
                    FROM aegis_notices
                    WHERE author_id = %s
                    ORDER BY updated_at DESC
                    """,
                    (
                        actor_id,
                    ),
                ).fetchall()

            else:
                rows = connection.execute(
                    """
                    SELECT
                        notice_id,
                        title,
                        notice_type,
                        summary,
                        content,
                        author_id,
                        author_name,
                        audience,
                        status,
                        version,
                        created_at,
                        updated_at,
                        published_at,
                        expires_at,
                        signed_asset_url,
                        signed_asset_sha256,
                        credential_serial_number,
                        publication_policy
                    FROM aegis_notices
                    ORDER BY updated_at DESC
                    """
                ).fetchall()

        return [
            self._row_to_record(
                row
            )
            for row in rows
        ]

    def get(
        self,
        notice_id: str,
    ) -> NoticeRecord:
        """Return one notice."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    notice_id,
                    title,
                    notice_type,
                    summary,
                    content,
                    author_id,
                    author_name,
                    audience,
                    status,
                    version,
                    created_at,
                    updated_at,
                    published_at,
                    expires_at,
                    signed_asset_url,
                    signed_asset_sha256,
                    credential_serial_number,
                    publication_policy
                FROM aegis_notices
                WHERE notice_id = %s
                """,
                (
                    notice_id,
                ),
            ).fetchone()

        if row is None:
            raise NoticeNotFoundError(
                "Notice not found."
            )

        return self._row_to_record(
            row
        )

    def update_draft(
        self,
        notice_id: str,
        *,
        actor_id: str,
        title: str,
        notice_type: str,
        summary: str,
        content: str,
        audience: str,
        expires_at: datetime | None,
    ) -> NoticeRecord:
        """Update a draft owned by the current publisher."""

        notice = self.get(
            notice_id
        )

        if notice.author_id != actor_id:
            raise NoticeAuthorizationError(
                "Only the notice author may edit this notice."
            )

        if notice.status != "DRAFT":
            raise NoticeStateError(
                "Only DRAFT notices can be edited."
            )

        title = title.strip()
        notice_type = notice_type.strip()
        summary = summary.strip()
        content = content.strip()
        audience = audience.strip()

        if not title:
            raise ValueError(
                "title must not be empty."
            )

        if not notice_type:
            raise ValueError(
                "notice_type must not be empty."
            )

        if not content:
            raise ValueError(
                "content must not be empty."
            )

        if not audience:
            raise ValueError(
                "audience must not be empty."
            )

        publication_policy = (
            self.publication_policy_for_type(
                notice_type
            )
        )

        now = datetime.now(
            timezone.utc
        )

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE aegis_notices
                SET
                    title = %s,
                    notice_type = %s,
                    summary = %s,
                    content = %s,
                    audience = %s,
                    version = version + 1,
                    updated_at = %s,
                    expires_at = %s,
                    publication_policy = %s
                WHERE notice_id = %s
                """,
                (
                    title,
                    notice_type,
                    summary,
                    content,
                    audience,
                    now,
                    expires_at,
                    publication_policy,
                    notice_id,
                ),
            )

        return self.get(
            notice_id
        )

    def submit_for_approval(
        self,
        notice_id: str,
        *,
        actor_id: str,
    ) -> NoticeRecord:
        """Move an approval-required draft into the approval queue."""

        notice = self.get(
            notice_id
        )

        if notice.author_id != actor_id:
            raise NoticeAuthorizationError(
                "Only the notice author may submit this notice."
            )

        if notice.status != "DRAFT":
            raise NoticeStateError(
                "Only DRAFT notices can be submitted."
            )

        if notice.publication_policy != (
            "APPROVAL_REQUIRED"
        ):
            raise NoticeStateError(
                "This notice is configured for direct publication."
            )

        now = datetime.now(
            timezone.utc
        )

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE aegis_notices
                SET
                    status = %s,
                    updated_at = %s
                WHERE notice_id = %s
                """,
                (
                    "READY_FOR_APPROVAL",
                    now,
                    notice_id,
                ),
            )

        return self.get(
            notice_id
        )

    def approve(
        self,
        notice_id: str,
    ) -> NoticeRecord:
        """Approve an approval-required notice."""

        notice = self.get(
            notice_id
        )

        if notice.publication_policy != (
            "APPROVAL_REQUIRED"
        ):
            raise NoticeStateError(
                "Direct-publication notices do not require approval."
            )

        if notice.status != (
            "READY_FOR_APPROVAL"
        ):
            raise NoticeStateError(
                "Only READY_FOR_APPROVAL notices can be approved."
            )

        now = datetime.now(
            timezone.utc
        )

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE aegis_notices
                SET
                    status = %s,
                    updated_at = %s
                WHERE notice_id = %s
                """,
                (
                    "APPROVED",
                    now,
                    notice_id,
                ),
            )

        return self.get(
            notice_id
        )

    def check_publish_eligibility(
        self,
        notice_id: str,
    ) -> NoticeRecord:
        """
        Verify that a notice is eligible for cryptographic signing
        and publication.

        This method does NOT mark the notice PUBLISHED.
        """

        notice = self.get(
            notice_id
        )

        if notice.publication_policy == "DIRECT":
            if notice.status != "DRAFT":
                raise NoticeStateError(
                    "Direct notices must be in DRAFT state before publishing."
                )

            return notice

        if notice.publication_policy == (
            "APPROVAL_REQUIRED"
        ):
            if notice.status != "APPROVED":
                raise NoticeStateError(
                    "This notice must be APPROVED before publishing."
                )

            return notice

        raise NoticeStateError(
            "Notice has an invalid publication policy."
        )
    def publish_signed(
        self,
        notice_id: str,
        *,
        signed_asset_url: str,
        signed_asset_sha256: str,
        credential_serial_number: str,
    ) -> NoticeRecord:
        """
        Mark a notice as PUBLISHED after successful signing and verification.

        This method enforces the publication policy again at the database
        boundary so callers cannot bypass the workflow.
        """

        notice = self.get(
            notice_id
        )

        if notice.publication_policy == "DIRECT":
            if notice.status != "DRAFT":
                raise NoticeStateError(
                    "Direct notices must be in DRAFT state before publishing."
                )

        elif notice.publication_policy == (
            "APPROVAL_REQUIRED"
        ):
            if notice.status != "APPROVED":
                raise NoticeStateError(
                    "This notice must be APPROVED before publishing."
                )

        else:
            raise NoticeStateError(
                "Notice has an invalid publication policy."
            )

        if not signed_asset_url.strip():
            raise ValueError(
                "signed_asset_url must not be empty."
            )

        if not signed_asset_sha256.strip():
            raise ValueError(
                "signed_asset_sha256 must not be empty."
            )

        if not credential_serial_number.strip():
            raise ValueError(
                "credential_serial_number must not be empty."
            )

        now = datetime.now(
            timezone.utc
        )

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE aegis_notices
                SET
                    status = %s,
                    version = version + 1,
                    updated_at = %s,
                    published_at = %s,
                    signed_asset_url = %s,
                    signed_asset_sha256 = %s,
                    credential_serial_number = %s
                WHERE notice_id = %s
                """,
                (
                    "PUBLISHED",
                    now,
                    now,
                    signed_asset_url,
                    signed_asset_sha256,
                    credential_serial_number,
                    notice_id,
                ),
            )

        return self.get(
            notice_id
        )

    def append_audit_event(
        self,
        *,
        notice_id: str,
        event_type: str,
        actor_id: str,
        actor_name: str,
        role: str,
        reason: str | None = None,
    ) -> dict:
        """Append a notice lifecycle audit event."""

        now = datetime.now(
            timezone.utc
        )

        with self._connect() as connection:
            previous = connection.execute(
                """
                SELECT event_hash
                FROM aegis_notice_audit
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()

            previous_hash = (
                ""
                if previous is None
                else str(
                    previous[0]
                )
            )

            next_sequence = int(
                connection.execute(
                    """
                    SELECT COALESCE(
                        MAX(sequence),
                        0
                    ) + 1
                    FROM aegis_notice_audit
                    """
                ).fetchone()[0]
            )

            comparable = {
                "sequence": next_sequence,
                "notice_id": notice_id,
                "event_type": event_type,
                "actor_id": actor_id,
                "actor_name": actor_name,
                "role": role,
                "event_time": now.isoformat(),
                "reason": reason,
                "previous_hash": previous_hash,
            }

            event_hash = (
                self.calculate_audit_hash(
                    comparable
                )
            )

            connection.execute(
                """
                INSERT INTO aegis_notice_audit (
                    sequence,
                    notice_id,
                    event_type,
                    actor_id,
                    actor_name,
                    event_time,
                    payload_json,
                    previous_hash,
                    event_hash
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    next_sequence,
                    notice_id,
                    event_type,
                    actor_id,
                    actor_name,
                    now,
                    json.dumps(
                        comparable,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    previous_hash,
                    event_hash,
                ),
            )

        return {
            **comparable,
            "event_hash": event_hash,
        }

    def audit_events(
        self,
        notice_id: str,
    ) -> list[dict]:
        """Return audit events for one notice."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    notice_id,
                    event_type,
                    actor_id,
                    actor_name,
                    event_time,
                    payload_json,
                    previous_hash,
                    event_hash
                FROM aegis_notice_audit
                WHERE notice_id = %s
                ORDER BY sequence ASC
                """,
                (
                    notice_id,
                ),
            ).fetchall()

        return [
            {
                "sequence": int(
                    row[0]
                ),
                "notice_id": str(
                    row[1]
                ),
                "event_type": str(
                    row[2]
                ),
                "actor_id": str(
                    row[3]
                ),
                "actor_name": str(
                    row[4]
                ),
                "event_time": (
                    row[5].isoformat()
                    if hasattr(
                        row[5],
                        "isoformat",
                    )
                    else str(
                        row[5]
                    )
                ),
                "payload_json": str(
                    row[6]
                ),
                "previous_hash": str(
                    row[7]
                ),
                "event_hash": str(
                    row[8]
                ),
            }
            for row in rows
        ]

    def verify_audit_chain(
        self,
    ) -> bool:
        """Verify the complete notice audit hash chain."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    sequence,
                    notice_id,
                    event_type,
                    actor_id,
                    actor_name,
                    event_time,
                    payload_json,
                    previous_hash,
                    event_hash
                FROM aegis_notice_audit
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
                notice_id,
                event_type,
                actor_id,
                actor_name,
                event_time,
                payload_json,
                supplied_previous_hash,
                supplied_hash,
            ) = row

            if int(sequence) != expected_sequence:
                return False

            if (
                str(
                    supplied_previous_hash
                )
                != previous_hash
            ):
                return False

            try:
                payload = json.loads(
                    str(
                        payload_json
                    )
                )
            except json.JSONDecodeError:
                return False

            comparable = {
                "sequence": int(
                    sequence
                ),
                "notice_id": str(
                    notice_id
                ),
                "event_type": str(
                    event_type
                ),
                "actor_id": str(
                    actor_id
                ),
                "actor_name": str(
                    actor_name
                ),
                "role": str(
                    payload.get(
                        "role",
                        "",
                    )
                ),
                "event_time": (
                    event_time.isoformat()
                    if hasattr(
                        event_time,
                        "isoformat",
                    )
                    else str(
                        event_time
                    )
                ),
                "reason": payload.get(
                    "reason"
                ),
                "previous_hash": str(
                    supplied_previous_hash
                ),
            }

            expected_hash = (
                self.calculate_audit_hash(
                    comparable
                )
            )

            if expected_hash != str(
                supplied_hash
            ):
                return False

            previous_hash = str(
                supplied_hash
            )

        return True

    @staticmethod
    def calculate_audit_hash(
        event: dict,
    ) -> str:
        """Calculate a deterministic audit hash."""

        canonical = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _new_notice_id() -> str:
        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%d")

        suffix = secrets.token_hex(
            4
        ).upper()

        return (
            f"AEGIS-{timestamp}-{suffix}"
        )

    @staticmethod
    def _row_to_record(
        row,
    ) -> NoticeRecord:
        return NoticeRecord(
            notice_id=str(
                row[0]
            ),
            title=str(
                row[1]
            ),
            notice_type=str(
                row[2]
            ),
            summary=str(
                row[3]
            ),
            content=str(
                row[4]
            ),
            author_id=str(
                row[5]
            ),
            author_name=str(
                row[6]
            ),
            audience=str(
                row[7]
            ),
            status=str(
                row[8]
            ),
            version=int(
                row[9]
            ),
            created_at=row[10],
            updated_at=row[11],
            published_at=row[12],
            expires_at=row[13],
            signed_asset_url=row[14],
            signed_asset_sha256=row[15],
            credential_serial_number=row[16],
            publication_policy=str(
                row[17]
            ),
        )