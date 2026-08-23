"""AEGIS verification, administration, and official communications API."""

from __future__ import annotations

import time
import os
import httpx
import secrets
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
import urllib.error
import urllib.request
from fastapi.responses import RedirectResponse
from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    UploadFile,
)
from packages.storage_b2 import (
    B2ObjectStore,
    B2StorageError,
)
from hashlib import sha256


from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from packages.trust.storage import (
    PostgreSQLCredentialStore,
)
from apps.api.config import settings
from packages.trust.admin_auth import (
    AdminAuthenticationError,
    AdminAuthorizationError,
    AdminSession,
)
from packages.trust.notice_store import (
    NoticeAuthorizationError,
    NoticeNotFoundError,
    NoticeRecord,
    NoticeStateError,
    NoticeStore,
)
from packages.trust.publisher_auth import (
    PublisherAuthenticationError,
    PublisherAuthorizationError,
    PublisherRegistry,
    PublisherSession,
)
from packages.trust.models import AEGISVerificationResult
from packages.trust.storage import (
    AdminAuditStore,
    AdminStore,
    CredentialStore,
    create_admin_audit_store,
    create_admin_store,
    create_credential_store,
)
from packages.trust.verifier import (
    AEGISVerifierError,
    verify_asset,
)


ROOT_CERTIFICATE_PATH = settings.root_certificate_path
CREDENTIAL_DATABASE_PATH = settings.credential_database_path
ADMIN_DATABASE_PATH = settings.administrator_database_path
ADMIN_AUDIT_PATH = settings.administrator_audit_path


class AdminLoginRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=128,
    )
    password: str = Field(
        min_length=1,
        max_length=4096,
    )


class PublisherLoginRequest(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=128,
    )
    password: str = Field(
        min_length=1,
        max_length=4096,
    )


class NoticeCreateRequest(BaseModel):
    title: str = Field(
        min_length=1,
        max_length=300,
    )
    notice_type: str = Field(
        min_length=1,
        max_length=100,
    )
    summary: str = Field(
        default="",
        max_length=2000,
    )
    content: str = Field(
        min_length=1,
        max_length=100000,
    )
    audience: str = Field(
        default="ALL",
        min_length=1,
        max_length=200,
    )
    expires_at: datetime | None = None


class NoticeUpdateRequest(BaseModel):
    title: str = Field(
        min_length=1,
        max_length=300,
    )
    notice_type: str = Field(
        min_length=1,
        max_length=100,
    )
    summary: str = Field(
        default="",
        max_length=2000,
    )
    content: str = Field(
        min_length=1,
        max_length=100000,
    )
    audience: str = Field(
        default="ALL",
        min_length=1,
        max_length=200,
    )
    expires_at: datetime | None = None


class NoticeAssetUploadRequest(BaseModel):
    """Request a direct-to-B2 notice asset upload."""

    filename: str = Field(
        min_length=1,
        max_length=255,
    )

    content_type: str = Field(
        min_length=1,
        max_length=128,
    )

    size_bytes: int = Field(
        gt=0,
    )

class RevokeCredentialRequest(BaseModel):
    reason: str = Field(
        min_length=1,
        max_length=500,
    )

class NoticeSignPublishRequest(BaseModel):
    """Request to sign and publish a B2-hosted notice asset."""

    source_key: str = Field(
        min_length=1,
        max_length=500,
    )

    filename: str = Field(
        min_length=1,
        max_length=255,
    )

    content_type: str = Field(
        min_length=1,
        max_length=128,
    )

_admin_store_lock = Lock()
_admin_stores: dict[str, AdminStore] = {}

_admin_audit_store_lock = Lock()
_admin_audit_stores: dict[str, AdminAuditStore] = {}

_publisher_registry_lock = Lock()
_publisher_registries: dict[str, PublisherRegistry] = {}

_notice_store_lock = Lock()
_notice_stores: dict[str, NoticeStore] = {}


def _path_key(
    path: str | Path,
) -> str:
    return str(
        Path(path).resolve()
    )


def _effective_storage_backend(
    *,
    database_path: str | Path | None,
    configured_path: str | Path | None,
) -> str:
    configured_backend = (
        settings.storage_backend
        .strip()
        .lower()
    )

    if (
        configured_backend in {
            "postgres",
            "postgresql",
        }
        and database_path is not None
        and configured_path is not None
        and _path_key(database_path)
        != _path_key(configured_path)
    ):
        return "sqlite"

    return configured_backend


def get_admin_registry() -> AdminStore:
    backend = _effective_storage_backend(
        database_path=ADMIN_DATABASE_PATH,
        configured_path=(
            settings.administrator_database_path
        ),
    )

    if backend in {
        "postgres",
        "postgresql",
    }:
        cache_key = (
            "postgres:"
            f"{settings.database_url}"
        )
    else:
        cache_key = (
            "sqlite:"
            f"{_path_key(ADMIN_DATABASE_PATH)}"
        )

    with _admin_store_lock:
        existing = _admin_stores.get(
            cache_key
        )

        if existing is not None:
            return existing

        store = create_admin_store(
            ADMIN_DATABASE_PATH,
            backend=backend,
            database_url=(
                settings.database_url
                if backend in {
                    "postgres",
                    "postgresql",
                }
                else None
            ),
        )

        _admin_stores[cache_key] = store

        return store


def get_admin_audit_store() -> AdminAuditStore:
    backend = _effective_storage_backend(
        database_path=ADMIN_AUDIT_PATH,
        configured_path=(
            settings.administrator_audit_path
        ),
    )

    if backend in {
        "postgres",
        "postgresql",
    }:
        cache_key = (
            "postgres:"
            f"{settings.database_url}"
        )
    else:
        cache_key = (
            "sqlite:"
            f"{_path_key(ADMIN_AUDIT_PATH)}"
        )

    with _admin_audit_store_lock:
        existing = _admin_audit_stores.get(
            cache_key
        )

        if existing is not None:
            return existing

        store = create_admin_audit_store(
            ADMIN_AUDIT_PATH,
            backend=backend,
            database_url=(
                settings.database_url
                if backend in {
                    "postgres",
                    "postgresql",
                }
                else None
            ),
        )

        _admin_audit_stores[
            cache_key
        ] = store

        return store


def get_credential_registry() -> CredentialStore:
    backend = _effective_storage_backend(
        database_path=CREDENTIAL_DATABASE_PATH,
        configured_path=(
            settings.credential_database_path
        ),
    )

    return create_credential_store(
        CREDENTIAL_DATABASE_PATH,
        backend=backend,
        database_url=(
            settings.database_url
            if backend in {
                "postgres",
                "postgresql",
            }
            else None
        ),
    )


def get_publisher_registry() -> PublisherRegistry:
    database_url = settings.database_url

    if not database_url:
        raise RuntimeError(
            "Publisher authentication requires "
            "a configured PostgreSQL database URL."
        )

    cache_key = (
        f"postgres:{database_url}"
    )

    with _publisher_registry_lock:
        existing = _publisher_registries.get(
            cache_key
        )

        if existing is not None:
            return existing

        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "Publisher authentication requires psycopg."
            ) from exc

        registry = PublisherRegistry(
            database_url,
            psycopg_module=psycopg,
            session_ttl_seconds=(
                settings.session_ttl_seconds
            ),
        )

        _publisher_registries[
            cache_key
        ] = registry

        return registry


def get_notice_store() -> NoticeStore:
    database_url = settings.database_url

    if not database_url:
        raise RuntimeError(
            "Notice storage requires "
            "a configured PostgreSQL database URL."
        )

    cache_key = (
        f"postgres:{database_url}"
    )

    with _notice_store_lock:
        existing = _notice_stores.get(
            cache_key
        )

        if existing is not None:
            return existing

        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError(
                "Notice storage requires psycopg."
            ) from exc

        store = NoticeStore(
            database_url,
            psycopg_module=psycopg,
        )

        _notice_stores[
            cache_key
        ] = store

        return store


def serialize_result(
    result: AEGISVerificationResult,
) -> dict:
    return {
        "status": result.status.value,
        "is_trusted": result.is_trusted,
        "issuer_trusted": result.issuer_trusted,
        "signature_valid": result.signature_valid,
        "content_integrity": result.content_integrity,
        "provenance_valid": result.provenance_valid,
        "credential_active": result.credential_active,
        "credential_status": result.credential_status,
        "evidence": [
            {
                "code": item.code,
                "message": item.message,
                "source": item.source,
            }
            for item in result.evidence
        ],
    }


def serialize_credential(
    record,
) -> dict:
    return {
        "key_id": record.key_id,
        "certificate_serial_number": (
            record.certificate_serial_number
        ),
        "subject": record.subject,
        "common_name": record.common_name,
        "status": record.status.value,
        "issued_at": record.issued_at.isoformat(),
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


def serialize_notice(
    notice: NoticeRecord,
) -> dict:
    return {
        "notice_id": notice.notice_id,
        "title": notice.title,
        "notice_type": notice.notice_type,
        "summary": notice.summary,
        "content": notice.content,
        "author_id": notice.author_id,
        "author_name": notice.author_name,
        "audience": notice.audience,
        "status": notice.status,
        "version": notice.version,
        "created_at": notice.created_at.isoformat(),
        "updated_at": notice.updated_at.isoformat(),
        "published_at": (
            notice.published_at.isoformat()
            if notice.published_at
            else None
        ),
        "expires_at": (
            notice.expires_at.isoformat()
            if notice.expires_at
            else None
        ),
        "signed_asset_url": (
            notice.signed_asset_url
        ),
        "signed_asset_sha256": (
            notice.signed_asset_sha256
        ),
        "credential_serial_number": (
            notice.credential_serial_number
        ),
        "publication_policy": (
            notice.publication_policy
        ),
    }


def append_admin_audit_event(
    *,
    session: AdminSession,
    event_type: str,
    certificate_serial_number: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return get_admin_audit_store().append_event(
        event_type=event_type,
        administrator_id=session.administrator_id,
        username=session.username,
        identity=session.display_name,
        role=session.role,
        certificate_serial_number=(
            certificate_serial_number
        ),
        reason=reason,
    )


def verify_admin_audit_chain() -> bool:
    return (
        get_admin_audit_store()
        .verify_chain()
    )


def read_admin_audit_events() -> list[dict]:
    return (
        get_admin_audit_store()
        .events()
    )


def require_admin_session(
    authorization: str | None = Header(
        default=None,
    ),
) -> AdminSession:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=(
                "Administrator session is required."
            ),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    scheme, separator, token = (
        authorization.partition(" ")
    )

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Use Authorization: Bearer <session-token>."
            ),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    try:
        return (
            get_admin_registry()
            .resolve_session(
                token
            )
        )

    except AdminAuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc


def require_permission(
    permission: str,
):
    def dependency(
        session: AdminSession = Depends(
            require_admin_session
        ),
    ) -> AdminSession:
        try:
            get_admin_registry().assert_permission(
                session,
                permission,
            )

        except AdminAuthorizationError as exc:
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

        return session

    return dependency


def require_publisher_session(
    authorization: str | None = Header(
        default=None,
    ),
) -> PublisherSession:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=(
                "Publisher session is required."
            ),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    scheme, separator, token = (
        authorization.partition(" ")
    )

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Use Authorization: Bearer <session-token>."
            ),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    try:
        return (
            get_publisher_registry()
            .resolve_session(
                token
            )
        )

    except PublisherAuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from exc


def require_publisher_permission(
    permission: str,
):
    def dependency(
        session: PublisherSession = Depends(
            require_publisher_session
        ),
    ) -> PublisherSession:
        try:
            PublisherRegistry.assert_permission(
                session,
                permission,
            )

        except PublisherAuthorizationError as exc:
            raise HTTPException(
                status_code=403,
                detail=str(exc),
            ) from exc

        return session

    return dependency


app = FastAPI(
    title="AEGIS Verification API",
    version=settings.api_version,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=list(
        settings.cors_origins
    ),
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
    ],
    allow_headers=[
        "Content-Type",
        "Authorization",
    ],
)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "aegis-verification-api",
        "environment": settings.environment,
        "version": settings.api_version,
        "storage_backend": (
            settings.storage_backend
        ),
    }


@app.post("/admin/login")
def admin_login(
    request: AdminLoginRequest,
) -> dict:
    registry = get_admin_registry()

    try:
        administrator = registry.authenticate(
            username=request.username,
            password=request.password,
        )

    except AdminAuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
        ) from exc

    token, session = (
        registry.create_session(
            administrator
        )
    )

    append_admin_audit_event(
        session=session,
        event_type="LOGIN",
    )

    return {
        "authenticated": True,
        "session_token": token,
        "administrator_id": (
            session.administrator_id
        ),
        "username": session.username,
        "identity": session.display_name,
        "role": session.role,
        "expires_in": (
            session.expires_at
            - session.created_at
        ),
    }


@app.post("/admin/session/validate")
def validate_admin_session(
    session: AdminSession = Depends(
        require_admin_session
    ),
) -> dict:
    return {
        "authenticated": True,
        "administrator_id": (
            session.administrator_id
        ),
        "username": session.username,
        "identity": session.display_name,
        "role": session.role,
        "expires_in": max(
            0,
            session.expires_at
            - int(time.time()),
        ),
    }


@app.post("/admin/session/revoke")
def revoke_admin_session(
    authorization: str | None = Header(
        default=None,
    ),
    session: AdminSession = Depends(
        require_admin_session
    ),
) -> dict:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=(
                "Administrator session is required."
            ),
        )

    _, _, token = (
        authorization.partition(" ")
    )

    revoked = (
        get_admin_registry()
        .revoke_session(
            token
        )
    )

    append_admin_audit_event(
        session=session,
        event_type="SESSION_REVOKED",
    )

    return {
        "revoked": revoked,
    }


@app.get("/admin/audit")
def get_admin_audit(
    _: AdminSession = Depends(
        require_permission(
            "audit.read"
        )
    ),
) -> dict:
    return {
        "audit_chain_valid": (
            verify_admin_audit_chain()
        ),
        "events": (
            read_admin_audit_events()
        ),
    }


@app.post("/publisher/login")
def publisher_login(
    request: PublisherLoginRequest,
) -> dict:
    registry = get_publisher_registry()

    try:
        publisher = registry.authenticate(
            username=request.username,
            password=request.password,
        )

    except PublisherAuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
        ) from exc

    token, session = (
        registry.create_session(
            publisher
        )
    )

    registry.append_audit_event(
        session=session,
        event_type="LOGIN",
    )

    return {
        "authenticated": True,
        "session_token": token,
        "publisher_id": session.publisher_id,
        "username": session.username,
        "identity": session.display_name,
        "organization": session.organization,
        "role": session.role,
        "expires_in": (
            session.expires_at
            - session.created_at
        ),
    }


@app.post("/publisher/session/validate")
def validate_publisher_session(
    session: PublisherSession = Depends(
        require_publisher_session
    ),
) -> dict:
    return {
        "authenticated": True,
        "publisher_id": session.publisher_id,
        "username": session.username,
        "identity": session.display_name,
        "organization": session.organization,
        "role": session.role,
        "expires_in": max(
            0,
            session.expires_at
            - int(time.time()),
        ),
    }


@app.post("/publisher/session/revoke")
def revoke_publisher_session(
    authorization: str | None = Header(
        default=None,
    ),
    session: PublisherSession = Depends(
        require_publisher_session
    ),
) -> dict:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=(
                "Publisher session is required."
            ),
        )

    scheme, separator, token = (
        authorization.partition(" ")
    )

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Use Authorization: Bearer <session-token>."
            ),
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

    registry = get_publisher_registry()

    revoked = (
        registry.revoke_session(
            token
        )
    )

    registry.append_audit_event(
        session=session,
        event_type="SESSION_REVOKED",
    )

    return {
        "revoked": revoked,
    }


@app.post("/verify")
async def verify(
    file: UploadFile = File(...),
) -> dict:
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="A filename is required.",
        )

    with TemporaryDirectory(
        prefix="aegis-verify-"
    ) as temporary_directory:
        temporary_path = (
            Path(temporary_directory)
            / Path(file.filename).name
        )

        total_bytes = 0

        try:
            with temporary_path.open(
                "wb"
            ) as destination:
                while True:
                    chunk = await file.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    total_bytes += len(
                        chunk
                    )

                    if (
                        total_bytes
                        > settings.upload_max_bytes
                    ):
                        raise HTTPException(
                            status_code=413,
                            detail=(
                                "Uploaded asset exceeds "
                                f"the configured limit of "
                                f"{settings.upload_max_bytes} bytes."
                            ),
                        )

                    destination.write(
                        chunk
                    )

            result = verify_asset(
                temporary_path,
                root_certificate_path=(
                    ROOT_CERTIFICATE_PATH
                ),
                credential_registry=(
                    get_credential_registry()
                ),
            )

            return {
                "filename": file.filename,
                "verification": (
                    serialize_result(
                        result
                    )
                ),
            }

        except HTTPException:
            raise

        except FileNotFoundError as exc:
            raise HTTPException(
                status_code=503,
                detail=str(exc),
            ) from exc

        except AEGISVerifierError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc

        except OSError as exc:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Unable to process uploaded asset."
                ),
            ) from exc


@app.get(
    "/credentials/{certificate_serial_number}"
)
def get_credential(
    certificate_serial_number: str,
    _: AdminSession = Depends(
        require_permission(
            "credential.read"
        )
    ),
) -> dict:
    registry = get_credential_registry()

    try:
        record = registry.get_by_serial(
            certificate_serial_number
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="Credential not found.",
        ) from exc

    return {
        "credential": (
            serialize_credential(
                record
            )
        )
    }


@app.get(
    "/credentials/{certificate_serial_number}/history"
)
def get_credential_history(
    certificate_serial_number: str,
    _: AdminSession = Depends(
        require_permission(
            "audit.read"
        )
    ),
) -> dict:
    registry = get_credential_registry()

    try:
        registry.get_by_serial(
            certificate_serial_number
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="Credential not found.",
        ) from exc

    events = [
        event
        for event in registry.audit_events()
        if (
            event[
                "certificate_serial_number"
            ]
            == certificate_serial_number
        )
    ]

    return {
        "certificate_serial_number": (
            certificate_serial_number
        ),
        "audit_chain_valid": (
            registry.verify_audit_chain()
        ),
        "events": events,
    }


@app.post(
    "/credentials/{certificate_serial_number}/revoke"
)
def revoke_credential(
    certificate_serial_number: str,
    request: RevokeCredentialRequest,
    session: AdminSession = Depends(
        require_permission(
            "credential.revoke"
        )
    ),
) -> dict:
    registry = get_credential_registry()

    try:
        record = registry.get_by_serial(
            certificate_serial_number
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="Credential not found.",
        ) from exc

    if record.status.value == "REVOKED":
        raise HTTPException(
            status_code=409,
            detail="Credential is already revoked.",
        )

    try:
        updated = registry.revoke(
            certificate_serial_number,
            reason=request.reason,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="Credential not found.",
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    append_admin_audit_event(
        session=session,
        event_type="CREDENTIAL_REVOKED",
        certificate_serial_number=(
            certificate_serial_number
        ),
        reason=request.reason,
    )

    return {
        "credential": (
            serialize_credential(
                updated
            )
        ),
        "audit_chain_valid": (
            verify_admin_audit_chain()
        ),
    }


# ---------------------------------------------------------------------------
# Notice creation and workflow.
# ---------------------------------------------------------------------------

@app.post("/notices")
def create_notice(
    request: NoticeCreateRequest,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.create"
        )
    ),
) -> dict:
    store = get_notice_store()

    try:
        notice = store.create(
            title=request.title,
            notice_type=request.notice_type,
            summary=request.summary,
            content=request.content,
            author_id=session.publisher_id,
            author_name=session.display_name,
            audience=request.audience,
            expires_at=request.expires_at,
        )

        audit_event = store.append_audit_event(
            notice_id=notice.notice_id,
            event_type="CREATED",
            actor_id=session.publisher_id,
            actor_name=session.display_name,
            role=session.role,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "notice": serialize_notice(
            notice
        ),
        "audit_event": audit_event,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
    }


@app.get("/notices")
def list_notices(
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.read"
        )
    ),
) -> dict:
    store = get_notice_store()

    notices = store.list_for_actor(
        actor_id=session.publisher_id,
        role=session.role,
    )

    return {
        "notices": [
            serialize_notice(
                notice
            )
            for notice in notices
        ],
    }


@app.get("/notices/{notice_id}")
def get_notice(
    notice_id: str,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.read"
        )
    ),
) -> dict:
    store = get_notice_store()

    try:
        notice = store.get(
            notice_id
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    if (
        session.role == "PUBLISHER"
        and notice.author_id
        != session.publisher_id
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Publisher may only access "
                "their own notices."
            ),
        )

    return {
        "notice": serialize_notice(
            notice
        ),
    }


@app.put("/notices/{notice_id}")
def update_notice(
    notice_id: str,
    request: NoticeUpdateRequest,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.update"
        )
    ),
) -> dict:
    store = get_notice_store()

    try:
        notice = store.update_draft(
            notice_id,
            actor_id=session.publisher_id,
            title=request.title,
            notice_type=request.notice_type,
            summary=request.summary,
            content=request.content,
            audience=request.audience,
            expires_at=request.expires_at,
        )

        audit_event = store.append_audit_event(
            notice_id=notice.notice_id,
            event_type="UPDATED",
            actor_id=session.publisher_id,
            actor_name=session.display_name,
            role=session.role,
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except NoticeAuthorizationError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    except NoticeStateError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "notice": serialize_notice(
            notice
        ),
        "audit_event": audit_event,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
    }


@app.post(
    "/notices/{notice_id}/submit"
)
def submit_notice(
    notice_id: str,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.submit"
        )
    ),
) -> dict:
    store = get_notice_store()

    try:
        notice = store.submit_for_approval(
            notice_id,
            actor_id=session.publisher_id,
        )

        audit_event = store.append_audit_event(
            notice_id=notice.notice_id,
            event_type="SUBMITTED_FOR_APPROVAL",
            actor_id=session.publisher_id,
            actor_name=session.display_name,
            role=session.role,
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except NoticeAuthorizationError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        ) from exc

    except NoticeStateError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    return {
        "notice": serialize_notice(
            notice
        ),
        "audit_event": audit_event,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
    }


@app.post(
    "/notices/{notice_id}/approve"
)
def approve_notice(
    notice_id: str,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.approve"
        )
    ),
) -> dict:
    store = get_notice_store()

    try:
        notice = store.approve(
            notice_id
        )

        audit_event = store.append_audit_event(
            notice_id=notice.notice_id,
            event_type="APPROVED",
            actor_id=session.publisher_id,
            actor_name=session.display_name,
            role=session.role,
        )

        publisher_audit = (
            get_publisher_registry()
            .append_audit_event(
                session=session,
                event_type="NOTICE_APPROVED",
                notice_id=notice.notice_id,
            )
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except NoticeStateError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    return {
        "notice": serialize_notice(
            notice
        ),
        "audit_event": audit_event,
        "publisher_audit": publisher_audit,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
    }


@app.post(
    "/notices/{notice_id}/publish"
)
def publish_notice(
    notice_id: str,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.publish"
        )
    ),
) -> dict:
    """
    Check whether a notice is eligible for signing/publishing.

    This endpoint deliberately does not mark the notice PUBLISHED yet.
    The next stage will perform C2PA signing and then commit publication.
    """

    store = get_notice_store()

    try:
        notice = (
            store.check_publish_eligibility(
                notice_id
            )
        )

        audit_event = store.append_audit_event(
            notice_id=notice.notice_id,
            event_type="PUBLICATION_AUTHORIZED",
            actor_id=session.publisher_id,
            actor_name=session.display_name,
            role=session.role,
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except NoticeStateError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    return {
        "notice": serialize_notice(
            notice
        ),
        "publication_authorized": True,
        "publication_policy": (
            notice.publication_policy
        ),
        "requires_approval": (
            notice.publication_policy
            == "APPROVAL_REQUIRED"
        ),
        "signing_required": True,
        "published": False,
        "audit_event": audit_event,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
    }
@app.post(
    "/notices/{notice_id}/asset-upload-url"
)
def create_notice_asset_upload_url(
    notice_id: str,
    request: NoticeAssetUploadRequest,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.publish"
        )
    ),
) -> dict:
    """Create a short-lived B2 upload URL for a notice asset."""

    store = get_notice_store()

    try:
        notice = store.get(
            notice_id
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    if (
        session.role == "PUBLISHER"
        and notice.author_id
        != session.publisher_id
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Publisher may only upload "
                "assets for their own notices."
            ),
        )

    allowed_types = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "application/pdf": ".pdf",
    }

    extension = (
        allowed_types.get(
            request.content_type
        )
    )

    if extension is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only PNG, JPEG, and PDF "
                "assets are supported."
            ),
        )

    if (
        request.size_bytes
        > settings.upload_max_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail=(
                "Notice asset exceeds the "
                "configured upload limit."
            ),
        )

    object_key = (
        f"notices/"
        f"{notice.notice_id}/"
        f"source/"
        f"{secrets.token_hex(16)}"
        f"{extension}"
    )

    try:
        storage = B2ObjectStore()

        upload_url = (
            storage.presigned_upload_url(
                object_key,
                content_type=request.content_type,
                expires_in=900,
            )
        )

    except B2StorageError as exc:
        raise HTTPException(
            status_code=503,
            detail=str(exc),
        ) from exc

    return {
        "upload_url": upload_url,
        "object_key": object_key,
        "expires_in": 900,
        "content_type": request.content_type,
    }
@app.post(
    "/notices/{notice_id}/sign-publish"
)
async def sign_publish_notice(
    notice_id: str,
    request: NoticeSignPublishRequest,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.publish"
        )
    ),
) -> dict:
    """
    Sign a B2-hosted notice asset, verify it, and publish the notice.

    The private signing key remains inside the isolated AEGIS
    signing service. The API never receives the private key.
    """

    store = get_notice_store()

    # ---------------------------------------------------------------
    # 1. Check publication eligibility.
    # ---------------------------------------------------------------
    try:
        notice = store.check_publish_eligibility(
            notice_id
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except NoticeStateError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    # ---------------------------------------------------------------
    # 2. Enforce publisher ownership.
    # ---------------------------------------------------------------
    if (
        session.role == "PUBLISHER"
        and notice.author_id
        != session.publisher_id
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Publisher may only publish "
                "their own notices."
            ),
        )

    # ---------------------------------------------------------------
    # 3. Validate the source object key.
    # ---------------------------------------------------------------
    expected_source_prefix = (
        f"notices/"
        f"{notice.notice_id}/"
        f"source/"
    )

    if not request.source_key.startswith(
        expected_source_prefix
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid source object for this notice."
            ),
        )

    # ---------------------------------------------------------------
    # 4. Validate the asset type.
    # ---------------------------------------------------------------
    allowed_types = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "application/pdf": ".pdf",
    }

    suffix = allowed_types.get(
        request.content_type
    )

    if suffix is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only PNG, JPEG, and PDF "
                "assets are supported."
            ),
        )

    # Do not trust a mismatched filename extension.
    filename_suffix = (
        Path(
            request.filename
        ).suffix.lower()
    )

    if filename_suffix not in {
        ".png",
        ".jpg",
        ".jpeg",
        ".pdf",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported notice asset extension."
            ),
        )

    # ---------------------------------------------------------------
    # 5. Verify the source exists in B2 and enforce size limit.
    # ---------------------------------------------------------------
    try:
        storage = B2ObjectStore()

        source_metadata = (
            storage.head(
                request.source_key
            )
        )

    except B2StorageError as exc:
        raise HTTPException(
            status_code=404,
            detail=(
                "The uploaded notice asset "
                "could not be found."
            ),
        ) from exc

    if (
        source_metadata.size
        <= 0
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "The uploaded notice asset is empty."
            ),
        )

    if (
        source_metadata.size
        > settings.upload_max_bytes
    ):
        raise HTTPException(
            status_code=413,
            detail=(
                "The uploaded notice asset exceeds "
                "the configured upload limit."
            ),
        )

    # ---------------------------------------------------------------
    # 6. Determine the immutable published object key.
    # ---------------------------------------------------------------
    signed_key = (
        f"notices/"
        f"{notice.notice_id}/"
        f"published/"
        f"{notice.notice_id}"
        f"{suffix}"
    )

    # ---------------------------------------------------------------
    # 7. Verify that the signer service is configured.
    # ---------------------------------------------------------------
    signer_service_url = (
        os.environ.get(
            "AEGIS_SIGNER_SERVICE_URL"
        )
    )

    signer_service_token = (
        os.environ.get(
            "AEGIS_SIGNER_SERVICE_TOKEN"
        )
    )

    if (
        not signer_service_url
        or not signer_service_token
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "AEGIS signing service "
                "is not configured."
            ),
        )

    # ---------------------------------------------------------------
    # 8. Ask the isolated signing service to sign the B2 object.
    # ---------------------------------------------------------------
    try:
        async with httpx.AsyncClient(
            timeout=120.0
        ) as client:
            response = await client.post(
                (
                    f"{signer_service_url.rstrip('/')}"
                    "/sign"
                ),
                headers={
                    "Authorization": (
                        "Bearer "
                        f"{signer_service_token}"
                    ),
                    "Content-Type": (
                        "application/json"
                    ),
                },
                json={
                    "notice_id": (
                        notice.notice_id
                    ),
                    "source_key": (
                        request.source_key
                    ),
                    "signed_key": (
                        signed_key
                    ),
                },
            )

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "AEGIS signing service "
                "could not be reached."
            ),
        ) from exc

    if response.status_code != 200:
        try:
            signer_error = response.json()
        except ValueError:
            signer_error = {
                "detail": (
                    response.text
                    or "Unknown signer-service error."
                )
            }

        raise HTTPException(
            status_code=503,
            detail={
                "message": (
                    "AEGIS signing service "
                    "rejected the request."
                ),
                "signer": signer_error,
            },
        )

    try:
        signing_result = (
            response.json()
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "AEGIS signing service returned "
                "invalid JSON."
            ),
        ) from exc

    signed_asset_sha256 = (
        signing_result.get(
            "signed_asset_sha256"
        )
    )

    key_id = (
        signing_result.get(
            "key_id"
        )
    )

    certificate_serial_number = (
        signing_result.get(
            "certificate_serial_number"
        )
    )

    returned_signed_key = (
        signing_result.get(
            "signed_key"
        )
    )

    if (
        not signed_asset_sha256
        or not key_id
        or not certificate_serial_number
        or returned_signed_key
        != signed_key
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "Signing service returned "
                "incomplete or inconsistent metadata."
            ),
        )

    # ---------------------------------------------------------------
    # 9. Download the signed asset from B2 and independently verify it.
    # ---------------------------------------------------------------
    with TemporaryDirectory(
        prefix="aegis-publish-verify-"
    ) as temporary_directory:

        signed_path = (
            Path(
                temporary_directory
            )
            / f"signed{suffix}"
        )

        try:
            storage.download_file(
                signed_key,
                signed_path,
            )

        except B2StorageError as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "The signed asset was not "
                    "available in B2."
                ),
            ) from exc

        actual_sha256 = (
            sha256(
                signed_path.read_bytes()
            ).hexdigest()
        )

        if (
            actual_sha256
            != signed_asset_sha256
        ):
            raise HTTPException(
                status_code=422,
                detail=(
                    "Signed asset hash returned by "
                    "the signing service does not "
                    "match the stored object."
                ),
            )

        try:
            verification = verify_asset(
                signed_path,
                root_certificate_path=(
                    ROOT_CERTIFICATE_PATH
                ),
                credential_registry=(
                    get_credential_registry()
                ),
            )

        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=(
                    "The signed asset could not "
                    "be verified by AEGIS."
                ),
            ) from exc

    # ---------------------------------------------------------------
    # 10. Refuse publication unless verification is fully trusted.
    # ---------------------------------------------------------------
    if not verification.is_trusted:
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "The signed asset failed "
                    "AEGIS verification."
                ),
                "verification": (
                    serialize_result(
                        verification
                    )
                ),
            },
        )

    # ---------------------------------------------------------------
    # 11. Commit publication to Neon.
    # ---------------------------------------------------------------
    signed_url = (
        f"/api/public/notices/"
        f"{notice.notice_id}/asset"
    )

    try:
        published_notice = (
            store.publish_signed(
                notice.notice_id,
                signed_asset_url=signed_url,
                signed_asset_sha256=(
                    actual_sha256
                ),
                credential_serial_number=(
                    certificate_serial_number
                ),
            )
        )

    except NoticeStateError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to commit the "
                "published notice."
            ),
        ) from exc

    # ---------------------------------------------------------------
    # 12. Record the chained audit events.
    # ---------------------------------------------------------------
    try:
        signed_audit = (
            store.append_audit_event(
                notice_id=notice.notice_id,
                event_type="SIGNED",
                actor_id=session.publisher_id,
                actor_name=session.display_name,
                role=session.role,
            )
        )

        published_audit = (
            store.append_audit_event(
                notice_id=notice.notice_id,
                event_type="PUBLISHED",
                actor_id=session.publisher_id,
                actor_name=session.display_name,
                role=session.role,
            )
        )

        publisher_audit = (
            get_publisher_registry()
            .append_audit_event(
                session=session,
                event_type="NOTICE_PUBLISHED",
                notice_id=notice.notice_id,
            )
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Notice was published but the "
                "publication audit could not "
                "be completed."
            ),
        ) from exc

    # ---------------------------------------------------------------
    # 13. Remove the temporary source object.
    # ---------------------------------------------------------------
    try:
        storage.delete(
            request.source_key
        )

    except B2StorageError:
        # Do not undo a successful publication merely because
        # cleanup failed. The source remains harmlessly private
        # under the notice-specific source prefix and can be
        # cleaned up later.
        pass

    return {
        "notice": serialize_notice(
            published_notice
        ),
        "signing": {
            "key_id": key_id,
            "certificate_serial_number": (
                certificate_serial_number
            ),
            "signed_asset_sha256": (
                actual_sha256
            ),
            "signed_key": signed_key,
        },
        "verification": serialize_result(
            verification
        ),
        "signed_audit": signed_audit,
        "published_audit": published_audit,
        "publisher_audit": publisher_audit,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
    }
@app.get(
    "/public/notices/{notice_id}/asset"
)
def get_public_notice_asset(
    notice_id: str,
) -> RedirectResponse:
    """Return the published notice asset from Backblaze B2."""

    store = get_notice_store()

    try:
        notice = store.get(
            notice_id
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    if notice.status != "PUBLISHED":
        raise HTTPException(
            status_code=404,
            detail="Published notice asset not found.",
        )

    if not notice.signed_asset_url:
        raise HTTPException(
            status_code=404,
            detail="Published notice asset not found.",
        )

    if not notice.signed_asset_sha256:
        raise HTTPException(
            status_code=404,
            detail="Published notice asset integrity record is missing.",
        )

    # The B2 published object uses the notice ID and the asset
    # extension. The current AEGIS publisher workflow supports PNG,
    # JPEG, and PDF.
    candidates = [
        ".png",
        ".jpg",
        ".jpeg",
        ".pdf",
    ]

    storage = B2ObjectStore()

    found_key: str | None = None

    for suffix in candidates:
        key = (
            f"notices/"
            f"{notice.notice_id}/"
            f"published/"
            f"{notice.notice_id}"
            f"{suffix}"
        )

        try:
            metadata = storage.head(
                key
            )

        except B2StorageError:
            continue

        if metadata.size > 0:
            found_key = key
            break

    if found_key is None:
        raise HTTPException(
            status_code=404,
            detail="Published notice asset not found.",
        )

    try:
        download_url = (
            storage.presigned_download_url(
                found_key,
                expires_in=300,
            )
        )

    except B2StorageError as exc:
        raise HTTPException(
            status_code=503,
            detail="Published notice asset is temporarily unavailable.",
        ) from exc

    return RedirectResponse(
        url=download_url,
        status_code=307,
    )

@app.get(
    "/notices/{notice_id}/audit"
)
def get_notice_audit(
    notice_id: str,
    session: PublisherSession = Depends(
        require_publisher_permission(
            "notice.audit"
        )
    ),
) -> dict:
    store = get_notice_store()

    try:
        store.get(
            notice_id
        )

    except NoticeNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    return {
        "notice_id": notice_id,
        "audit_chain_valid": (
            store.verify_audit_chain()
        ),
        "events": (
            store.audit_events(
                notice_id
            )
        ),
    }