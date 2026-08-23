"""AEGIS application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]


def _read_string(
    name: str,
    default: str,
) -> str:
    value = os.environ.get(
        name
    )

    if value is None:
        return default

    value = value.strip()

    return value or default


def _read_int(
    name: str,
    default: int,
    *,
    minimum: int,
) -> int:
    raw = os.environ.get(
        name
    )

    if raw is None:
        return default

    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be an integer."
        ) from exc

    if value < minimum:
        raise RuntimeError(
            f"{name} must be at least {minimum}."
        )

    return value


def _read_float(
    name: str,
    default: float,
    *,
    minimum: float,
) -> float:
    raw = os.environ.get(
        name
    )

    if raw is None:
        return default

    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"{name} must be a number."
        ) from exc

    if value < minimum:
        raise RuntimeError(
            f"{name} must be at least {minimum}."
        )

    return value


def _read_bool(
    name: str,
    default: bool,
) -> bool:
    raw = os.environ.get(
        name
    )

    if raw is None:
        return default

    value = raw.strip().lower()

    if value in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }:
        return True

    if value in {
        "0",
        "false",
        "no",
        "n",
        "off",
    }:
        return False

    raise RuntimeError(
        f"{name} must be a boolean."
    )


def _read_origins(
    name: str,
    defaults: tuple[str, ...],
) -> tuple[str, ...]:
    raw = os.environ.get(
        name
    )

    if raw is None:
        return defaults

    origins = tuple(
        origin.strip().rstrip("/")
        for origin in raw.split(",")
        if origin.strip()
    )

    if not origins:
        raise RuntimeError(
            f"{name} must contain at least one origin."
        )

    return origins


@dataclass(frozen=True)
class AEGISSettings:
    """Runtime configuration for AEGIS."""

    environment: str

    api_version: str

    storage_backend: str

    database_url: str | None

    auto_migrate: bool

    web_origins: tuple[str, ...]

    cors_origins: tuple[str, ...]

    session_ttl_seconds: int

    postgres_pool_min_size: int

    postgres_pool_max_size: int

    postgres_pool_timeout: float

    postgres_pool_max_idle: float

    postgres_pool_max_lifetime: float

    postgres_pool_reconnect_timeout: float

    postgres_pool_max_waiting: int

    postgres_require_ssl: bool

    root_certificate_path: Path

    credential_database_path: Path

    administrator_database_path: Path

    administrator_audit_path: Path

    upload_max_bytes: int


def load_settings() -> AEGISSettings:
    """Load and validate runtime configuration."""

    environment = _read_string(
        "AEGIS_ENVIRONMENT",
        "development",
    ).lower()

    if environment not in {
        "development",
        "test",
        "production",
    }:
        raise RuntimeError(
            "AEGIS_ENVIRONMENT must be "
            "development, test, or production."
        )

    storage_backend = _read_string(
        "AEGIS_STORAGE_BACKEND",
        "sqlite",
    ).lower()

    if storage_backend not in {
        "sqlite",
        "postgres",
        "postgresql",
    }:
        raise RuntimeError(
            "AEGIS_STORAGE_BACKEND must be "
            "sqlite or postgres."
        )

    database_url = (
        os.environ.get(
            "AEGIS_DATABASE_URL"
        )
        or os.environ.get(
            "DATABASE_URL"
        )
    )

    if (
        storage_backend
        in {
            "postgres",
            "postgresql",
        }
        and not database_url
    ):
        raise RuntimeError(
            "PostgreSQL storage requires "
            "AEGIS_DATABASE_URL or DATABASE_URL."
        )

    # Production databases have already been migrated during deployment
    # preparation. Auto-migration therefore defaults to false in production.
    auto_migrate = _read_bool(
        "AEGIS_AUTO_MIGRATE",
        environment != "production",
    )

    require_ssl = _read_bool(
        "AEGIS_POSTGRES_REQUIRE_SSL",
        environment == "production",
    )

    if (
        require_ssl
        and storage_backend
        in {
            "postgres",
            "postgresql",
        }
    ):
        lowered_url = (
            database_url
            or ""
        ).lower()

        if (
            "sslmode=require"
            not in lowered_url
            and "sslmode=verify-full"
            not in lowered_url
            and "sslmode=verify-ca"
            not in lowered_url
        ):
            raise RuntimeError(
                "Production PostgreSQL requires "
                "an SSL-enabled database URL."
            )

    default_web_origins = (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )

    web_origins = _read_origins(
        "AEGIS_WEB_ORIGINS",
        default_web_origins,
    )

    cors_origins = _read_origins(
        "AEGIS_CORS_ORIGINS",
        web_origins,
    )

    return AEGISSettings(
        environment=environment,

        api_version=_read_string(
            "AEGIS_API_VERSION",
            "0.7.0",
        ),

        storage_backend=storage_backend,

        database_url=database_url,

        auto_migrate=auto_migrate,

        web_origins=web_origins,

        cors_origins=cors_origins,

        session_ttl_seconds=_read_int(
            "AEGIS_SESSION_TTL",
            15 * 60,
            minimum=60,
        ),

        postgres_pool_min_size=_read_int(
            "AEGIS_POSTGRES_POOL_MIN_SIZE",
            0,
            minimum=0,
        ),

        postgres_pool_max_size=_read_int(
            "AEGIS_POSTGRES_POOL_MAX_SIZE",
            4,
            minimum=1,
        ),

        postgres_pool_timeout=_read_float(
            "AEGIS_POSTGRES_POOL_TIMEOUT",
            10.0,
            minimum=0.1,
        ),

        postgres_pool_max_idle=_read_float(
            "AEGIS_POSTGRES_POOL_MAX_IDLE",
            30.0,
            minimum=1.0,
        ),

        postgres_pool_max_lifetime=_read_float(
            "AEGIS_POSTGRES_POOL_MAX_LIFETIME",
            300.0,
            minimum=30.0,
        ),

        postgres_pool_reconnect_timeout=_read_float(
            "AEGIS_POSTGRES_POOL_RECONNECT_TIMEOUT",
            30.0,
            minimum=1.0,
        ),

        postgres_pool_max_waiting=_read_int(
            "AEGIS_POSTGRES_POOL_MAX_WAITING",
            20,
            minimum=0,
        ),

        postgres_require_ssl=require_ssl,

        root_certificate_path=Path(
            _read_string(
                "AEGIS_ROOT_CERTIFICATE_PATH",
                str(
                    PROJECT_ROOT
                    / "pki"
                    / "root"
                    / "root-cert.pem"
                ),
            )
        ),

        credential_database_path=Path(
            _read_string(
                "AEGIS_CREDENTIAL_DATABASE_PATH",
                str(
                    PROJECT_ROOT
                    / "transparency"
                    / "credentials.sqlite3"
                ),
            )
        ),

        administrator_database_path=Path(
            _read_string(
                "AEGIS_ADMIN_DATABASE_PATH",
                str(
                    PROJECT_ROOT
                    / "transparency"
                    / "administrators.sqlite3"
                ),
            )
        ),

        administrator_audit_path=Path(
            _read_string(
                "AEGIS_ADMIN_AUDIT_PATH",
                str(
                    PROJECT_ROOT
                    / "transparency"
                    / "admin_audit.jsonl"
                ),
            )
        ),

        upload_max_bytes=_read_int(
            "AEGIS_UPLOAD_MAX_BYTES",
            25 * 1024 * 1024,
            minimum=1,
        ),
    )


settings = load_settings()