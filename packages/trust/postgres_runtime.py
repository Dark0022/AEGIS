"""AEGIS PostgreSQL runtime connection management.

Provides one lazily-created, bounded connection pool per PostgreSQL URL.

Normal application queries use this pool. Database migrations are handled
separately by packages.trust.migrations and are never run implicitly when a
storage class is instantiated.
"""

from __future__ import annotations

from threading import Lock

try:
    import psycopg
    from psycopg.rows import tuple_row
    from psycopg_pool import ConnectionPool

except ImportError:  # pragma: no cover
    psycopg = None
    tuple_row = None
    ConnectionPool = None


class PostgreSQLRuntimeError(RuntimeError):
    """Raised when PostgreSQL runtime support is unavailable."""


class PostgreSQLRuntime:
    """Lazy, bounded PostgreSQL connection pool."""

    DEFAULT_MIN_SIZE = 0
    DEFAULT_MAX_SIZE = 4
    DEFAULT_TIMEOUT = 10.0
    DEFAULT_MAX_IDLE = 30.0
    DEFAULT_MAX_LIFETIME = 300.0
    DEFAULT_RECONNECT_TIMEOUT = 30.0
    DEFAULT_MAX_WAITING = 20

    _instances: dict[
        str,
        "PostgreSQLRuntime",
    ] = {}

    _instances_lock = Lock()

    def __init__(
        self,
        database_url: str,
        *,
        min_size: int = DEFAULT_MIN_SIZE,
        max_size: int = DEFAULT_MAX_SIZE,
        timeout: float = DEFAULT_TIMEOUT,
        max_idle: float = DEFAULT_MAX_IDLE,
        max_lifetime: float = DEFAULT_MAX_LIFETIME,
        reconnect_timeout: float = DEFAULT_RECONNECT_TIMEOUT,
        max_waiting: int = DEFAULT_MAX_WAITING,
    ) -> None:
        if psycopg is None:
            raise PostgreSQLRuntimeError(
                "PostgreSQL support requires "
                "'psycopg[binary,pool]'."
            )

        if ConnectionPool is None:
            raise PostgreSQLRuntimeError(
                "PostgreSQL pool support is unavailable. "
                "Install 'psycopg[binary,pool]'."
            )

        database_url = database_url.strip()

        if not database_url:
            raise ValueError(
                "PostgreSQL database URL must not be empty."
            )

        if min_size < 0:
            raise ValueError(
                "PostgreSQL pool min_size must be >= 0."
            )

        if max_size < 1:
            raise ValueError(
                "PostgreSQL pool max_size must be >= 1."
            )

        if min_size > max_size:
            raise ValueError(
                "PostgreSQL pool min_size cannot exceed max_size."
            )

        if timeout <= 0:
            raise ValueError(
                "PostgreSQL pool timeout must be > 0."
            )

        if max_waiting < 0:
            raise ValueError(
                "PostgreSQL pool max_waiting must be >= 0."
            )

        self.database_url = database_url

        self._pool = ConnectionPool(
            conninfo=database_url,
            min_size=min_size,
            max_size=max_size,
            timeout=timeout,
            max_idle=max_idle,
            max_lifetime=max_lifetime,
            reconnect_timeout=reconnect_timeout,
            max_waiting=max_waiting,
            open=False,
            kwargs={
                "row_factory": tuple_row,
            },
        )

        self._opened = False
        self._closed = False
        self._pool_lock = Lock()

    @classmethod
    def for_url(
        cls,
        database_url: str,
    ) -> "PostgreSQLRuntime":
        """Return the shared runtime for a database URL."""

        key = database_url.strip()

        if not key:
            raise ValueError(
                "PostgreSQL database URL must not be empty."
            )

        with cls._instances_lock:
            existing = cls._instances.get(
                key
            )

            if existing is not None:
                if not existing.closed:
                    return existing

                cls._instances.pop(
                    key,
                    None,
                )

            runtime = cls(
                key
            )

            cls._instances[
                key
            ] = runtime

            return runtime

    @property
    def closed(self) -> bool:
        """Return whether the runtime has been closed."""

        return self._closed

    def _ensure_open(
        self,
    ) -> None:
        """Open the pool lazily and exactly once."""

        if self._closed:
            raise PostgreSQLRuntimeError(
                "PostgreSQL connection pool is closed."
            )

        if self._opened:
            return

        with self._pool_lock:
            if self._closed:
                raise PostgreSQLRuntimeError(
                    "PostgreSQL connection pool is closed."
                )

            if self._opened:
                return

            self._pool.open(
                wait=True
            )

            self._opened = True

    def connection(self):
        """Return a pooled PostgreSQL connection context manager."""

        self._ensure_open()

        return self._pool.connection()

    def check(
        self,
    ) -> tuple[str, str]:
        """Check PostgreSQL connectivity."""

        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT
                    current_database(),
                    current_user
                """
            ).fetchone()

        if row is None:
            raise PostgreSQLRuntimeError(
                "PostgreSQL connectivity check returned no result."
            )

        return (
            str(row[0]),
            str(row[1]),
        )

    @property
    def min_size(self) -> int:
        return int(
            self._pool.min_size
        )

    @property
    def max_size(self) -> int:
        return int(
            self._pool.max_size
        )

    def close(
        self,
    ) -> None:
        """Close the pool."""

        with self._pool_lock:
            if self._closed:
                return

            self._closed = True

            if self._opened:
                self._pool.close()

    @classmethod
    def clear_for_tests(
        cls,
    ) -> None:
        """Close and remove all cached runtimes."""

        with cls._instances_lock:
            runtimes = list(
                cls._instances.values()
            )

            cls._instances.clear()

        for runtime in runtimes:
            runtime.close()


def get_postgres_runtime(
    database_url: str,
) -> PostgreSQLRuntime:
    """Return the shared runtime for a PostgreSQL URL."""

    return PostgreSQLRuntime.for_url(
        database_url
    )


def check_postgres_connection(
    database_url: str,
) -> tuple[str, str]:
    """Check a PostgreSQL connection."""

    return get_postgres_runtime(
        database_url
    ).check()