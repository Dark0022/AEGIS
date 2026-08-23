"""Bootstrap an AEGIS Official Communications Publisher account."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from dotenv import dotenv_values


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from packages.trust.publisher_auth import (
    PublisherRole,
    PublisherRegistry,
)


def load_database_url() -> str:
    """Load the PostgreSQL URL from the local environment file."""

    env_path = (
        PROJECT_ROOT
        / ".env.local"
    )

    values = dotenv_values(
        env_path
    )

    database_url = (
        values.get("AEGIS_DATABASE_URL")
        or values.get("DATABASE_URL")
    )

    if not database_url:
        raise RuntimeError(
            "DATABASE_URL or AEGIS_DATABASE_URL "
            "was not found in .env.local."
        )

    return database_url


def choose_role() -> str:
    """Prompt for a supported publisher role."""

    print()
    print("Publisher roles:")
    print()
    print("  1. PUBLISHER")
    print("  2. APPROVER")
    print("  3. NOTICE_ADMIN")
    print()

    while True:
        choice = input(
            "Select role [1-3]: "
        ).strip()

        roles = {
            "1": PublisherRole.PUBLISHER,
            "2": PublisherRole.APPROVER,
            "3": PublisherRole.NOTICE_ADMIN,
        }

        role = roles.get(choice)

        if role is not None:
            return role

        print(
            "Invalid selection. "
            "Choose 1, 2, or 3."
        )


def main() -> None:
    print("=" * 72)
    print("AEGIS Official Communications Publisher Bootstrap")
    print("=" * 72)
    print()

    publisher_id = input(
        "Publisher ID: "
    ).strip()

    if not publisher_id:
        raise SystemExit(
            "Publisher ID is required."
        )

    username = input(
        "Publisher username: "
    ).strip()

    if not username:
        raise SystemExit(
            "Publisher username is required."
        )

    display_name = input(
        "Publisher display name: "
    ).strip()

    if not display_name:
        raise SystemExit(
            "Publisher display name is required."
        )

    organization = input(
        "Organization: "
    ).strip()

    if not organization:
        raise SystemExit(
            "Organization is required."
        )

    role = choose_role()

    print()
    print(
        f"Selected role: {role}"
    )
    print()

    password = getpass.getpass(
        "Publisher password: "
    )

    confirmation = getpass.getpass(
        "Confirm publisher password: "
    )

    if password != confirmation:
        raise SystemExit(
            "Passwords do not match."
        )

    if len(password) < 12:
        raise SystemExit(
            "Publisher password must be at least 12 characters."
        )

    print()
    print("Connecting to Neon...")

    try:
        import psycopg
    except ImportError as exc:
        raise SystemExit(
            "psycopg is required."
        ) from exc

    database_url = load_database_url()

    registry = PublisherRegistry(
        database_url,
        psycopg_module=psycopg,
    )

    try:
        publisher = registry.register(
            publisher_id=publisher_id,
            username=username,
            display_name=display_name,
            role=role,
            organization=organization,
            password=password,
        )

    except ValueError as exc:
        print()
        print(
            "Publisher registration refused:"
        )
        print(
            f"  {exc}"
        )
        print()
        print(
            "The existing publisher registry "
            "was not modified."
        )
        raise SystemExit(1)

    print()
    print("=" * 72)
    print("PUBLISHER REGISTERED SUCCESSFULLY")
    print("=" * 72)
    print()

    print(
        f"Publisher ID:  {publisher.publisher_id}"
    )
    print(
        f"Username:      {publisher.username}"
    )
    print(
        f"Display name:  {publisher.display_name}"
    )
    print(
        f"Organization:  {publisher.organization}"
    )
    print(
        f"Role:          {publisher.role}"
    )
    print(
        f"Enabled:       {publisher.enabled}"
    )
    print(
        f"Created at:    {publisher.created_at}"
    )
    print()

    print(
        "The publisher account is now stored in Neon."
    )


if __name__ == "__main__":
    main()