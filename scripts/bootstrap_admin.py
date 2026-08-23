"""Create the first persistent AEGIS administrator."""

from __future__ import annotations

import getpass
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from packages.trust.admin_auth import (
    AdminRole,
    PersistentAdminRegistry,
)


DATABASE_PATH = (
    PROJECT_ROOT
    / "transparency"
    / "administrators.sqlite3"
)


def main() -> None:
    print("=" * 64)
    print("AEGIS Administrator Bootstrap")
    print("=" * 64)
    print()

    username = input(
        "Administrator username: "
    ).strip()

    display_name = input(
        "Administrator display name: "
    ).strip()

    password = getpass.getpass(
        "Administrator password: "
    )

    confirmation = getpass.getpass(
        "Confirm administrator password: "
    )

    if password != confirmation:
        raise SystemExit(
            "Passwords do not match."
        )

    registry = PersistentAdminRegistry(
        DATABASE_PATH
    )

    administrator = registry.register(
        administrator_id=f"admin-{username}",
        username=username,
        display_name=display_name,
        role=AdminRole.ADMIN,
        password=password,
    )

    print()
    print(
        "Administrator created successfully."
    )
    print(
        f"  ID:          {administrator.administrator_id}"
    )
    print(
        f"  Username:    {administrator.username}"
    )
    print(
        f"  Display:     {administrator.display_name}"
    )
    print(
        f"  Role:        {administrator.role}"
    )
    print(
        f"  Database:    {DATABASE_PATH}"
    )


if __name__ == "__main__":
    main()