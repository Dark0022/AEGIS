"""Create a development AEGIS VIEWER administrator."""

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
    print("AEGIS VIEWER Administrator Bootstrap")
    print("=" * 64)
    print()

    username = input(
        "Viewer username: "
    ).strip()

    display_name = input(
        "Viewer display name: "
    ).strip()

    password = getpass.getpass(
        "Viewer password: "
    )

    confirmation = getpass.getpass(
        "Confirm viewer password: "
    )

    if password != confirmation:
        raise SystemExit(
            "Passwords do not match."
        )

    registry = PersistentAdminRegistry(
        DATABASE_PATH
    )

    administrator = registry.register(
        administrator_id=f"viewer-{username}",
        username=username,
        display_name=display_name,
        role=AdminRole.VIEWER,
        password=password,
    )

    print()
    print(
        "VIEWER administrator created successfully."
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