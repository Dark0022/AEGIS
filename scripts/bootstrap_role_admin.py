"""Create a persistent AEGIS administrator with a selected role."""

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


VALID_ROLES = {
    "VIEWER": AdminRole.VIEWER,
    "AUDITOR": AdminRole.AUDITOR,
    "OPERATOR": AdminRole.OPERATOR,
    "ADMIN": AdminRole.ADMIN,
}


def main() -> None:
    print("=" * 64)
    print("AEGIS Administrator Bootstrap")
    print("=" * 64)
    print()

    username = input(
        "Username: "
    ).strip()

    display_name = input(
        "Display name: "
    ).strip()

    print()
    print(
        "Available roles:"
    )

    for role in VALID_ROLES:
        print(
            f"  {role}"
        )

    print()

    role_input = input(
        "Role: "
    ).strip().upper()

    role = VALID_ROLES.get(
        role_input
    )

    if role is None:
        raise SystemExit(
            f"Unsupported role: {role_input}"
        )

    password = getpass.getpass(
        "Password: "
    )

    confirmation = getpass.getpass(
        "Confirm password: "
    )

    if password != confirmation:
        raise SystemExit(
            "Passwords do not match."
        )

    registry = PersistentAdminRegistry(
        DATABASE_PATH
    )

    try:
        administrator = registry.register(
            administrator_id=(
                f"{role.lower()}-{username}"
            ),
            username=username,
            display_name=display_name,
            role=role,
            password=password,
        )
    except ValueError as exc:
        raise SystemExit(
            str(exc)
        ) from exc

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