"""Rotate the AEGIS Emergency Communications Issuer credential."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from packages.crypto.chain import (
    validate_issuer_chain,
)
from packages.crypto.pki import (
    build_issuer_certificate,
    generate_ed25519_keypair,
)
from packages.crypto.pki_store import (
    load_certificate,
    load_private_key,
    save_certificate,
    save_private_key,
)


def private_pki_root() -> Path:
    configured = os.environ.get(
        "AEGIS_PRIVATE_PKI_ROOT"
    )

    if configured:
        return Path(
            configured
        ).expanduser().resolve()

    return (
        PROJECT_ROOT.parent
        / "AEGIS-SECRETS"
        / "pki"
    )


PRIVATE_PKI_ROOT = (
    private_pki_root()
)


ROOT_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "root"
    / "root-cert.pem"
)

INSTITUTION_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "institutions"
    / "soa-university"
    / "ca-cert.pem"
)

INSTITUTION_KEY_PATH = (
    PRIVATE_PKI_ROOT
    / "institutions"
    / "soa-university"
    / "ca-key.json"
)

NEW_ISSUER_DIR = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v4"
)

NEW_ISSUER_CERT_PATH = (
    NEW_ISSUER_DIR
    / "issuer-cert.pem"
)

NEW_ISSUER_KEY_PATH = (
    PRIVATE_PKI_ROOT
    / "issuers"
    / "emergency-communications-v4"
    / "issuer-key.json"
)


def get_new_password() -> str:
    """Prompt for a new issuer password and confirm it."""

    while True:
        password = getpass.getpass(
            "Enter password for the NEW Emergency Communications Issuer v4: "
        )

        if not password:
            print(
                "Password cannot be empty."
            )
            continue

        confirmation = getpass.getpass(
            "Confirm password for the NEW Emergency Communications Issuer v4: "
        )

        if password != confirmation:
            print(
                "Passwords do not match. Try again."
            )
            continue

        return password


def main() -> None:
    print("=" * 64)
    print(
        "AEGIS Emergency Communications Issuer v4 Rotation"
    )
    print("=" * 64)
    print()

    required_files = [
        ROOT_CERT_PATH,
        INSTITUTION_CERT_PATH,
        INSTITUTION_KEY_PATH,
    ]

    missing = [
        path
        for path in required_files
        if not path.is_file()
    ]

    if missing:
        print(
            "Required PKI files are missing:"
        )

        for path in missing:
            print(
                f"  {path}"
            )

        raise SystemExit(1)

    if NEW_ISSUER_DIR.exists():
        print(
            "Refusing to overwrite an existing issuer directory:"
        )
        print(
            f"  {NEW_ISSUER_DIR}"
        )
        raise SystemExit(1)

    NEW_ISSUER_KEY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    institution_password = getpass.getpass(
        "Enter the SOA University CA password: "
    )

    new_issuer_password = (
        get_new_password()
    )

    print()
    print(
        "Loading AEGIS Root CA certificate..."
    )

    root_certificate = load_certificate(
        ROOT_CERT_PATH
    )

    print(
        "Loading SOA University CA certificate..."
    )

    institution_certificate = (
        load_certificate(
            INSTITUTION_CERT_PATH
        )
    )

    print(
        "Loading SOA University CA private key..."
    )

    institution_private_key = (
        load_private_key(
            INSTITUTION_KEY_PATH,
            institution_password,
        )
    )

    print()
    print(
        "Generating new Emergency Communications Issuer v4..."
    )

    issuer_private_key = (
        generate_ed25519_keypair()
    )

    issuer_certificate = (
        build_issuer_certificate(
            issuer_private_key,
            institution_private_key,
            institution_certificate,
            common_name="Emergency Communications Issuer",
            organization="SOA University",
            organizational_unit=(
                "Emergency Management Office"
            ),
        )
    )

    print(
        "Validating new issuer trust chain..."
    )

    validate_issuer_chain(
        issuer_certificate,
        institution_certificate,
        root_certificate,
    )

    print(
        "  Root CA -> Institution CA -> "
        "Issuer v4: VALID"
    )

    print()
    print(
        "Saving encrypted issuer key..."
    )

    issuer_key_id = save_private_key(
        issuer_private_key,
        NEW_ISSUER_KEY_PATH,
        new_issuer_password,
    )

    print(
        "Saving issuer certificate..."
    )

    save_certificate(
        issuer_certificate,
        NEW_ISSUER_CERT_PATH,
    )

    print()
    print("=" * 64)
    print(
        "Issuer v4 rotation completed."
    )
    print("=" * 64)
    print()

    print(
        f"Issuer key ID:  {issuer_key_id}"
    )
    print(
        f"Certificate:    {NEW_ISSUER_CERT_PATH}"
    )
    print(
        f"Encrypted key:  {NEW_ISSUER_KEY_PATH}"
    )

    print()
    print(
        "Certificate profile:"
    )
    print(
        "  CA:                  FALSE"
    )
    print(
        "  digitalSignature:    TRUE"
    )
    print(
        "  C2PA claim signing:  TRUE"
    )
    print(
        "  document signing:    TRUE"
    )
    print()

    print(
        "The issuer chains to the existing AEGIS Root "
        "and SOA University CA."
    )
    print()

    print(
        "The previous issuer credentials were not modified."
    )
    print(
        "Use Issuer v4 for all new AEGIS content."
    )


if __name__ == "__main__":
    main()