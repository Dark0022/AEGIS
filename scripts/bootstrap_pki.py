"""Bootstrap the AEGIS development PKI hierarchy."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from packages.crypto.chain import validate_issuer_chain
from packages.crypto.pki import (
    build_institution_ca_certificate,
    build_issuer_certificate,
    build_root_certificate,
    generate_ed25519_keypair,
)
from packages.crypto.pki_store import (
    save_certificate,
    save_private_key,
)


def private_pki_root() -> Path:
    """Return the local-only private PKI root directory."""

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


PKI_ROOT = PROJECT_ROOT / "pki"
PRIVATE_PKI_ROOT = private_pki_root()

ROOT_DIR = PKI_ROOT / "root"
INSTITUTION_DIR = (
    PKI_ROOT
    / "institutions"
    / "soa-university"
)
ISSUER_DIR = (
    PKI_ROOT
    / "issuers"
    / "emergency-communications"
)

PRIVATE_ROOT_DIR = (
    PRIVATE_PKI_ROOT / "root"
)
PRIVATE_INSTITUTION_DIR = (
    PRIVATE_PKI_ROOT
    / "institutions"
    / "soa-university"
)
PRIVATE_ISSUER_DIR = (
    PRIVATE_PKI_ROOT
    / "issuers"
    / "emergency-communications"
)

ROOT_CERT_PATH = (
    ROOT_DIR / "root-cert.pem"
)
ROOT_KEY_PATH = (
    PRIVATE_ROOT_DIR
    / "root-key.json"
)

INSTITUTION_CERT_PATH = (
    INSTITUTION_DIR / "ca-cert.pem"
)
INSTITUTION_KEY_PATH = (
    PRIVATE_INSTITUTION_DIR
    / "ca-key.json"
)

ISSUER_CERT_PATH = (
    ISSUER_DIR / "issuer-cert.pem"
)
ISSUER_KEY_PATH = (
    PRIVATE_ISSUER_DIR
    / "issuer-key.json"
)


def get_new_password(
    label: str,
) -> str:
    """Prompt for and confirm a new password."""

    while True:
        password = getpass.getpass(
            f"Enter password for {label}: "
        )

        if not password:
            print(
                "Password cannot be empty."
            )
            continue

        confirmation = getpass.getpass(
            f"Confirm password for {label}: "
        )

        if password != confirmation:
            print(
                "Passwords do not match. Try again."
            )
            continue

        return password


def ensure_target_does_not_exist(
    paths: list[Path],
) -> None:
    """Abort bootstrap rather than overwriting existing PKI material."""

    existing = [
        path
        for path in paths
        if path.exists()
    ]

    if not existing:
        return

    print(
        "PKI bootstrap aborted because the following "
        "artifacts already exist:"
    )

    for path in existing:
        print(
            f"  {path}"
        )

    print()
    print(
        "No existing PKI material was modified."
    )

    raise SystemExit(1)


def main() -> None:
    print("=" * 64)
    print(
        "AEGIS Development PKI Bootstrap"
    )
    print("=" * 64)
    print()

    print("This will create:")
    print("  AEGIS Root CA")
    print("      -> SOA University CA")
    print(
        "          -> Emergency Communications Issuer"
    )
    print()

    print(
        "Public certificates will be stored under:"
    )
    print(
        f"  {PKI_ROOT}"
    )
    print()

    print(
        "Encrypted private keys will be stored under:"
    )
    print(
        f"  {PRIVATE_PKI_ROOT}"
    )
    print()

    ensure_target_does_not_exist(
        [
            ROOT_CERT_PATH,
            ROOT_KEY_PATH,
            INSTITUTION_CERT_PATH,
            INSTITUTION_KEY_PATH,
            ISSUER_CERT_PATH,
            ISSUER_KEY_PATH,
        ]
    )

    ROOT_KEY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    INSTITUTION_KEY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    ISSUER_KEY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        "Passwords are entered interactively and are not "
        "stored in this script."
    )
    print()

    root_password = get_new_password(
        "AEGIS Root CA"
    )

    institution_password = get_new_password(
        "SOA University CA"
    )

    issuer_password = get_new_password(
        "Emergency Communications Issuer"
    )

    print()
    print(
        "Generating AEGIS Root CA..."
    )

    root_private_key = (
        generate_ed25519_keypair()
    )

    root_certificate = (
        build_root_certificate(
            root_private_key,
            common_name="AEGIS Root CA",
            organization="AEGIS",
        )
    )

    root_key_id = save_private_key(
        root_private_key,
        ROOT_KEY_PATH,
        root_password,
    )

    save_certificate(
        root_certificate,
        ROOT_CERT_PATH,
    )

    print(
        f"  Root key ID: {root_key_id}"
    )
    print(
        f"  Certificate: {ROOT_CERT_PATH}"
    )
    print(
        f"  Encrypted key: {ROOT_KEY_PATH}"
    )

    print()
    print(
        "Generating SOA University CA..."
    )

    institution_private_key = (
        generate_ed25519_keypair()
    )

    institution_certificate = (
        build_institution_ca_certificate(
            institution_private_key,
            root_private_key,
            root_certificate,
            common_name="SOA University CA",
            organization="SOA University",
        )
    )

    institution_key_id = save_private_key(
        institution_private_key,
        INSTITUTION_KEY_PATH,
        institution_password,
    )

    save_certificate(
        institution_certificate,
        INSTITUTION_CERT_PATH,
    )

    print(
        f"  Institution key ID: {institution_key_id}"
    )
    print(
        f"  Certificate: {INSTITUTION_CERT_PATH}"
    )
    print(
        f"  Encrypted key: {INSTITUTION_KEY_PATH}"
    )

    print()
    print(
        "Generating Emergency Communications Issuer..."
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

    issuer_key_id = save_private_key(
        issuer_private_key,
        ISSUER_KEY_PATH,
        issuer_password,
    )

    save_certificate(
        issuer_certificate,
        ISSUER_CERT_PATH,
    )

    print(
        f"  Issuer key ID: {issuer_key_id}"
    )
    print(
        f"  Certificate: {ISSUER_CERT_PATH}"
    )
    print(
        f"  Encrypted key: {ISSUER_KEY_PATH}"
    )

    print()
    print(
        "Validating generated trust chain..."
    )

    validate_issuer_chain(
        issuer_certificate,
        institution_certificate,
        root_certificate,
    )

    print(
        "  Root CA -> Institution CA -> "
        "Issuer: VALID"
    )

    print()
    print("=" * 64)
    print(
        "AEGIS development PKI bootstrap completed."
    )
    print("=" * 64)
    print()

    print(
        "Trust hierarchy:"
    )
    print(
        "  AEGIS Root CA"
    )
    print(
        "      |"
    )
    print(
        "      +-- SOA University CA"
    )
    print(
        "              |"
    )
    print(
        "              +-- Emergency Communications Issuer"
    )
    print()

    print(
        "IMPORTANT: The generated private-key records "
        "contain encrypted key material."
    )
    print(
        "They are stored outside the application repository."
    )
    print(
        "They must not be committed to version control."
    )
    print()

    print(
        "The AEGIS Root CA private key must not be exposed "
        "to the web/API application."
    )


if __name__ == "__main__":
    main()