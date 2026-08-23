"""Create a fresh C2PA asset signed by AEGIS Issuer v8."""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from packages.crypto.providers.pki_signer import (
    PKISigner,
)
from packages.provenance.c2pa_asset import (
    add_created_action,
    create_manifest,
    detect_asset_format,
    sign_asset,
)
from packages.provenance.c2pa_signer import (
    AEGISC2PASigner,
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


SOURCE_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice.png"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "datasets"
    / "synthetic"
    / "official_notice_v8_signed.png"
)

ISSUER_KEY_PATH = (
    PRIVATE_PKI_ROOT
    / "issuers"
    / "emergency-communications-v8"
    / "issuer-key.json"
)

ISSUER_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v8"
    / "issuer-cert.pem"
)

INSTITUTION_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "institutions"
    / "soa-university"
    / "ca-cert.pem"
)


def main() -> None:
    print("=" * 72)
    print(
        "AEGIS C2PA Demo Asset — Issuer v8"
    )
    print("=" * 72)
    print()

    required = (
        SOURCE_PATH,
        ISSUER_KEY_PATH,
        ISSUER_CERT_PATH,
        INSTITUTION_CERT_PATH,
    )

    missing = [
        path
        for path in required
        if not path.is_file()
    ]

    if missing:
        print(
            "Missing required v8 signing artifacts:"
        )

        for path in missing:
            print(
                f"  {path}"
            )

        raise SystemExit(1)

    if OUTPUT_PATH.exists():
        print(
            "Refusing to overwrite existing output:"
        )

        print(
            f"  {OUTPUT_PATH}"
        )

        print(
            "Delete the file manually if you intentionally "
            "want to regenerate it."
        )

        raise SystemExit(1)

    password = getpass.getpass(
        "Enter the v8 issuer password: "
    )

    aegis_signer = PKISigner.load(
        ISSUER_KEY_PATH,
        password,
    )

    c2pa_signer = AEGISC2PASigner(
        aegis_signer,
        issuer_certificate_path=(
            ISSUER_CERT_PATH
        ),
        institution_certificate_path=(
            INSTITUTION_CERT_PATH
        ),
    )

    print(
        "Creating C2PA manifest..."
    )

    asset_format = detect_asset_format(
        SOURCE_PATH
    )

    builder = create_manifest(
        claim_generator="AEGIS/0.1",
        asset_format=asset_format,
    )

    add_created_action(
        builder
    )

    print(
        "Signing asset..."
    )

    sign_asset(
        builder,
        source_path=SOURCE_PATH,
        destination_path=OUTPUT_PATH,
        signer=c2pa_signer,
    )

    print()
    print("=" * 72)
    print(
        "V8 SIGNED DEMO ASSET CREATED"
    )
    print("=" * 72)
    print()

    print(
        f"Output:    {OUTPUT_PATH}"
    )

    print(
        f"Signer ID: {aegis_signer.key_id()}"
    )


if __name__ == "__main__":
    main()