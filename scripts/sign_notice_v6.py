"""Create a fresh C2PA asset signed by AEGIS Issuer v6."""

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
    / "official_notice_v6_signed.png"
)

ISSUER_KEY_PATH = (
    PRIVATE_PKI_ROOT
    / "issuers"
    / "emergency-communications-v6"
    / "issuer-key.json"
)

ISSUER_CERT_PATH = (
    PROJECT_ROOT
    / "pki"
    / "issuers"
    / "emergency-communications-v6"
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
        raise SystemExit(
            "Missing required v6 signing artifacts:\n"
            + "\n".join(
                f"  {path}"
                for path in missing
            )
        )

    if OUTPUT_PATH.exists():
        OUTPUT_PATH.unlink()

    print(
        "Enter the NEW Emergency Communications Issuer v6 password:"
    )

    password = getpass.getpass()

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

    sign_asset(
        builder,
        source_path=SOURCE_PATH,
        destination_path=OUTPUT_PATH,
        signer=c2pa_signer,
    )

    print()
    print(
        "Created v6-signed asset:"
    )
    print(
        f"  {OUTPUT_PATH}"
    )
    print()
    print(
        "Signer key ID:",
        aegis_signer.key_id(),
    )


if __name__ == "__main__":
    main()