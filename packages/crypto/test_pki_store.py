from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from packages.crypto.pki import (
    build_root_certificate,
    generate_ed25519_keypair,
)
from packages.crypto.pki_store import (
    PKIRecordExistsError,
    PKIStoreError,
    load_certificate,
    load_private_key,
    save_certificate,
    save_private_key,
)
from packages.crypto.providers.keystore import (
    InvalidPasswordError,
)


def test_certificate_round_trip(tmp_path: Path):
    private_key = generate_ed25519_keypair()

    certificate = build_root_certificate(
        private_key,
        common_name="AEGIS Test Root CA",
        organization="AEGIS Test",
    )

    certificate_path = (
        tmp_path / "root-cert.pem"
    )

    save_certificate(
        certificate,
        certificate_path,
    )

    loaded = load_certificate(
        certificate_path,
    )

    assert loaded.subject == certificate.subject
    assert loaded.issuer == certificate.issuer
    assert loaded.serial_number == certificate.serial_number
    assert loaded.public_key().public_bytes_raw() == (
        certificate.public_key().public_bytes_raw()
    )


def test_private_key_round_trip(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()

    key_path = (
        tmp_path / "root-key.json"
    )

    key_id = save_private_key(
        private_key,
        key_path,
        "development-password",
    )

    loaded = load_private_key(
        key_path,
        "development-password",
    )

    assert key_id == (
        __import__(
            "hashlib"
        ).sha256(
            private_key.public_key().public_bytes_raw()
        ).hexdigest()[:16]
    )

    assert (
        loaded.public_key().public_bytes_raw()
        == private_key.public_key().public_bytes_raw()
    )


def test_wrong_password_is_rejected(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()

    key_path = (
        tmp_path / "root-key.json"
    )

    save_private_key(
        private_key,
        key_path,
        "correct-password",
    )

    with pytest.raises(InvalidPasswordError):
        load_private_key(
            key_path,
            "wrong-password",
        )


def test_key_record_cannot_be_overwritten(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()

    key_path = (
        tmp_path / "root-key.json"
    )

    save_private_key(
        private_key,
        key_path,
        "password",
    )

    with pytest.raises(PKIRecordExistsError):
        save_private_key(
            private_key,
            key_path,
            "password",
        )


def test_certificate_cannot_be_overwritten(tmp_path: Path):
    private_key = generate_ed25519_keypair()

    certificate = build_root_certificate(
        private_key,
    )

    certificate_path = (
        tmp_path / "root-cert.pem"
    )

    save_certificate(
        certificate,
        certificate_path,
    )

    with pytest.raises(PKIRecordExistsError):
        save_certificate(
            certificate,
            certificate_path,
        )


def test_corrupted_key_record_is_rejected(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()

    key_path = (
        tmp_path / "root-key.json"
    )

    save_private_key(
        private_key,
        key_path,
        "password",
    )

    key_path.write_text(
        '{"format_version": 999}',
        encoding="utf-8",
    )

    with pytest.raises(PKIStoreError):
        load_private_key(
            key_path,
            "password",
        )


def test_corrupted_certificate_is_rejected(tmp_path: Path):
    certificate_path = (
        tmp_path / "root-cert.pem"
    )

    certificate_path.write_text(
        "NOT A CERTIFICATE",
        encoding="utf-8",
    )

    with pytest.raises(PKIStoreError):
        load_certificate(
            certificate_path,
        )


def test_stored_private_key_is_not_plaintext(tmp_path: Path):
    private_key = Ed25519PrivateKey.generate()

    key_path = (
        tmp_path / "root-key.json"
    )

    save_private_key(
        private_key,
        key_path,
        "password",
    )

    stored_text = key_path.read_text(
        encoding="utf-8"
    )

    raw_private_key = private_key.private_bytes(
        encoding=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["Encoding"],
        ).Encoding.Raw,
        format=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["PrivateFormat"],
        ).PrivateFormat.Raw,
        encryption_algorithm=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["NoEncryption"],
        ).NoEncryption(),
    )

    assert raw_private_key.hex() not in stored_text