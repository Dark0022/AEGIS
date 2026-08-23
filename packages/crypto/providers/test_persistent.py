from pathlib import Path

import pytest

from packages.crypto.providers.keystore import (
    InvalidPasswordError,
)
from packages.crypto.providers.persistent import (
    PersistentSoftwareSigner,
    PersistentSignerError,
)
from packages.crypto.verification import verify_signature


def test_create_persist_reload_sign_and_verify(tmp_path: Path):
    key_path = tmp_path / "aegis-key.json"
    password = "correct-development-password"

    signer = PersistentSoftwareSigner.create(
        key_path,
        password,
    )

    data = b"AEGIS official communication"
    signature = signer.sign(data)

    assert key_path.exists()

    key_id_before = signer.key_id()
    public_key_before = signer.public_key()

    reloaded = PersistentSoftwareSigner.load(
        key_path,
        password,
    )

    assert reloaded.key_id() == key_id_before
    assert reloaded.public_key() == public_key_before

    assert verify_signature(
        data=data,
        signature=signature,
        public_key=reloaded.public_key(),
    )


def test_wrong_password_fails(tmp_path: Path):
    key_path = tmp_path / "aegis-key.json"

    PersistentSoftwareSigner.create(
        key_path,
        "correct-password",
    )

    with pytest.raises(InvalidPasswordError):
        PersistentSoftwareSigner.load(
            key_path,
            "wrong-password",
        )


def test_corrupted_key_record_fails(tmp_path: Path):
    key_path = tmp_path / "aegis-key.json"

    PersistentSoftwareSigner.create(
        key_path,
        "correct-password",
    )

    key_path.write_text(
        '{"this": "is not a valid aegis key record"}',
        encoding="utf-8",
    )

    with pytest.raises(PersistentSignerError):
        PersistentSoftwareSigner.load(
            key_path,
            "correct-password",
        )


def test_existing_key_is_not_overwritten(tmp_path: Path):
    key_path = tmp_path / "aegis-key.json"

    PersistentSoftwareSigner.create(
        key_path,
        "correct-password",
    )

    with pytest.raises(FileExistsError):
        PersistentSoftwareSigner.create(
            key_path,
            "another-password",
        )


def test_modified_content_fails_after_reload(tmp_path: Path):
    key_path = tmp_path / "aegis-key.json"

    signer = PersistentSoftwareSigner.create(
        key_path,
        "correct-password",
    )

    original = b"Original AEGIS message"
    modified = b"Modified AEGIS message"

    signature = signer.sign(original)

    reloaded = PersistentSoftwareSigner.load(
        key_path,
        "correct-password",
    )

    assert verify_signature(
        original,
        signature,
        reloaded.public_key(),
    )

    assert not verify_signature(
        modified,
        signature,
        reloaded.public_key(),
    )