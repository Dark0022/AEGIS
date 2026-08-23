"""Persistent software-backed signer for AEGIS."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from ..signer import Signer
from .keystore import decrypt_private_key, encrypt_private_key
from .software import SoftwareSigner


class PersistentSignerError(Exception):
    """Base exception for persistent signer failures."""


class PersistentSoftwareSigner(Signer):
    """
    Development signer backed by an encrypted local keystore.

    The private key is never exposed through the public signer interface.
    """

    _FORMAT_VERSION = 1

    def __init__(
        self,
        signer: SoftwareSigner,
        *,
        key_path: Path,
    ) -> None:
        self._signer = signer
        self._key_path = key_path

    @classmethod
    def create(
        cls,
        key_path: str | Path,
        password: str,
    ) -> "PersistentSoftwareSigner":
        """
        Generate a new Ed25519 key and persist it in encrypted form.

        Existing key files are never overwritten.
        """
        path = Path(key_path)

        if path.exists():
            raise FileExistsError(
                f"Key file already exists: {path}"
            )

        signer = SoftwareSigner.generate()

        private_key_bytes = signer.export_private_key_material()

        salt, nonce, ciphertext = encrypt_private_key(
            private_key_bytes,
            password,
            associated_data=b"AEGIS-KEYSTORE-v1",
        )

        record = {
            "format_version": cls._FORMAT_VERSION,
            "key_id": signer.key_id(),
            "algorithm": "Ed25519",
            "kdf": {
                "name": "scrypt",
            },
            "encryption": {
                "name": "AES-256-GCM",
            },
            "public_key": _b64encode(
                signer.public_key()
            ),
            "salt": _b64encode(salt),
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }

        _write_json_atomically(
            path,
            record,
        )

        return cls(
            signer,
            key_path=path,
        )

    @classmethod
    def load(
        cls,
        key_path: str | Path,
        password: str,
    ) -> "PersistentSoftwareSigner":
        """Load an existing signer from an encrypted key record."""
        path = Path(key_path)

        if not path.is_file():
            raise FileNotFoundError(
                f"Key file not found: {path}"
            )

        try:
            with path.open(
                "r",
                encoding="utf-8",
            ) as file:
                record = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise PersistentSignerError(
                f"Unable to read key record: {path}"
            ) from exc

        _validate_record(
            record,
            cls._FORMAT_VERSION,
        )

        salt = _b64decode(
            record["salt"]
        )

        nonce = _b64decode(
            record["nonce"]
        )

        ciphertext = _b64decode(
            record["ciphertext"]
        )

        private_key_bytes = decrypt_private_key(
            ciphertext,
            password,
            salt,
            nonce,
            associated_data=b"AEGIS-KEYSTORE-v1",
        )

        try:
            private_key = Ed25519PrivateKey.from_private_bytes(
                private_key_bytes
            )
        finally:
            del private_key_bytes

        signer = SoftwareSigner.from_private_key(
            private_key
        )

        if signer.key_id() != record["key_id"]:
            raise PersistentSignerError(
                "Stored key ID does not match private key."
            )

        if (
            signer.public_key()
            != _b64decode(record["public_key"])
        ):
            raise PersistentSignerError(
                "Stored public key does not match private key."
            )

        return cls(
            signer,
            key_path=path,
        )

    def sign(
        self,
        data: bytes,
    ) -> bytes:
        """Sign data without exposing the private key."""
        return self._signer.sign(data)

    def public_key(self) -> bytes:
        """Return the public key."""
        return self._signer.public_key()

    def key_id(self) -> str:
        """Return the stable signing key identifier."""
        return self._signer.key_id()


def _b64encode(value: bytes) -> str:
    """Encode bytes as ASCII-safe Base64."""
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    """Decode Base64 text with validation."""
    try:
        return base64.b64decode(
            value.encode("ascii"),
            validate=True,
        )
    except (
        ValueError,
        UnicodeEncodeError,
    ) as exc:
        raise PersistentSignerError(
            "Invalid Base64 in key record."
        ) from exc


def _validate_record(
    record: object,
    expected_version: int,
) -> None:
    """Validate the minimum structure of a key record."""
    if not isinstance(record, dict):
        raise PersistentSignerError(
            "Key record must be a JSON object."
        )

    required = {
        "format_version",
        "key_id",
        "algorithm",
        "public_key",
        "salt",
        "nonce",
        "ciphertext",
    }

    missing = required - record.keys()

    if missing:
        raise PersistentSignerError(
            "Key record is missing fields: "
            f"{sorted(missing)}"
        )

    if record["format_version"] != expected_version:
        raise PersistentSignerError(
            "Unsupported key-record format version."
        )

    if record["algorithm"] != "Ed25519":
        raise PersistentSignerError(
            "Unsupported signing algorithm."
        )


def _write_json_atomically(
    path: Path,
    record: dict,
) -> None:
    """Write a key record atomically."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:
        with temp_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as file:
            json.dump(
                record,
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        temp_path.replace(path)

    except OSError as exc:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass

        raise PersistentSignerError(
            f"Unable to write key record: {path}"
        ) from exc