"""Persistent storage helpers for AEGIS PKI material."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from .providers.keystore import (
    decrypt_private_key,
    encrypt_private_key,
)


KEYSTORE_FORMAT_VERSION = 1
KEYSTORE_ASSOCIATED_DATA = b"AEGIS-PKI-KEYSTORE-v1"


class PKIStoreError(Exception):
    """Base exception for AEGIS PKI storage failures."""


class PKIRecordExistsError(PKIStoreError):
    """Raised when storage would overwrite an existing record."""


def save_certificate(
    certificate: x509.Certificate,
    path: str | Path,
) -> None:
    """
    Save an X.509 certificate as PEM.

    Existing files are never overwritten.
    """
    target = Path(path)

    if target.exists():
        raise PKIRecordExistsError(
            f"Certificate already exists: {target}"
        )

    target.parent.mkdir(parents=True, exist_ok=True)

    pem = certificate.public_bytes(
        serialization.Encoding.PEM
    )

    _write_bytes_atomically(
        target,
        pem,
    )


def load_certificate(
    path: str | Path,
) -> x509.Certificate:
    """Load an X.509 certificate from PEM."""
    target = Path(path)

    if not target.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {target}"
        )

    try:
        data = target.read_bytes()
        return x509.load_pem_x509_certificate(data)
    except (OSError, ValueError) as exc:
        raise PKIStoreError(
            f"Unable to load certificate: {target}"
        ) from exc


def save_private_key(
    private_key: Ed25519PrivateKey,
    path: str | Path,
    password: str,
) -> str:
    """
    Encrypt and save an Ed25519 private key.

    Returns the key identifier derived from the public key.

    The plaintext private key is never written to disk.
    """
    target = Path(path)

    if target.exists():
        raise PKIRecordExistsError(
            f"Private-key record already exists: {target}"
        )

    if not password:
        raise ValueError("Password must not be empty.")

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    key_id = hashlib.sha256(
        public_key_bytes
    ).hexdigest()[:16]

    try:
        salt, nonce, ciphertext = encrypt_private_key(
            private_key_bytes,
            password,
            associated_data=KEYSTORE_ASSOCIATED_DATA,
        )
    finally:
        del private_key_bytes

    record = {
        "format_version": KEYSTORE_FORMAT_VERSION,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "public_key": _b64encode(public_key_bytes),
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }

    _write_json_atomically(
        target,
        record,
    )

    return key_id


def load_private_key(
    path: str | Path,
    password: str,
) -> Ed25519PrivateKey:
    """
    Load an Ed25519 private key from an encrypted PKI record.

    The plaintext key exists only in memory for reconstruction of
    the key object.
    """
    target = Path(path)

    if not target.is_file():
        raise FileNotFoundError(
            f"Private-key record not found: {target}"
        )

    if not password:
        raise ValueError("Password must not be empty.")

    try:
        record = json.loads(
            target.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise PKIStoreError(
            f"Unable to read private-key record: {target}"
        ) from exc

    _validate_key_record(record)

    salt = _b64decode(record["salt"])
    nonce = _b64decode(record["nonce"])
    ciphertext = _b64decode(record["ciphertext"])
    expected_public_key = _b64decode(
        record["public_key"]
    )

    private_key_bytes = decrypt_private_key(
        ciphertext,
        password,
        salt,
        nonce,
        associated_data=KEYSTORE_ASSOCIATED_DATA,
    )

    try:
        private_key = Ed25519PrivateKey.from_private_bytes(
            private_key_bytes
        )
    finally:
        del private_key_bytes

    actual_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if actual_public_key != expected_public_key:
        raise PKIStoreError(
            "Stored private key does not match stored public key."
        )

    actual_key_id = hashlib.sha256(
        actual_public_key
    ).hexdigest()[:16]

    if actual_key_id != record["key_id"]:
        raise PKIStoreError(
            "Stored key ID does not match the loaded key."
        )

    return private_key


def _validate_key_record(record: object) -> None:
    """Validate the PKI private-key record structure."""
    if not isinstance(record, dict):
        raise PKIStoreError(
            "Private-key record must be a JSON object."
        )

    required_fields = {
        "format_version",
        "algorithm",
        "key_id",
        "public_key",
        "salt",
        "nonce",
        "ciphertext",
    }

    missing_fields = required_fields - record.keys()

    if missing_fields:
        raise PKIStoreError(
            "Private-key record is missing fields: "
            f"{sorted(missing_fields)}"
        )

    if record["format_version"] != KEYSTORE_FORMAT_VERSION:
        raise PKIStoreError(
            "Unsupported PKI key-record format version."
        )

    if record["algorithm"] != "Ed25519":
        raise PKIStoreError(
            "Unsupported PKI key algorithm."
        )

    if not isinstance(record["key_id"], str):
        raise PKIStoreError(
            "Invalid key ID."
        )


def _b64encode(value: bytes) -> str:
    """Encode bytes as Base64 text."""
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    """Decode validated Base64 text."""
    try:
        return base64.b64decode(
            value.encode("ascii"),
            validate=True,
        )
    except (
        ValueError,
        UnicodeEncodeError,
    ) as exc:
        raise PKIStoreError(
            "Invalid Base64 data in PKI record."
        ) from exc


def _write_json_atomically(
    path: Path,
    record: dict,
) -> None:
    """Write JSON through a temporary file and atomically replace target."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:
        temp_path.write_text(
            json.dumps(
                record,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        temp_path.replace(path)

    except OSError as exc:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass

        raise PKIStoreError(
            f"Unable to write PKI record: {path}"
        ) from exc


def _write_bytes_atomically(
    path: Path,
    data: bytes,
) -> None:
    """Write binary data through a temporary file."""
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:
        temp_path.write_bytes(data)
        temp_path.replace(path)

    except OSError as exc:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass

        raise PKIStoreError(
            f"Unable to write PKI file: {path}"
        ) from exc