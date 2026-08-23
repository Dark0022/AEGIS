"""Encrypted development keystore primitives for AEGIS."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Security parameters for the development keystore.
#
# These are deliberately explicit rather than hidden in cryptographic
# helper calls so they can be reviewed and changed intentionally.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LENGTH = 32  # 256-bit AES key
_SALT_LENGTH = 16
_NONCE_LENGTH = 12


class KeystoreError(Exception):
    """Base exception for AEGIS keystore failures."""


class InvalidPasswordError(KeystoreError):
    """Raised when authenticated decryption fails."""


def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from a password using scrypt.
    """
    if not password:
        raise ValueError("Password must not be empty.")

    if len(salt) < _SALT_LENGTH:
        raise ValueError("Salt is too short.")

    kdf = Scrypt(
        salt=salt,
        length=_KEY_LENGTH,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(
    private_key: bytes,
    password: str,
    *,
    associated_data: bytes = b"AEGIS-KS-v1",
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt private-key material using a password-derived AES-GCM key.

    Returns:
        (salt, nonce, ciphertext)
    """
    if not private_key:
        raise ValueError("Private key material must not be empty.")

    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)

    encryption_key = derive_encryption_key(password, salt)
    ciphertext = AESGCM(encryption_key).encrypt(
        nonce,
        private_key,
        associated_data,
    )

    return salt, nonce, ciphertext


def decrypt_private_key(
    ciphertext: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    *,
    associated_data: bytes = b"AEGIS-KS-v1",
) -> bytes:
    """
    Decrypt and authenticate private-key material.

    Raises InvalidPasswordError if authentication fails.
    """
    if not ciphertext:
        raise ValueError("Ciphertext must not be empty.")

    if len(nonce) != _NONCE_LENGTH:
        raise ValueError("Invalid nonce length.")

    encryption_key = derive_encryption_key(password, salt)

    try:
        return AESGCM(encryption_key).decrypt(
            nonce,
            ciphertext,
            associated_data,
        )
    except InvalidTag as exc:
        raise InvalidPasswordError(
            "Unable to decrypt keystore data."
        ) from exc