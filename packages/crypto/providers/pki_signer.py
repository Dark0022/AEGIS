"""Signer implementation backed by the AEGIS PKI key store."""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from ..signer import Signer
from ..pki_store import load_private_key


class PKISigner(Signer):
    """
    Signer backed by a private key stored in the AEGIS PKI store.

    The private key is loaded internally and is never exposed through
    the Signer interface.
    """

    def __init__(
        self,
        private_key,
        *,
        key_path: str | Path,
    ) -> None:
        self._private_key = private_key
        self._key_path = Path(key_path)

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        self._key_id = hashlib.sha256(
            public_key
        ).hexdigest()[:16]

    @classmethod
    def load(
        cls,
        key_path: str | Path,
        password: str,
    ) -> "PKISigner":
        """Load a signing key from the AEGIS PKI key store."""
        private_key = load_private_key(
            key_path,
            password,
        )

        return cls(
            private_key,
            key_path=key_path,
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data with the protected PKI private key."""
        return self._private_key.sign(data)

    def public_key(self) -> bytes:
        """Return the public key."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def key_id(self) -> str:
        """Return the stable key identifier."""
        return self._key_id