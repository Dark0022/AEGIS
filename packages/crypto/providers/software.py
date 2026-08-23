"""Development software-backed signer for AEGIS."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..signer import Signer


@dataclass
class SoftwareSigner(Signer):
    """
    Development-only Ed25519 signer.

    The private key remains encapsulated inside the signer.
    """

    _private_key: Ed25519PrivateKey
    _key_id: str

    @classmethod
    def generate(cls) -> "SoftwareSigner":
        """Generate a new Ed25519 signing key."""
        private_key = Ed25519PrivateKey.generate()
        return cls.from_private_key(private_key)

    @classmethod
    def from_private_key(
        cls,
        private_key: Ed25519PrivateKey,
    ) -> "SoftwareSigner":
        """Create a signer from an existing private key."""
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        key_id = hashlib.sha256(public_key_bytes).hexdigest()[:16]

        return cls(
            _private_key=private_key,
            _key_id=key_id,
        )

    def export_private_key_material(self) -> bytes:
        """
        Export raw private-key material for the key-storage provider.

        This method exists only at the crypto-provider boundary.
        Application/business logic must never call it.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data using the encapsulated private key."""
        return self._private_key.sign(data)

    def public_key(self) -> bytes:
        """Return the raw Ed25519 public key."""
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def key_id(self) -> str:
        """Return the stable identifier for this signing key."""
        return self._key_id