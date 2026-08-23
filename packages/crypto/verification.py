"""Signature verification utilities for AEGIS."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_signature(
    data: bytes,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """
    Verify an Ed25519 signature.

    Returns True when the signature is valid.
    Returns False when the signature is invalid.
    """
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False