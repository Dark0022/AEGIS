"""Signing interfaces for AEGIS."""

from __future__ import annotations

from abc import ABC, abstractmethod


class Signer(ABC):
    """Abstract interface for an AEGIS signing provider."""

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """
        Sign data and return the raw signature.

        Implementations must never expose the private key
        to the caller.
        """
        raise NotImplementedError

    @abstractmethod
    def public_key(self) -> bytes:
        """
        Return the public key associated with this signer.
        """
        raise NotImplementedError

    @abstractmethod
    def key_id(self) -> str:
        """
        Return a stable identifier for the signing key.

        This is an identifier, not the private key itself.
        """
        raise NotImplementedError