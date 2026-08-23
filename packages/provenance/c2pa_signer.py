"""AEGIS integration with the C2PA Python signing API."""

from __future__ import annotations

from pathlib import Path

import c2pa

from packages.crypto.signer import Signer


class C2PASignerError(Exception):
    """Raised when an AEGIS C2PA signer cannot be created."""


class AEGISC2PASigner:
    """
    Adapter between the AEGIS signing abstraction and C2PA.

    C2PA receives a callback that asks AEGIS to sign bytes.
    The private signing key is never passed to C2PA.
    """

    def __init__(
        self,
        aegis_signer: Signer,
        *,
        issuer_certificate_path: str | Path,
        institution_certificate_path: str | Path,
    ) -> None:
        self._aegis_signer = aegis_signer

        issuer_certificate = _read_pem_certificate(
            issuer_certificate_path,
        )

        institution_certificate = _read_pem_certificate(
            institution_certificate_path,
        )

        self._certificate_chain = (
            issuer_certificate
            + institution_certificate
        )

        self._c2pa_signer = c2pa.Signer.from_callback(
            self._sign_callback,
            c2pa.C2paSigningAlg.ED25519,
            self._certificate_chain,
        )

    def _sign_callback(
        self,
        data: bytes,
    ) -> bytes:
        """Delegate the C2PA signing operation to AEGIS."""
        return self._aegis_signer.sign(data)

    @property
    def signer(self) -> c2pa.Signer:
        """Return the C2PA signer object."""
        return self._c2pa_signer

    @property
    def key_id(self) -> str:
        """Return the AEGIS key identifier."""
        return self._aegis_signer.key_id()

    @property
    def certificate_chain(self) -> str:
        """Return the public C2PA certificate chain."""
        return self._certificate_chain


def _read_pem_certificate(
    path: str | Path,
) -> str:
    """Read a PEM-encoded certificate as UTF-8 text."""
    certificate_path = Path(path)

    if not certificate_path.is_file():
        raise FileNotFoundError(
            f"Certificate not found: {certificate_path}"
        )

    try:
        certificate_bytes = certificate_path.read_bytes()
    except OSError as exc:
        raise C2PASignerError(
            f"Unable to read certificate: {certificate_path}"
        ) from exc

    try:
        certificate = certificate_bytes.decode(
            "ascii"
        )
    except UnicodeDecodeError as exc:
        raise C2PASignerError(
            f"Certificate is not ASCII PEM: {certificate_path}"
        ) from exc

    if (
        "-----BEGIN CERTIFICATE-----" not in certificate
        or "-----END CERTIFICATE-----" not in certificate
    ):
        raise C2PASignerError(
            f"Invalid PEM certificate: {certificate_path}"
        )

    return certificate