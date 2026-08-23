"""AEGIS trust result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AEGISStatus(str, Enum):
    """High-level AEGIS verification statuses."""

    TRUSTED = "TRUSTED"
    UNVERIFIED = "UNVERIFIED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNTRUSTED_ISSUER = "UNTRUSTED_ISSUER"
    REVOKED_CREDENTIAL = "REVOKED_CREDENTIAL"
    EXPIRED_CREDENTIAL = "EXPIRED_CREDENTIAL"
    MALFORMED_PROVENANCE = "MALFORMED_PROVENANCE"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


@dataclass(frozen=True)
class VerificationEvidence:
    """Evidence collected during verification."""

    code: str
    message: str
    source: str


@dataclass(frozen=True)
class AEGISVerificationResult:
    """Structured result returned by the AEGIS Trust Engine."""

    status: AEGISStatus
    issuer_trusted: bool
    signature_valid: bool
    content_integrity: bool | None
    provenance_valid: bool
    credential_active: bool | None
    credential_status: str | None = None
    evidence: tuple[VerificationEvidence, ...] = field(
        default_factory=tuple
    )

    @property
    def is_trusted(self) -> bool:
        """Return True only for a fully trusted result."""
        return self.status is AEGISStatus.TRUSTED