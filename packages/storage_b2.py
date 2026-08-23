"""AEGIS durable object storage using Backblaze B2 S3 API."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import boto3
from botocore.client import Config
from botocore.exceptions import BotoCoreError, ClientError


class B2StorageError(Exception):
    """Raised when Backblaze B2 storage operations fail."""


@dataclass(frozen=True)
class B2ObjectMetadata:
    """Metadata for an object stored in B2."""

    key: str
    size: int
    content_type: str | None


class B2ObjectStore:
    """Small S3-compatible adapter for Backblaze B2."""

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        bucket: str | None = None,
        key_id: str | None = None,
        application_key: str | None = None,
    ) -> None:
        self._endpoint = (
            endpoint
            or os.environ.get(
                "B2_ENDPOINT"
            )
        )

        self._bucket = (
            bucket
            or os.environ.get(
                "B2_BUCKET"
            )
        )

        self._key_id = (
            key_id
            or os.environ.get(
                "B2_KEY_ID"
            )
        )

        self._application_key = (
            application_key
            or os.environ.get(
                "B2_APPLICATION_KEY"
            )
        )

        missing: list[str] = []

        if not self._endpoint:
            missing.append(
                "B2_ENDPOINT"
            )

        if not self._bucket:
            missing.append(
                "B2_BUCKET"
            )

        if not self._key_id:
            missing.append(
                "B2_KEY_ID"
            )

        if not self._application_key:
            missing.append(
                "B2_APPLICATION_KEY"
            )

        if missing:
            raise B2StorageError(
                "Missing Backblaze B2 configuration: "
                + ", ".join(missing)
            )

        try:
            self._client = boto3.client(
                "s3",
                endpoint_url=self._endpoint,
                aws_access_key_id=self._key_id,
                aws_secret_access_key=(
                    self._application_key
                ),
                region_name="us-east-005",
                config=Config(
                    signature_version="s3v4",
                    s3={
                        "addressing_style": "path",
                    },
                ),
            )

        except Exception as exc:
            raise B2StorageError(
                "Unable to initialize Backblaze B2 client."
            ) from exc

    @property
    def bucket(self) -> str:
        return self._bucket

    def upload_file(
        self,
        source_path: str | Path,
        key: str,
        *,
        content_type: str | None = None,
    ) -> None:
        """Upload a local file to B2."""

        path = Path(
            source_path
        )

        if not path.is_file():
            raise FileNotFoundError(
                f"Source file not found: {path}"
            )

        extra_args: dict[str, str] = {}

        if content_type:
            extra_args[
                "ContentType"
            ] = content_type

        try:
            if extra_args:
                self._client.upload_file(
                    str(path),
                    self._bucket,
                    key,
                    ExtraArgs=extra_args,
                )
            else:
                self._client.upload_file(
                    str(path),
                    self._bucket,
                    key,
                )

        except (
            BotoCoreError,
            ClientError,
        ) as exc:
            raise B2StorageError(
                f"Unable to upload B2 object: {key}"
            ) from exc

    def download_file(
        self,
        key: str,
        destination_path: str | Path,
    ) -> Path:
        """Download an object from B2."""

        destination = Path(
            destination_path
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            self._client.download_file(
                self._bucket,
                key,
                str(destination),
            )

        except (
            BotoCoreError,
            ClientError,
        ) as exc:
            raise B2StorageError(
                f"Unable to download B2 object: {key}"
            ) from exc

        return destination

    def head(
        self,
        key: str,
    ) -> B2ObjectMetadata:
        """Return B2 object metadata."""

        try:
            response = (
                self._client.head_object(
                    Bucket=self._bucket,
                    Key=key,
                )
            )

        except (
            BotoCoreError,
            ClientError,
        ) as exc:
            raise B2StorageError(
                f"Unable to inspect B2 object: {key}"
            ) from exc

        return B2ObjectMetadata(
            key=key,
            size=int(
                response.get(
                    "ContentLength",
                    0,
                )
            ),
            content_type=(
                response.get(
                    "ContentType"
                )
            ),
        )

    def delete(
        self,
        key: str,
    ) -> None:
        """Delete an object from B2."""

        try:
            self._client.delete_object(
                Bucket=self._bucket,
                Key=key,
            )

        except (
            BotoCoreError,
            ClientError,
        ) as exc:
            raise B2StorageError(
                f"Unable to delete B2 object: {key}"
            ) from exc

    def presigned_upload_url(
        self,
        key: str,
        *,
        content_type: str,
        expires_in: int = 900,
    ) -> str:
        """Create a temporary browser upload URL."""

        try:
            return self._client.generate_presigned_url(
                "put_object",
                Params={
                    "Bucket": self._bucket,
                    "Key": key,
                    "ContentType": content_type,
                },
                ExpiresIn=expires_in,
            )

        except (
            BotoCoreError,
            ClientError,
        ) as exc:
            raise B2StorageError(
                f"Unable to create upload URL for: {key}"
            ) from exc

    def presigned_download_url(
        self,
        key: str,
        *,
        expires_in: int = 900,
    ) -> str:
        """Create a temporary browser download URL."""

        try:
            return self._client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self._bucket,
                    "Key": key,
                },
                ExpiresIn=expires_in,
            )

        except (
            BotoCoreError,
            ClientError,
        ) as exc:
            raise B2StorageError(
                f"Unable to create download URL for: {key}"
            ) from exc