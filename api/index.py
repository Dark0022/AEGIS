"""Vercel entrypoint for the AEGIS FastAPI application."""

from __future__ import annotations

from apps.api.main import app as aegis_app


class StripAPIPrefix:
    """Remove the Vercel /api prefix before FastAPI route matching."""

    def __init__(self, application):
        self.application = application

    async def __call__(
        self,
        scope,
        receive,
        send,
    ):
        if (
            scope["type"] == "http"
            and scope["path"].startswith("/api")
        ):
            scope = scope.copy()

            stripped_path = (
                scope["path"][4:]
            )

            if not stripped_path:
                stripped_path = "/"

            scope["path"] = stripped_path

            raw_path = scope.get(
                "raw_path"
            )

            if raw_path:
                raw_path = raw_path[4:]

                if not raw_path:
                    raw_path = b"/"

                scope["raw_path"] = raw_path

        await self.application(
            scope,
            receive,
            send,
        )


app = StripAPIPrefix(
    aegis_app
)