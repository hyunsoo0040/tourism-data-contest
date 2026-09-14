"""Bound multipart input before large uploads can fill the temporary spool."""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.formparsers import MultiPartException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class PhotoBodyLimit:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != "/v1/authenticity/photos":
            await self.app(scope, receive, send)
            return
        limit = 31 * 1024 * 1024
        headers = Headers(scope=scope)
        try:
            size = int(headers.get("content-length", "0"))
        except ValueError:
            size = limit + 1
        if size > limit:
            await JSONResponse({"detail": "사진 전체 크기를 줄여 주세요."}, status_code=413)(
                scope, receive, send
            )
            return
        count = 0

        async def bounded_receive() -> Message:
            nonlocal count
            message = await receive()
            if message["type"] == "http.request":
                count += len(message.get("body", b""))
                if count > limit:
                    # Starlette's multipart parser closes its open files on this exception.
                    raise MultiPartException("PHOTO_TOTAL_BYTES_LIMIT")
            return message

        await self.app(scope, bounded_receive, send)
