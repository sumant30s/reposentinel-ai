from secrets import compare_digest

from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    """Authenticate before buffering bodies and bound chunked requests as well as Content-Length."""

    def __init__(self, app, settings):
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("method") not in {"POST", "PUT", "PATCH"}
            or not scope.get("path", "").startswith("/api/")
        ):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        expected = self.settings.api_token.get_secret_value().encode()
        supplied = headers.get(b"authorization", b"").removeprefix(b"Bearer ")
        if len(expected) < 32 or not compare_digest(supplied, expected):
            status = 503 if len(expected) < 32 else 401
            return await JSONResponse(
                {
                    "detail": "API token is not configured"
                    if status == 503
                    else "Invalid or missing bearer token"
                },
                status_code=status,
            )(scope, receive, send)
        limit = (
            self.settings.max_archive_bytes
            if scope["path"].endswith("/scans/upload")
            else 64 * 1024
        )
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > limit:
                return await JSONResponse(
                    {"detail": "Request body exceeds limit"}, status_code=413
                )(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break

        async def replay():
            return chunks.pop(0) if chunks else await receive()

        return await self.app(scope, replay, send)
