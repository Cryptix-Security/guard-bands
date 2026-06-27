import json
from collections.abc import Iterable
from typing import Any

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.crypto import GuardBandCrypto
from app.models import CONTENT_MAX_BYTES
from app.replay import apply_replay_protection


class GuardBandVerificationMiddleware:
    """Verify Guard Band request bodies before FastAPI route handlers run."""

    def __init__(
        self,
        app: ASGIApp,
        crypto: GuardBandCrypto,
        required_paths: Iterable[str],
        methods: Iterable[str] = ("POST", "PUT", "PATCH"),
        wrapped_content_field: str = "wrapped_content",
        context_field: str = "context",
        replay_protection: bool = False,
        max_body_bytes: int = CONTENT_MAX_BYTES,
    ) -> None:
        self.app = app
        self.crypto = crypto
        self.required_paths = set(required_paths)
        self.methods = {method.upper() for method in methods}
        self.wrapped_content_field = wrapped_content_field
        self.context_field = context_field
        self.replay_protection = replay_protection
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self._should_verify(scope):
            await self.app(scope, receive, send)
            return

        body, body_error = await self._read_body(receive)
        if body_error:
            await self._reject(scope, send, body_error)
            return

        payload, error = self._parse_json_body(scope, body)
        if error:
            await self._reject(scope, send, error)
            return

        wrapped_content = payload.get(self.wrapped_content_field)
        context = payload.get(self.context_field, {})
        if not isinstance(wrapped_content, str):
            await self._reject(scope, send, f"Missing string field: {self.wrapped_content_field}")
            return
        if not isinstance(context, dict):
            await self._reject(scope, send, f"Field must be an object: {self.context_field}")
            return

        result = self.crypto.extract_and_verify(wrapped_content, context)
        if self.replay_protection:
            result = apply_replay_protection(result, context)
        if not result.get("valid"):
            await self._reject(scope, send, f"Guard Band verification failed: {result.get('error')}")
            return

        scope.setdefault("state", {})["guard_band_verification"] = result
        await self.app(scope, self._replay_body(body), send)

    def _should_verify(self, scope: Scope) -> bool:
        return (
            scope["type"] == "http"
            and scope["method"].upper() in self.methods
            and scope["path"] in self.required_paths
        )

    async def _read_body(self, receive: Receive) -> tuple[bytes, str | None]:
        chunks = []
        total_size = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total_size += len(chunk)
            if total_size > self.max_body_bytes:
                return b"", f"Request body exceeds {self.max_body_bytes} bytes"
            chunks.append(chunk)
            more_body = message.get("more_body", False)
        return b"".join(chunks), None

    def _parse_json_body(self, scope: Scope, body: bytes) -> tuple[dict[str, Any], str | None]:
        content_type = Headers(scope=scope).get("content-type", "")
        if "application/json" not in content_type:
            return {}, "Guard Band verification requires application/json"
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return {}, "Malformed JSON request body"
        if not isinstance(payload, dict):
            return {}, "JSON request body must be an object"
        return payload, None

    def _replay_body(self, body: bytes) -> Receive:
        sent = False

        async def receive() -> Message:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        return receive

    async def _reject(self, scope: Scope, send: Send, error: str) -> None:
        response = JSONResponse({"detail": error}, status_code=400)
        await response(scope, self._empty_receive, send)

    async def _empty_receive(self) -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}


def guard_band_verification(request: Request) -> dict[str, Any] | None:
    """Return middleware verification details attached to request.state."""
    return getattr(request.state, "guard_band_verification", None)
