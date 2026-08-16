"""MCP ``tools/call`` integration for Guard Bands.

The adapter signs complete JSON arguments and results with detached envelopes
stored in MCP ``_meta``. Text result blocks are also wrapped with visible Guard
Band markers so their data/instruction boundary survives presentation to a
model.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import mcp.types as mcp_types
from mcp.client import advertise
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.extension import Extension
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolRequestParams, CallToolResult, TextContent

from ..crypto import GuardBandCrypto, canonical_json

MCP_GUARD_BAND_ID = "com.guardbands/guard-band"
MCP_GUARD_BAND_VERSION = 1
DEFAULT_MAX_MCP_PAYLOAD_BYTES = 1_000_000
_CALL_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

ServerContextResolver = Callable[
    [str, dict[str, Any], ServerRequestContext[Any, Any]], dict[str, Any]
]
ClientAuthorizer = Callable[[str, dict[str, Any], dict[str, Any]], None]


class MCPGuardBandError(ValueError):
    """Raised when guarded MCP traffic fails local verification."""


@dataclass(frozen=True, slots=True)
class MCPToolPolicy:
    """Select which sides of a tool call require Guard Bands."""

    guard_inputs: bool = False
    guard_outputs: bool = False
    wrap_text_outputs: bool = True
    ttl_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.wrap_text_outputs and not self.guard_outputs:
            object.__setattr__(self, "wrap_text_outputs", False)
        if self.ttl_seconds is not None and self.ttl_seconds < 0:
            raise ValueError("ttl_seconds must not be negative")

    @property
    def enabled(self) -> bool:
        return self.guard_inputs or self.guard_outputs


def guard_bands_client_capability():
    """Return the MCP client capability advertisement for Guard Bands."""
    return advertise(MCP_GUARD_BAND_ID, {"envelopeVersion": MCP_GUARD_BAND_VERSION})


def _policy_for(policies: Mapping[str, MCPToolPolicy], tool_name: str) -> MCPToolPolicy:
    return policies.get(tool_name, policies.get("*", MCPToolPolicy()))


def _input_digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(arguments).encode("utf-8")).hexdigest()


def _mcp_context(
    *,
    audience: str,
    direction: str,
    tool_name: str,
    call_id: str,
    application_context: dict[str, Any],
    arguments: dict[str, Any],
    content_index: int | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "application": application_context,
        "audience": audience,
        "call_id": call_id,
        "direction": direction,
        "input_sha256": _input_digest(arguments),
        "integration": "mcp",
        "method": "tools/call",
        "tool": tool_name,
    }
    if content_index is not None:
        context["content_index"] = content_index
    return context


def _payload_size(value: Any) -> int:
    return len(canonical_json(value).encode("utf-8"))


def _result_payload(result: CallToolResult) -> dict[str, Any]:
    return {
        "content": [
            block.model_dump(by_alias=True, exclude_none=False, mode="json")
            for block in result.content
        ],
        "is_error": result.is_error,
        "structured_content": result.structured_content,
    }


def _guard_meta(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    value = (meta or {}).get(MCP_GUARD_BAND_ID)
    return value if isinstance(value, dict) else None


def _call_id(meta: dict[str, Any] | None) -> str | None:
    guard_meta = _guard_meta(meta)
    if guard_meta is None or guard_meta.get("version") != MCP_GUARD_BAND_VERSION:
        return None
    value = guard_meta.get("call_id")
    if not isinstance(value, str) or not _CALL_ID_PATTERN.fullmatch(value):
        return None
    return value


class GuardBandMCPServerExtension(Extension):
    """Verify guarded tool arguments and sign guarded tool results."""

    identifier = MCP_GUARD_BAND_ID

    def __init__(
        self,
        crypto: GuardBandCrypto,
        *,
        audience: str,
        policies: Mapping[str, MCPToolPolicy],
        context_resolver: ServerContextResolver | None = None,
        signing_key_id: str | None = None,
        issuer: str = "mcp-server",
        max_payload_bytes: int = DEFAULT_MAX_MCP_PAYLOAD_BYTES,
    ) -> None:
        if not audience:
            raise ValueError("audience is required")
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        self.crypto = crypto
        self.audience = audience
        self.policies = dict(policies)
        self.context_resolver = context_resolver or (lambda _name, _args, _ctx: {})
        self.signing_key_id = signing_key_id
        self.issuer = issuer
        self.max_payload_bytes = max_payload_bytes

    def settings(self) -> dict[str, Any]:
        return {"envelopeVersion": MCP_GUARD_BAND_VERSION, "method": "tools/call"}

    async def intercept_tool_call(
        self,
        params: CallToolRequestParams,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        policy = _policy_for(self.policies, params.name)
        if not policy.enabled:
            return await call_next(ctx)

        arguments = params.arguments or {}
        if _payload_size(arguments) > self.max_payload_bytes:
            raise MCPError(mcp_types.INVALID_PARAMS, "Guarded MCP payload is too large")

        call_id = _call_id(params.meta)
        if call_id is None:
            raise MCPError(mcp_types.INVALID_PARAMS, "Valid Guard Band call metadata is required")

        application_context = self.context_resolver(params.name, arguments, ctx)
        if not isinstance(application_context, dict):
            raise MCPError(mcp_types.INTERNAL_ERROR, "Guard Band context resolution failed")

        if policy.guard_inputs:
            guard_meta = _guard_meta(params.meta)
            envelope = guard_meta.get("input") if guard_meta else None
            verification = self.crypto.verify_value(
                arguments,
                envelope,
                _mcp_context(
                    audience=self.audience,
                    direction="input",
                    tool_name=params.name,
                    call_id=call_id,
                    application_context=application_context,
                    arguments=arguments,
                ),
            )
            if not verification.get("valid"):
                raise MCPError(mcp_types.INVALID_PARAMS, "Guard Band input verification failed")

        result = await call_next(ctx)
        if not policy.guard_outputs or not isinstance(result, CallToolResult):
            # Multi-round-trip ``input_required`` results are not final tool
            # output. The SDK retries with the same signed arguments and this
            # interceptor signs the eventual complete CallToolResult.
            return result

        if _payload_size(_result_payload(result)) > self.max_payload_bytes:
            raise MCPError(mcp_types.INTERNAL_ERROR, "Guarded MCP result is too large")
        if policy.wrap_text_outputs:
            result = self._wrap_text_blocks(
                result,
                policy,
                params.name,
                call_id,
                application_context,
                arguments,
            )

        payload = _result_payload(result)
        if _payload_size(payload) > self.max_payload_bytes:
            raise MCPError(mcp_types.INTERNAL_ERROR, "Guarded MCP result is too large")
        envelope = self.crypto.sign_value(
            payload,
            _mcp_context(
                audience=self.audience,
                direction="output",
                tool_name=params.name,
                call_id=call_id,
                application_context=application_context,
                arguments=arguments,
            ),
            key_id=self.signing_key_id,
            issuer=self.issuer,
            ttl_seconds=policy.ttl_seconds,
        )
        result_meta = dict(result.meta or {})
        result_meta[MCP_GUARD_BAND_ID] = {
            "version": MCP_GUARD_BAND_VERSION,
            "call_id": call_id,
            "output": envelope,
        }
        return result.model_copy(update={"meta": result_meta})

    def _wrap_text_blocks(
        self,
        result: CallToolResult,
        policy: MCPToolPolicy,
        tool_name: str,
        call_id: str,
        application_context: dict[str, Any],
        arguments: dict[str, Any],
    ) -> CallToolResult:
        blocks = []
        for index, block in enumerate(result.content):
            if not isinstance(block, TextContent):
                blocks.append(block)
                continue
            if "⟪INERT:START" in block.text or "⟪INERT:END" in block.text:
                raise MCPError(
                    mcp_types.INTERNAL_ERROR,
                    "Tool output contains reserved Guard Band markers",
                )
            wrapped = self.crypto.wrap_content(
                block.text,
                _mcp_context(
                    audience=self.audience,
                    direction="output-text",
                    tool_name=tool_name,
                    call_id=call_id,
                    application_context=application_context,
                    arguments=arguments,
                    content_index=index,
                ),
                key_id=self.signing_key_id,
                issuer=self.issuer,
                ttl_seconds=policy.ttl_seconds,
            )
            blocks.append(block.model_copy(update={"text": wrapped}))
        return result.model_copy(update={"content": blocks})


class GuardBandMCPClient:
    """Sign calls made by an MCP client and verify guarded results."""

    def __init__(
        self,
        client: Any,
        crypto: GuardBandCrypto,
        *,
        audience: str,
        policies: Mapping[str, MCPToolPolicy],
        signing_key_id: str | None = None,
        issuer: str = "mcp-client",
        authorizer: ClientAuthorizer | None = None,
        max_payload_bytes: int = DEFAULT_MAX_MCP_PAYLOAD_BYTES,
    ) -> None:
        if not audience:
            raise ValueError("audience is required")
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        self.client = client
        self.crypto = crypto
        self.audience = audience
        self.policies = dict(policies)
        self.signing_key_id = signing_key_id
        self.issuer = issuer
        self.authorizer = authorizer
        self.max_payload_bytes = max_payload_bytes

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        guard_context: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> CallToolResult:
        policy = _policy_for(self.policies, name)
        arguments = arguments or {}
        application_context = guard_context or {}
        if not isinstance(application_context, dict):
            raise TypeError("guard_context must be a dict")
        if not policy.enabled:
            return await self.client.call_tool(name, arguments, meta=meta, **kwargs)
        if _payload_size(arguments) > self.max_payload_bytes:
            raise MCPGuardBandError("Guarded MCP payload is too large")
        if self.authorizer is not None:
            self.authorizer(name, arguments, application_context)

        outgoing_meta = dict(meta or {})
        if MCP_GUARD_BAND_ID in outgoing_meta:
            raise MCPGuardBandError(f"{MCP_GUARD_BAND_ID} metadata is reserved")
        call_id = secrets.token_urlsafe(16)
        guard_meta: dict[str, Any] = {
            "version": MCP_GUARD_BAND_VERSION,
            "call_id": call_id,
        }
        if policy.guard_inputs:
            guard_meta["input"] = self.crypto.sign_value(
                arguments,
                _mcp_context(
                    audience=self.audience,
                    direction="input",
                    tool_name=name,
                    call_id=call_id,
                    application_context=application_context,
                    arguments=arguments,
                ),
                key_id=self.signing_key_id,
                issuer=self.issuer,
                ttl_seconds=policy.ttl_seconds,
            )
        outgoing_meta[MCP_GUARD_BAND_ID] = guard_meta

        result = await self.client.call_tool(name, arguments, meta=outgoing_meta, **kwargs)
        if policy.guard_outputs:
            self._verify_result(
                result,
                policy,
                name,
                call_id,
                application_context,
                arguments,
            )
        return result

    def _verify_result(
        self,
        result: CallToolResult,
        policy: MCPToolPolicy,
        tool_name: str,
        call_id: str,
        application_context: dict[str, Any],
        arguments: dict[str, Any],
    ) -> None:
        payload = _result_payload(result)
        if _payload_size(payload) > self.max_payload_bytes:
            raise MCPGuardBandError("Guarded MCP result is too large")
        guard_meta = _guard_meta(result.meta)
        if (
            guard_meta is None
            or guard_meta.get("version") != MCP_GUARD_BAND_VERSION
            or guard_meta.get("call_id") != call_id
        ):
            raise MCPGuardBandError("Valid Guard Band result metadata is required")
        verification = self.crypto.verify_value(
            payload,
            guard_meta.get("output"),
            _mcp_context(
                audience=self.audience,
                direction="output",
                tool_name=tool_name,
                call_id=call_id,
                application_context=application_context,
                arguments=arguments,
            ),
        )
        if not verification.get("valid"):
            raise MCPGuardBandError("Guard Band output verification failed")

        if not policy.wrap_text_outputs:
            return
        for index, block in enumerate(result.content):
            if not isinstance(block, TextContent):
                continue
            text_verification = self.crypto.extract_and_verify(
                block.text,
                _mcp_context(
                    audience=self.audience,
                    direction="output-text",
                    tool_name=tool_name,
                    call_id=call_id,
                    application_context=application_context,
                    arguments=arguments,
                    content_index=index,
                ),
            )
            if not text_verification.get("valid"):
                raise MCPGuardBandError("Guard Band text output verification failed")


__all__ = [
    "DEFAULT_MAX_MCP_PAYLOAD_BYTES",
    "MCP_GUARD_BAND_ID",
    "MCP_GUARD_BAND_VERSION",
    "GuardBandMCPClient",
    "GuardBandMCPServerExtension",
    "MCPGuardBandError",
    "MCPToolPolicy",
    "guard_bands_client_capability",
]
