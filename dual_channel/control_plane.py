"""Control-plane service: trusted instructions and tool execution.

This is the only service with a tool surface, and it enforces the channel
separation at the join point:

- Instructions are taken exclusively from this service's authenticated
  request body. Document text is never parsed for instructions.
- Data is accepted only if it carries a valid data-plane signature (key id,
  issuer, and a `channel: data` context binding all authenticated by the MAC).
  Raw text, tampered blocks, or blocks minted by anything other than the data
  plane are rejected — fail closed.

In a deployment it runs as its own process on its own port:

    uvicorn dual_channel.control_plane:app --port 8002
"""

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.crypto import GuardBandCrypto, StaticKeyResolver
from dual_channel.data_plane import DATA_PLANE_ISSUER, DATA_PLANE_KEY_ID


def _build_crypto() -> GuardBandCrypto:
    # The control plane holds the data-plane key for verification. With HMAC
    # the same secret signs and verifies; production deployments should scope
    # signing access to the data plane only (see docs/KEY_MANAGEMENT.md).
    secret = os.getenv("DUAL_CHANNEL_SECRET_KEY", "dual-channel-dev-secret").encode("utf-8")
    return GuardBandCrypto(
        key_resolver=StaticKeyResolver({DATA_PLANE_KEY_ID: secret}, DATA_PLANE_KEY_ID)
    )


crypto = _build_crypto()
app = FastAPI(title="Guard Bands Control Plane", version="0.1.0")

READ_ONLY_ACTIONS = {"summarize_document"}
SENSITIVE_ACTIONS = {"issue_refund"}
ROLE_ACTIONS = {
    "viewer": READ_ONLY_ACTIONS,
    "operator": READ_ONLY_ACTIONS | SENSITIVE_ACTIONS,
}


class WrappedDocument(BaseModel):
    wrapped_content: str
    context: dict


class ExecuteRequest(BaseModel):
    # The instruction channel: action selection happens here and only here.
    action: str = Field(..., max_length=100)
    principal_user: str = Field(..., max_length=200)
    principal_role: str = Field(default="viewer", max_length=50)
    tenant_id: str = Field(..., max_length=100)
    documents: list[WrappedDocument] = Field(default_factory=list)


def _verify_data_plane_document(document: WrappedDocument, tenant_id: str) -> str:
    """Admit a document only if it provably came through the data plane."""
    result = crypto.extract_and_verify(document.wrapped_content, document.context)
    if not result.get("valid"):
        raise HTTPException(
            status_code=400,
            detail=f"Data-plane verification failed: {result.get('error')}",
        )
    if result["key_id"] != DATA_PLANE_KEY_ID or result["issuer"] != DATA_PLANE_ISSUER:
        raise HTTPException(
            status_code=400,
            detail="Document was not signed by the data plane",
        )
    if document.context.get("channel") != "data":
        raise HTTPException(
            status_code=400,
            detail="Document is not bound to the data channel",
        )
    if document.context.get("tenant_id") != tenant_id:
        raise HTTPException(
            status_code=403,
            detail="Document tenant does not match request tenant",
        )
    return result["content"]


@app.post("/execute")
async def execute(body: ExecuteRequest):
    # 1. Authorize the instruction. It came from this authenticated channel;
    #    nothing inside a document can select or escalate the action.
    allowed_actions = ROLE_ACTIONS.get(body.principal_role, set())
    if body.action not in ROLE_ACTIONS["operator"]:
        raise HTTPException(status_code=400, detail=f"Unknown action: {body.action}")
    if body.action not in allowed_actions:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{body.principal_role}' is not allowed to perform: {body.action}",
        )

    # 2. Admit data only with a valid data-plane signature — fail closed.
    verified_contents = [
        _verify_data_plane_document(document, body.tenant_id)
        for document in body.documents
    ]

    # 3. Execute. Document text is inert data: it is summarized or attached,
    #    never interpreted as an instruction.
    if body.action == "summarize_document":
        return {
            "action": body.action,
            "allowed": True,
            "documents_verified": len(verified_contents),
            "content_length": sum(len(content) for content in verified_contents),
            "summary": "Verified data-plane content accepted for read-only summarization.",
        }

    return {
        "action": body.action,
        "allowed": True,
        "documents_verified": len(verified_contents),
        "message": (
            "Authorized action would be queued for a real tool here. "
            "Action selection came from the control channel only."
        ),
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "plane": "control"}
