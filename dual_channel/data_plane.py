"""Data-plane service: untrusted content intake.

This service is deliberately incapable of executing anything. It exposes no
tool registry, no instruction endpoint, and no model access. Its only job is
to take untrusted content and return a signed inert block. In a deployment it
runs as its own process on its own port (or host/network segment):

    uvicorn dual_channel.data_plane:app --port 8001

Everything it emits is bound to `channel: data` and signed with the
data-plane key and issuer, so a downstream control plane can cryptographically
prove which channel a piece of content entered through.
"""

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.crypto import GuardBandCrypto, StaticKeyResolver
from app.models import CONTENT_MAX_BYTES

DATA_PLANE_KEY_ID = "data-plane"
DATA_PLANE_ISSUER = "data-plane"


def _build_crypto() -> GuardBandCrypto:
    secret = os.getenv("DUAL_CHANNEL_SECRET_KEY", "dual-channel-dev-secret").encode("utf-8")
    return GuardBandCrypto(
        key_resolver=StaticKeyResolver({DATA_PLANE_KEY_ID: secret}, DATA_PLANE_KEY_ID)
    )


crypto = _build_crypto()
app = FastAPI(title="Guard Bands Data Plane", version="0.1.0")


class IngestRequest(BaseModel):
    content: str = Field(..., max_length=CONTENT_MAX_BYTES)
    source: str = Field(..., max_length=200)
    request_id: str = Field(..., max_length=100)
    tenant_id: str = Field(..., max_length=100)
    user: str = Field(..., max_length=200)


class IngestResponse(BaseModel):
    wrapped_content: str
    context: dict


@app.post("/ingest", response_model=IngestResponse)
async def ingest(body: IngestRequest):
    """Wrap untrusted content into a signed inert block. Nothing more."""
    # Reject marker smuggling at the entry point rather than letting it fail
    # later as a nested-marker verification error downstream.
    if "⟪INERT:START" in body.content or "⟪INERT:END" in body.content:
        raise HTTPException(
            status_code=400,
            detail="Content may not contain guard band markers",
        )

    context = {
        "request_id": body.request_id,
        "tenant_id": body.tenant_id,
        "user": body.user,
        "source": body.source,
        # The channel is bound into the signature: this block provably
        # entered through the data plane and nowhere else.
        "channel": "data",
        "policy_path": "dual_channel.read_only",
    }
    wrapped = crypto.wrap_content(body.content, context, issuer=DATA_PLANE_ISSUER)
    return IngestResponse(wrapped_content=wrapped, context=context)


@app.get("/health")
async def health():
    return {"status": "healthy", "plane": "data"}
