from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

CONTENT_MAX_BYTES = 50_000


class WrapRequest(BaseModel):
    content: str = Field(..., max_length=CONTENT_MAX_BYTES)
    context: Dict[str, Any] = Field(default_factory=dict)
    key_id: str = "key001"


class WrapResponse(BaseModel):
    wrapped_content: str
    nonce: str
    content_hash: str


class VerifyRequest(BaseModel):
    wrapped_content: str
    context: Dict[str, Any] = Field(default_factory=dict)


class VerifyResponse(BaseModel):
    valid: bool
    content: Optional[str] = None
    error: Optional[str] = None
    nonce: Optional[str] = None
    key_id: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=CONTENT_MAX_BYTES)
    # context must match what was used when wrapping so the LLM's
    # verify tool call uses the correct signing context
    context: Dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    response: str
    model: str
    usage: dict
