from pydantic import BaseModel
from typing import Optional, Dict, Any

class WrapRequest(BaseModel):
    content: str
    context: Dict[str, Any] = {}
    key_id: str = "key001"

class WrapResponse(BaseModel):
    wrapped_content: str
    nonce: str
    content_hash: str

class VerifyRequest(BaseModel):
    wrapped_content: str
    context: Dict[str, Any] = {}

class VerifyResponse(BaseModel):
    valid: bool
    content: Optional[str] = None
    error: Optional[str] = None
    nonce: Optional[str] = None
    key_id: Optional[str] = None
