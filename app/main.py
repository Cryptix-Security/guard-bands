from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from app.crypto import GuardBandCrypto
from app.models import WrapRequest, WrapResponse, VerifyRequest, VerifyResponse
from app.config import settings
from app.llm import llm_service

app = FastAPI(title="Guard Bands POC", version="0.1.0")

# CORS middleware for testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize crypto
crypto = GuardBandCrypto(settings.SECRET_KEY)

# New model for LLM chat
class ChatRequest(BaseModel):
    message: str
    system_prompt: Optional[str] = None

class ChatResponse(BaseModel):
    response: str
    model: str
    usage: dict

@app.get("/")
async def root():
    return {
        "message": "Guard Bands POC API",
        "endpoints": {
            "wrap": "/wrap",
            "verify": "/verify",
            "chat": "/chat",
            "health": "/health"
        }
    }

@app.post("/wrap", response_model=WrapResponse)
async def wrap_content(request: WrapRequest):
    """Wrap untrusted content with cryptographic guard bands"""
    try:
        wrapped = crypto.wrap_content(
            content=request.content,
            context=request.context,
            key_id=request.key_id
        )
        
        # Extract nonce and hash properly
        nonce = wrapped.split(":r:")[1].split(":h:")[0]
        content_hash = wrapped.split(":h:")[1].split("⟫")[0]
        
        return WrapResponse(
            wrapped_content=wrapped,
            nonce=nonce,
            content_hash=content_hash
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Wrapping failed: {str(e)}")

@app.post("/verify", response_model=VerifyResponse)
async def verify_content(request: VerifyRequest):
    """Verify cryptographic guard bands and extract content"""
    result = crypto.extract_and_verify(
        wrapped=request.wrapped_content,
        context=request.context
    )
    
    return VerifyResponse(**result)

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Chat with Claude (with guard band awareness)"""
    result = llm_service.chat(
        user_message=request.message,
        system_prompt=request.system_prompt
    )
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["error"])
    
    return ChatResponse(
        response=result["response"],
        model=result["model"],
        usage=result["usage"]
    )

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
