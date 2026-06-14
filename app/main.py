import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.audit import AuditEvent, audit
from app.config import settings
from app.crypto import GuardBandCrypto
from app.llm import llm_service
from app.models import WrapRequest, WrapResponse, VerifyRequest, VerifyResponse


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host or "unknown")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.sinks.console import ConsoleSink
    audit.add_sink(ConsoleSink())

    if settings.LOG_POSTGRES_DSN:
        from app.sinks.postgres import PostgresSink
        audit.add_sink(PostgresSink(settings.LOG_POSTGRES_DSN))

    if settings.LOG_SPLUNK_HEC_URL and settings.LOG_SPLUNK_HEC_TOKEN:
        from app.sinks.splunk import SplunkHECSink
        audit.add_sink(SplunkHECSink(
            hec_url=settings.LOG_SPLUNK_HEC_URL,
            token=settings.LOG_SPLUNK_HEC_TOKEN,
            index=settings.LOG_SPLUNK_INDEX,
            source=settings.LOG_SPLUNK_SOURCE,
            ssl_verify=settings.LOG_SPLUNK_SSL_VERIFY,
        ))

    await audit.startup()
    yield
    await audit.shutdown()


app = FastAPI(title="Guard Bands POC", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

crypto = GuardBandCrypto(settings.SECRET_KEY)


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
            "health": "/health",
        },
    }


@app.post("/wrap", response_model=WrapResponse)
async def wrap_content(request: WrapRequest, req: Request):
    start = time.monotonic()
    ip = _client_ip(req)
    try:
        wrapped = crypto.wrap_content(
            content=request.content,
            context=request.context,
            key_id=request.key_id,
        )
        nonce = wrapped.split(":r:")[1].split(":h:")[0]
        content_hash = wrapped.split(":h:")[1].split("⟫")[0]

        await audit.log(AuditEvent(
            event_type="wrap",
            success=True,
            ip=ip,
            duration_ms=(time.monotonic() - start) * 1000,
            details={
                "key_id": request.key_id,
                "content_hash": content_hash,
                # context keys only — values may contain PII
                "context_keys": sorted(request.context.keys()),
            },
        ))
        return WrapResponse(wrapped_content=wrapped, nonce=nonce, content_hash=content_hash)

    except Exception as e:
        await audit.log(AuditEvent(
            event_type="wrap",
            success=False,
            ip=ip,
            duration_ms=(time.monotonic() - start) * 1000,
            details={"error": str(e)},
        ))
        raise HTTPException(status_code=500, detail=f"Wrapping failed: {str(e)}")


@app.post("/verify", response_model=VerifyResponse)
async def verify_content(request: VerifyRequest, req: Request):
    start = time.monotonic()
    ip = _client_ip(req)

    result = crypto.extract_and_verify(
        wrapped=request.wrapped_content,
        context=request.context,
    )

    await audit.log(AuditEvent(
        event_type="verify",
        success=result["valid"],
        ip=ip,
        duration_ms=(time.monotonic() - start) * 1000,
        details={
            "valid": result["valid"],
            "error": result.get("error"),
            "nonce": result.get("nonce"),
            "key_id": result.get("key_id"),
            "context_keys": sorted(request.context.keys()),
        },
    ))
    return VerifyResponse(**result)


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, req: Request):
    start = time.monotonic()
    ip = _client_ip(req)
    guard_bands_present = "⟪INERT:START" in request.message

    result = llm_service.chat(
        user_message=request.message,
        system_prompt=request.system_prompt,
    )

    success = result["success"]
    await audit.log(AuditEvent(
        event_type="chat",
        success=success,
        ip=ip,
        duration_ms=(time.monotonic() - start) * 1000,
        details={
            "model": result.get("model"),
            "input_tokens": result.get("usage", {}).get("input_tokens"),
            "output_tokens": result.get("usage", {}).get("output_tokens"),
            "guard_bands_in_message": guard_bands_present,
            "error": result.get("error") if not success else None,
        },
    ))

    if not success:
        raise HTTPException(status_code=500, detail=result["error"])

    return ChatResponse(
        response=result["response"],
        model=result["model"],
        usage=result["usage"],
    )


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
