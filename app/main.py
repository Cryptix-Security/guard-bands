import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.audit import AuditEvent, audit
from app.config import settings
from app.crypto import GuardBandCrypto, StaticKeyResolver
from app.llm import llm_service
from app.middleware.auth import SSOHeaderMiddleware
from app.models import (
    ChatRequest, ChatResponse,
    WrapRequest, WrapResponse,
    VerifyRequest, VerifyResponse,
)
from app.replay import apply_replay_protection


def _rate_limit_key(request: Request) -> str:
    # SSOHeaderMiddleware sets user_id; fall back to IP for unauthenticated paths
    user_id = getattr(request.state, "user_id", None)
    return user_id if user_id else get_remote_address(request)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host or "unknown")


limiter = Limiter(key_func=_rate_limit_key)


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
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware executes in reverse-registration order (last added = first to run)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SSOHeaderMiddleware)  # runs first: populates request.state.user_id

crypto = GuardBandCrypto(
    key_resolver=StaticKeyResolver(settings.GUARD_BAND_KEYS, settings.KEY_ID)
)


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
@limiter.limit("60/minute")
async def wrap_content(request: Request, body: WrapRequest):
    start = time.monotonic()
    ip = _client_ip(request)
    try:
        wrapped = crypto.wrap_content(
            content=body.content,
            context=body.context,
            key_id=body.key_id,
        )
        nonce = wrapped.split(":r:")[1].split(":h:")[0]
        content_hash = wrapped.split(":h:")[1].split("⟫")[0]

        await audit.log(AuditEvent(
            event_type="wrap",
            success=True,
            ip=ip,
            user_id=request.state.user_id,
            duration_ms=(time.monotonic() - start) * 1000,
            details={
                "key_id": body.key_id,
                "content_hash": content_hash,
                "context_keys": sorted(body.context.keys()),
                "user_email": request.state.user_email,
            },
        ))
        return WrapResponse(wrapped_content=wrapped, nonce=nonce, content_hash=content_hash)

    except ValueError as e:
        await audit.log(AuditEvent(
            event_type="wrap",
            success=False,
            ip=ip,
            user_id=request.state.user_id,
            duration_ms=(time.monotonic() - start) * 1000,
            details={"error": str(e), "user_email": request.state.user_email},
        ))
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        await audit.log(AuditEvent(
            event_type="wrap",
            success=False,
            ip=ip,
            user_id=request.state.user_id,
            duration_ms=(time.monotonic() - start) * 1000,
            details={"error": str(e), "user_email": request.state.user_email},
        ))
        raise HTTPException(status_code=500, detail=f"Wrapping failed: {str(e)}")


@app.post("/verify", response_model=VerifyResponse)
@limiter.limit("120/minute")
async def verify_content(request: Request, body: VerifyRequest):
    start = time.monotonic()
    ip = _client_ip(request)

    result = crypto.extract_and_verify(
        wrapped=body.wrapped_content,
        context=body.context,
    )
    result = apply_replay_protection(result, body.context)

    await audit.log(AuditEvent(
        event_type="verify",
        success=result["valid"],
        ip=ip,
        user_id=request.state.user_id,
        duration_ms=(time.monotonic() - start) * 1000,
        details={
            "valid": result["valid"],
            "error": result.get("error"),
            "nonce": result.get("nonce"),
            "key_id": result.get("key_id"),
            "context_keys": sorted(body.context.keys()),
            "user_email": request.state.user_email,
        },
    ))
    return VerifyResponse(**result)


@app.post("/chat", response_model=ChatResponse)
@limiter.limit("20/minute")
async def chat(request: Request, body: ChatRequest):
    start = time.monotonic()
    ip = _client_ip(request)
    guard_bands_present = "⟪INERT:START" in body.message

    result = await llm_service.chat(
        user_message=body.message,
        context=body.context,
    )

    success = result["success"]
    await audit.log(AuditEvent(
        event_type="chat",
        success=success,
        ip=ip,
        user_id=request.state.user_id,
        duration_ms=(time.monotonic() - start) * 1000,
        details={
            "model": result.get("model"),
            "input_tokens": result.get("usage", {}).get("input_tokens"),
            "output_tokens": result.get("usage", {}).get("output_tokens"),
            "guard_bands_in_message": guard_bands_present,
            "user_email": request.state.user_email,
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
