"""Secure Ingest Service on Port 8001 for IdentityShield v3.

Dedicated FastAPI microservice providing:
- POST /ingest/v1/events: HMAC-authenticated log ingestion with size bounding,
  rate limiting, event schema validation, spooling to data/spool/YYYYMMDD.jsonl,
  bus handoff, and audit logging.
- GET /ingest/v1/health: health telemetry and backpressure state.
- Strictly scoped CORS for generator origin.
- Zero credential/body logging.

Runner: `python -m app.v3.ingest.service`
"""
import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from math import ceil
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.v3 import audit, config
from app.v3.config import Settings, get_settings
from app.v3.ingest.security import (
    AuthError,
    NonceCache,
    RateLimited,
    SchemaError,
    TokenBucket,
    TooLarge,
    default_nonce_cache,
    default_rate_limiter,
    verify_signature,
)
from app.v3.models import IngestEnvelope, IngestRejectedItem, IngestResult, Source
from app.v3.supervisor import Supervisor

log = logging.getLogger("identityshield.ingest")

SPOOL_DIR = config.ROOT_DIR / "data" / "spool"


def _sanitize_event(obj: Any) -> Any:
    """Recursively truncate string values exceeding 2048 characters."""
    if isinstance(obj, str):
        return obj[:2048]
    if isinstance(obj, dict):
        return {k: _sanitize_event(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_event(x) for x in obj]
    return obj


def _validate_event_source(ev: Any, source: Source) -> str | None:
    """Return error reason if event lacks minimal required fields, or None if valid."""
    if not isinstance(ev, dict):
        return "event must be a JSON object"

    if source == Source.okta:
        for field in ("uuid", "published", "eventType", "actor"):
            if field not in ev or ev[field] is None:
                return f"missing required okta field: '{field}'"
    elif source == Source.cloudtrail:
        for field in ("eventID", "eventTime", "eventName", "userIdentity"):
            if field not in ev or ev[field] is None:
                return f"missing required cloudtrail field: '{field}'"
    return None


def create_ingest_app(
    bus_handoff: Callable[[str, list[dict[str, Any]]], None] | None = None,
    supervisor: Supervisor | None = None,
    settings: Settings | None = None,
    nonce_cache: NonceCache | None = None,
    rate_limiter: TokenBucket | None = None,
    spool_dir: Path | None = None,
    clock: Any = None,
) -> FastAPI:
    """Construct and configure the Ingest Service FastAPI application."""
    active_settings = settings or get_settings()
    active_nonce_cache = nonce_cache or default_nonce_cache
    active_rate_limiter = rate_limiter or default_rate_limiter
    target_spool = spool_dir or SPOOL_DIR
    target_spool.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="IdentityShield Ingest Service", version="3.0", docs_url=None, redoc_url=None)

    # Scoped CORS for attack generator origin
    allowed_origins = active_settings.ingest_allowed_origins or ["null", "http://localhost:5500"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["POST", "GET", "OPTIONS"],
        allow_headers=[
            "Content-Type",
            "X-IS-Key-Id",
            "X-IS-Timestamp",
            "X-IS-Nonce",
            "X-IS-Signature",
            "ngrok-skip-browser-warning",
        ],
    )

    # Ingestion metrics
    metrics: dict[str, Any] = {
        "accepted_total": 0,
        "rejected_total": 0,
        "rejected_by_reason": defaultdict(int),
    }

    @app.post("/ingest/v1/events", status_code=202, response_model=IngestResult)
    async def ingest_events(request: Request) -> Response:
        if clock is not None:
            now_dt = clock() if callable(clock) else clock.now()
        else:
            now_dt = datetime.now(UTC)
        now_ts = now_dt.timestamp()
        now_iso = now_dt.isoformat()

        # 1. Backpressure guard from supervisor or bus
        if supervisor is not None and getattr(supervisor, "backpressure", False):
            return JSONResponse(
                status_code=429,
                content={"error": "backpressure", "detail": "Ingest service under backpressure"},
                headers={"Retry-After": "2"},
            )

        # 2. Read raw body with strict size check
        raw_body = await request.body()
        if len(raw_body) > config.INGEST_MAX_BODY_BYTES:
            raise TooLarge(f"Body size {len(raw_body)} exceeds limit {config.INGEST_MAX_BODY_BYTES}")

        # 3. Verify HMAC signature & replay protection
        keys = active_settings.ingest_keys
        if not keys:
            # Fallback for dev / tests if no keys configured
            keys = {"dev": "dev_secret_key_32bytes_long_random!"}

        try:
            key_id = verify_signature(
                headers=request.headers,
                raw_body=raw_body,
                keys=keys,
                now=now_ts,
                nonce_cache=active_nonce_cache,
            )
        except AuthError as exc:
            return JSONResponse(status_code=401, content={"error": "unauthorized", "detail": str(exc)})

        # 4. Parse envelope JSON
        try:
            raw_json = json.loads(raw_body.decode("utf-8"))
            if not isinstance(raw_json, dict):
                raise SchemaError("Request body must be a JSON object")
            envelope = IngestEnvelope.model_validate(raw_json)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            return JSONResponse(status_code=422, content={"error": "unprocessable_entity", "detail": str(exc)})

        # 5. Token bucket rate limit check per key
        allowed, retry_after = active_rate_limiter.consume(
            key_id=key_id,
            event_count=len(envelope.events),
            now=now_ts,
        )
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited", "detail": f"Rate limit exceeded. Retry in {retry_after}s"},
                headers={"Retry-After": str(ceil(retry_after))},
            )

        # 6. Validate events minimally per source
        accepted_events: list[dict[str, Any]] = []
        rejected_items: list[IngestRejectedItem] = []

        for idx, ev in enumerate(envelope.events):
            reason = _validate_event_source(ev, envelope.source)
            if reason:
                rejected_items.append(IngestRejectedItem(index=idx, reason=reason))
                metrics["rejected_total"] += 1
                metrics["rejected_by_reason"][reason] += 1
            else:
                sanitized = _sanitize_event(ev)
                accepted_events.append(sanitized)
                metrics["accepted_total"] += 1

        # 7. Append accepted events to spool file: data/spool/YYYYMMDD.jsonl
        if accepted_events:
            spool_date = now_dt.strftime("%Y%m%d")
            spool_file = target_spool / f"{spool_date}.jsonl"
            try:
                with spool_file.open("a", encoding="utf-8") as f:
                    for ev in accepted_events:
                        entry = {
                            "batch_id": envelope.batch_id,
                            "received_at": now_iso,
                            "sender_id": envelope.sender_id,
                            "source": envelope.source.value,
                            "event": ev,
                        }
                        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError:
                log.exception("Failed to write accepted events to spool")

        # 8. Bus handoff (non-blocking)
        if accepted_events and bus_handoff:
            topic = "raw.okta" if envelope.source == Source.okta else "raw.cloudtrail"
            try:
                bus_handoff(topic, accepted_events)
            except Exception:
                log.exception("Bus handoff failed")

        # 9. Write tamper-evident audit record
        body_sha256 = hashlib.sha256(raw_body).hexdigest()
        audit_detail = {
            "sender_id": envelope.sender_id,
            "batch_id": envelope.batch_id,
            "accepted": len(accepted_events),
            "rejected": len(rejected_items),
            "body_sha256": body_sha256,
        }
        try:
            audit.append("ingest", "ingest_batch", audit_detail)
        except Exception:
            log.exception("Failed to write audit entry for ingest batch")

        result = IngestResult(
            batch_id=envelope.batch_id,
            accepted=len(accepted_events),
            rejected=rejected_items,
            received_at=now_iso,
        )
        return JSONResponse(status_code=202, content=result.model_dump())

    @app.get("/ingest/v1/health")
    def health_check() -> dict[str, Any]:
        bp = bool(supervisor is not None and getattr(supervisor, "backpressure", False))
        return {
            "status": "ok",
            "accepted_total": metrics["accepted_total"],
            "rejected_total": metrics["rejected_total"],
            "rejected_by_reason": dict(metrics["rejected_by_reason"]),
            "backpressure": bp,
        }

    # Exception handlers
    @app.exception_handler(TooLarge)
    async def handle_too_large(_: Request, exc: TooLarge) -> JSONResponse:
        return JSONResponse(status_code=413, content={"error": "payload_too_large", "detail": str(exc)})

    @app.exception_handler(RateLimited)
    async def handle_rate_limited(_: Request, exc: RateLimited) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"error": "rate_limited", "detail": str(exc)},
            headers={"Retry-After": str(ceil(exc.retry_after))},
        )

    return app


if __name__ == "__main__":
    uvicorn.run(
        "app.v3.ingest.service:create_ingest_app",
        factory=True,
        host="0.0.0.0",
        port=config.INGEST_PORT,
        log_level="info",
    )
