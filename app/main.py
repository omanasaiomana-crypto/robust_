"""FastAPI main application: lifecycle, routers, exception handlers, and static files."""
import logging
import threading
import uuid
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import store
from app.api import alerts, audit, health, identities, metrics
from app.config import STATIC_DIR
from app.pipeline import run_pipeline
from app.v3 import config as v3_config
from app.v3 import store as v3_store
from app.v3.agents import register_all
from app.v3.agents.base import Agent, AgentContext
from app.v3.bus import Bus
from app.v3.ingest.service import create_ingest_app
from app.v3.models import Event, Message, RawLog, Signal, Source
from app.v3.pipeline_v3 import StoreAdapter, _persist_event, _persist_signal
from app.v3.supervisor import Supervisor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("identityshield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.result = None
    app.state.startup_error = ""
    store.init_db()
    try:
        app.state.result = run_pipeline()
    except Exception as exc:
        log.exception("Pipeline failed at startup")
        app.state.result = None
        app.state.startup_error = str(exc)

    # v3 live runtime initialization
    ingest_server = None
    ingest_thread = None
    if getattr(v3_config, "V3_ENABLED", True):
        try:
            v3_store.create_tables()
            v3_sup = Supervisor()
            app.state.v3_supervisor = v3_sup
            adapter = StoreAdapter(v3_store.get_db_path())
            v3_bus = Bus(supervisor=v3_sup, ctx=AgentContext(settings=v3_config.get_settings(), store=adapter))
            app.state.v3_bus = v3_bus
            register_all(v3_sup, v3_bus)

            # Auto-persist signals and events in live mode
            orig_bus_publish = v3_bus.publish

            def _live_persist_publish(message: Message, agent: Agent | None = None) -> bool:
                res = orig_bus_publish(message, agent=agent)
                if res:
                    if message.topic == "signals" and isinstance(message.payload, Signal):
                        _persist_signal(adapter, message.payload, message.created_at)
                    elif message.topic == "events" and isinstance(message.payload, Event):
                        _persist_event(adapter, message.payload)
                return res

            v3_bus.publish = _live_persist_publish

            # Background thread running the Ingest service on INGEST_PORT (8001)
            def _handoff(topic: str, records: list[dict]):
                source = Source.okta if "okta" in topic else Source.cloudtrail
                msg = v3_bus.ctx.new_message(
                    topic=topic,
                    payload=RawLog(source=source, records=records),
                    producer="ingest_8001",
                )
                v3_bus.publish(msg)

            ingest_app = create_ingest_app(bus_handoff=_handoff, supervisor=v3_sup)
            ingest_cfg = uvicorn.Config(
                ingest_app,
                host="0.0.0.0",
                port=v3_config.INGEST_PORT,
                log_level="warning",
            )
            ingest_server = uvicorn.Server(ingest_cfg)
            ingest_server.install_signal_handlers = lambda: None
            ingest_thread = threading.Thread(
                target=ingest_server.run,
                name="v3_ingest_8001",
                daemon=True,
            )
            ingest_thread.start()
            log.info("Started IdentityShield v3 Ingest service on port %d", v3_config.INGEST_PORT)
        except Exception:
            log.exception("Failed to initialize v3 runtime")

    yield

    # Clean shutdown
    if ingest_server is not None:
        ingest_server.should_exit = True
    if ingest_thread is not None and ingest_thread.is_alive():
        ingest_thread.join(timeout=1.0)


app = FastAPI(title="IdentityShield", version="1.0", lifespan=lifespan)
app.state.result = None
app.state.startup_error = ""


def _err(status: int, error: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": error, "detail": detail, "request_id": uuid.uuid4().hex[:12]},
    )


@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    code = {404: "not_found", 409: "conflict", 503: "pipeline_not_ready"}.get(exc.status_code, "http_error")
    return _err(exc.status_code, code, str(exc.detail))


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    return _err(422, "validation_error", str(exc.errors()))


@app.exception_handler(Exception)
async def unhandled_error(_: Request, exc: Exception):
    log.exception("Unhandled error")
    return _err(500, "internal_error", "Unexpected server error. See server log.")


for module in (health, alerts, identities, metrics, audit):
    app.include_router(module.router, prefix="/api")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/v3/index.html")


STATIC_DIR.mkdir(parents=True, exist_ok=True)
from app.api import v21 as _v21_api  # v2.1 kit

app.include_router(_v21_api.router, prefix="/api")

if getattr(v3_config, "V3_ENABLED", True):
    from app.v3.api import router as v3_router

    app.include_router(v3_router)

_gen_dir = v3_config.ROOT_DIR / "generator"
if _gen_dir.is_dir():
    app.mount("/generator", StaticFiles(directory=_gen_dir, html=True), name="generator")

app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
