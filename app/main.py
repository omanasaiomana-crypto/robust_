"""FastAPI main application: lifecycle, routers, exception handlers, and static files."""
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import notify, runner, store
from app.api import alerts, analytics, audit, health, identities, metrics, notifications, scan
from app.config import STATIC_DIR
from app.pipeline import run_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("identityshield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.result = None
    app.state.startup_error = ""
    store.init_db()
    notify.init_tables()
    runner.run_now(app)
    yield


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


for module in (health, alerts, identities, metrics, audit, analytics, notifications, scan):
    app.include_router(module.router, prefix="/api")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/index.html")


STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
