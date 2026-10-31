"""HTTP API for the 30-day memory. Mounted by app/main.py with prefix /api/memory (before the static mount).

Thin handlers: validate input, call MemoryEngine, return JSON. Mutating routes require the X-Analyst-Token header
when ANALYST_TOKEN is set in the environment.
"""
from __future__ import annotations

import hmac
import json
import logging
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from . import config, synth
from .engine import MemoryEngine

log = logging.getLogger(__name__)
router = APIRouter(tags=["memory30"])

_engine: MemoryEngine | None = None
_engine_lock = threading.Lock()
_busy = threading.Lock()


def get_engine() -> MemoryEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = MemoryEngine(config.DB_PATH)
        return _engine


def _require_token(request: Request) -> None:
    token = config.analyst_token()
    if not token:
        return
    given = request.headers.get("x-analyst-token", "")
    if not hmac.compare_digest(given.encode(), token.encode()):
        raise HTTPException(status_code=401, detail="Missing or wrong X-Analyst-Token")


def _safe_paths(paths: list[str] | None) -> list[Path] | None:
    """Only allow paths inside the project's data/ folder."""
    if not paths:
        return None
    root = config.DATA_DIR.resolve()
    out = []
    for p in paths:
        rp = (config.ROOT / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
        if root != rp and root not in rp.parents:
            raise HTTPException(status_code=422, detail=f"Path must be inside data/: {p}")
        out.append(rp)
    return out


class IngestBody(BaseModel):
    paths: list[str] | None = None


class SynthBody(BaseModel):
    days: int = Field(30, ge=7, le=120)
    identities: int = Field(200, ge=5, le=2000)
    seed: int = 42
    ingest: bool = True
    reset_first: bool = False


class PruneBody(BaseModel):
    vacuum: bool = False


@router.get("/stats")
def stats():
    return get_engine().stats()


@router.get("/identities")
def identities(limit: int = 50):
    return {"identities": get_engine().identities(limit)}


@router.get("/identity/{identity_id}")
def identity(identity_id: str, days: int = 30):
    view = get_engine().identity_view(identity_id, days)
    if view is None:
        raise HTTPException(status_code=404, detail="Identity not found in memory")
    return view


@router.get("/findings")
def findings(limit: int = 100, identity: str | None = None):
    return {"findings": get_engine().findings(limit=limit, identity=identity)}


@router.get("/evidence")
def evidence(ids: str = ""):
    id_list = [i for i in ids.split(",") if i][:200]
    return {"events": get_engine().evidence_events(id_list)}


@router.post("/ingest")
def ingest(request: Request, body: IngestBody | None = None):
    _require_token(request)
    paths = _safe_paths((body or IngestBody()).paths)
    if not _busy.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another memory job is running")
    try:
        return get_engine().ingest_paths(paths)
    finally:
        _busy.release()


@router.post("/synth")
def synth_run(request: Request, body: SynthBody | None = None):
    _require_token(request)
    body = body or SynthBody()
    if not _busy.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another memory job is running")
    try:
        eng = get_engine()
        if body.reset_first:
            eng.reset()
        info = synth.write(config.SYNTH_DIR, body.days, body.identities, body.seed)
        out = {"generated": info}
        if body.ingest:
            out["ingest"] = eng.ingest_paths([config.SYNTH_DIR / "okta", config.SYNTH_DIR / "cloudtrail"])
            labels = json.loads((config.SYNTH_DIR / "labels.json").read_text(encoding="utf-8"))
            out["report"] = synth.report(eng, labels)
        return out
    finally:
        _busy.release()


@router.get("/report")
def report():
    lp = config.SYNTH_DIR / "labels.json"
    if not lp.exists():
        return {"status": "no_synthetic_labels"}
    return synth.report(get_engine(), json.loads(lp.read_text(encoding="utf-8")))


@router.post("/prune")
def prune(request: Request, body: PruneBody | None = None):
    _require_token(request)
    if not _busy.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another memory job is running")
    try:
        return get_engine().prune(vacuum=(body or PruneBody()).vacuum)
    finally:
        _busy.release()


@router.post("/reset")
def reset(request: Request):
    _require_token(request)
    if not _busy.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Another memory job is running")
    try:
        get_engine().reset()
        return {"status": "reset"}
    finally:
        _busy.release()
