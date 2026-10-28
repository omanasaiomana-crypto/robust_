"""Tamper-evident audit log query and cryptographic verification endpoints."""
import logging
from typing import Any
from fastapi import APIRouter

from app import audit
from app.models import AuditEntry
from app.utils import clean_json

log = logging.getLogger(__name__)

router = APIRouter(tags=["audit"])


@router.get("/audit", response_model=list[AuditEntry])
def get_audit_log(limit: int = 200) -> list[AuditEntry]:
    return audit.list_entries(limit=limit)


@router.get("/audit/verify")
def verify_audit_chain() -> dict[str, Any]:
    valid, broken_at = audit.verify()
    return clean_json({"valid": valid, "broken_at": broken_at})
