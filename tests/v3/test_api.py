"""Integration and contract tests for IdentityShield v3 API (/api/v3).

Covers Phase P12 requirements:
- Every GET returns 200 with expected keys on a dataset run of the fixtures
- Mutating routes 401 without token when ANALYST_TOKEN is configured
- Approve flow through API changes action state
- SSE endpoint streams a heartbeat and a trace event
- /api/v3/run/dataset produces at least one case on the E1 fixture
- v2 smoke endpoints continue to work as expected
"""
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.v3 import config as v3_cfg
from app.v3.models import (
    ActionKind,
    ActionState,
)
from app.v3.pipeline_v3 import run_dataset
from app.v3.sse import broadcaster
from app.v3.store import create_tables, fetch_one, insert_many, set_db_path

E1_FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "e1_attack.json"


@pytest.fixture
def client(tmp_db: Path) -> Generator[TestClient, None, None]:
    """TestClient configured with temporary database."""
    set_db_path(tmp_db)
    create_tables(tmp_db)
    with TestClient(app) as test_client:
        yield test_client


# ---------------------------------------------------------------------------
# 1. Dataset Execution on E1 Fixture
# ---------------------------------------------------------------------------


def test_run_dataset_e1_produces_case(tmp_db: Path, client: TestClient) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    # Execute dataset run on E1 fixture
    resp = client.post("/api/v3/run/dataset", json={"paths": str(E1_FIXTURE_PATH), "pace": 0.0})
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["status"] == "completed"
    assert summary["events"] >= 8
    assert summary["cases"] >= 1

    # Verify case endpoint reflects the produced case
    c_resp = client.get("/api/v3/cases")
    assert c_resp.status_code == 200
    c_data = c_resp.json()
    assert c_data["total"] >= 1
    assert len(c_data["items"]) >= 1
    first_case = c_data["items"][0]
    assert first_case["identity_id"] == "alice@example.com"
    assert first_case["band"] in ("restrict", "revoke")


# ---------------------------------------------------------------------------
# 2. Every GET Returns 200 with Expected Keys
# ---------------------------------------------------------------------------


def test_every_get_endpoint_returns_200(tmp_db: Path, client: TestClient) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    # First run the E1 fixture so the database is populated
    run_dataset(paths=E1_FIXTURE_PATH, db_path=tmp_db)

    # 1. /api/v3/health
    r_health = client.get("/api/v3/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"
    assert r_health.json()["v3_enabled"] is True

    # 2. /api/v3/agents
    r_agents = client.get("/api/v3/agents")
    assert r_agents.status_code == 200
    assert len(r_agents.json()) == 15

    # 3. /api/v3/identities
    r_ids = client.get("/api/v3/identities")
    assert r_ids.status_code == 200
    ids_data = r_ids.json()
    assert "items" in ids_data and "total" in ids_data
    target_id = ids_data["items"][0]["identity_id"] if ids_data["items"] else "alice@example.com"

    # Seed identity if empty
    if not ids_data["items"]:
        insert_many("identities_v3", [{
            "identity_id": target_id,
            "primary_user": "Alice",
            "email": "alice@example.com",
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
        }], db_path=tmp_db)

    # 4. /api/v3/identities/{id}
    r_id = client.get(f"/api/v3/identities/{target_id}")
    assert r_id.status_code == 200
    id_data = r_id.json()
    assert "identity" in id_data and "risk" in id_data

    # 5. /api/v3/identities/{id}/graph
    r_id_graph = client.get(f"/api/v3/identities/{target_id}/graph")
    assert r_id_graph.status_code == 200
    assert "nodes" in r_id_graph.json() and "edges" in r_id_graph.json()

    # 6. /api/v3/graph/global
    r_global_graph = client.get("/api/v3/graph/global")
    assert r_global_graph.status_code == 200
    assert "nodes" in r_global_graph.json() and "edges" in r_global_graph.json()

    # 7. /api/v3/geo/logins
    r_geo = client.get("/api/v3/geo/logins")
    assert r_geo.status_code == 200
    assert "points" in r_geo.json() and "arcs" in r_geo.json()

    # 8. /api/v3/cases
    r_cases = client.get("/api/v3/cases")
    assert r_cases.status_code == 200
    cases_data = r_cases.json()
    assert "items" in cases_data and "total" in cases_data
    assert cases_data["total"] >= 1
    case_id = cases_data["items"][0]["case_id"]

    # 9. /api/v3/cases/{id}
    r_case_det = client.get(f"/api/v3/cases/{case_id}")
    assert r_case_det.status_code == 200
    c_det = r_case_det.json()
    assert c_det["case_id"] == case_id
    assert "chain" in c_det and "reasons" in c_det

    # 10. /api/v3/actions
    r_actions = client.get("/api/v3/actions")
    assert r_actions.status_code == 200
    assert "items" in r_actions.json() and "total" in r_actions.json()

    # 11. /api/v3/playbooks
    r_playbooks = client.get("/api/v3/playbooks")
    assert r_playbooks.status_code == 200
    assert len(r_playbooks.json()) >= 5

    # 12. /api/v3/run/status
    r_status = client.get("/api/v3/run/status")
    assert r_status.status_code == 200
    assert "running" in r_status.json()

    # 13. /api/v3/metrics/kpi
    r_kpi = client.get("/api/v3/metrics/kpi")
    assert r_kpi.status_code == 200

    # 14. /api/v3/metrics/perf
    r_perf = client.get("/api/v3/metrics/perf")
    assert r_perf.status_code == 200
    perf_data = r_perf.json()
    assert "p50_ms" in perf_data and "p95_ms" in perf_data

    # 15. /api/v3/config
    r_cfg = client.get("/api/v3/config")
    assert r_cfg.status_code == 200
    assert r_cfg.json()["v3_enabled"] is True

    # 16. /api/v3/config/versions
    r_vers = client.get("/api/v3/config/versions")
    assert r_vers.status_code == 200
    assert isinstance(r_vers.json(), list)


# ---------------------------------------------------------------------------
# 3. Mutating Routes Require Token when ANALYST_TOKEN is Set
# ---------------------------------------------------------------------------


def test_mutating_routes_401_without_token(
    tmp_db: Path,
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    # Configure analyst token
    secret_token = "analyst-secret-xyz"
    monkeypatch.setenv("ANALYST_TOKEN", secret_token)
    monkeypatch.setattr(v3_cfg, "_settings_cache", None)

    # 1. Label endpoint without token -> 401
    r_lbl = client.post("/api/v3/cases/c1/label", json={"verdict": "true_positive"})
    assert r_lbl.status_code == 401
    assert "Invalid or missing analyst token" in r_lbl.json()["detail"]

    # 2. Action approve without token -> 401
    r_app = client.post("/api/v3/actions/act1/approve")
    assert r_app.status_code == 401

    # 3. Action reject without token -> 401
    r_rej = client.post("/api/v3/actions/act1/reject")
    assert r_rej.status_code == 401

    # 4. Action rollback without token -> 401
    r_rb = client.post("/api/v3/actions/act1/rollback")
    assert r_rb.status_code == 401

    # 5. Bench run without token -> 401
    r_bench = client.post("/api/v3/bench/run")
    assert r_bench.status_code == 401

    # 6. Config rollback without token -> 401
    r_cfg_rb = client.post("/api/v3/config/rollback/1")
    assert r_cfg_rb.status_code == 401

    # Providing correct token succeeds auth check
    r_bench_ok = client.post("/api/v3/bench/run", headers={"X-Analyst-Token": secret_token})
    assert r_bench_ok.status_code == 200


# ---------------------------------------------------------------------------
# 4. Action Approve Flow Through API
# ---------------------------------------------------------------------------


def test_approve_flow_through_api(tmp_db: Path, client: TestClient) -> None:
    set_db_path(tmp_db)
    create_tables(tmp_db)

    # Seed an action in pending_approval state
    act_id = "act-api-test-01"
    now_iso = datetime.now(UTC).isoformat()
    insert_many("actions_v3", [{
        "action_id": act_id,
        "case_id": "case-test-1",
        "playbook_id": "PB-03",
        "action_kind": ActionKind.revoke_sessions.value,
        "approval_required": 1,
        "state": ActionState.pending_approval.value,
        "simulator_ref": None,
        "reason": "Revoke sessions pending analyst approval",
        "created_at": now_iso,
        "updated_at": now_iso,
    }], db_path=tmp_db)

    # Approve via API
    resp = client.post(
        f"/api/v3/actions/{act_id}/approve",
        json={"analyst": "analyst_carol", "reason": "Confirmed incident"},
    )
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["action_id"] == act_id
    assert res_data["state"] == ActionState.applied.value
    assert res_data["approved_by"] == "analyst_carol"

    # Verify persisted in database
    row = fetch_one("SELECT * FROM actions_v3 WHERE action_id = ?", (act_id,), db_path=tmp_db)
    assert row is not None
    assert row["state"] == ActionState.applied.value


# ---------------------------------------------------------------------------
# 5. Server-Sent Events (SSE) Stream
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_sse_endpoint_streams_heartbeat_and_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.v3.sse as sse_mod
    from app.v3.sse import sse_stream

    monkeypatch.setattr(sse_mod, "HEARTBEAT_INTERVAL", 0.05)

    response = await sse_stream()
    assert response.status_code == 200
    assert response.media_type == "text/event-stream"
    assert response.headers["Cache-Control"] == "no-cache"

    gen = response.body_iterator

    # 1. Connection confirmation
    ev_connected = await anext(gen)
    assert "event: connected" in ev_connected

    # 2. Heartbeat comment emitted on timeout
    ev_heartbeat = await anext(gen)
    assert ": heartbeat\n\n" in ev_heartbeat

    # 3. Trace event published via broadcaster delivered to stream
    broadcaster.publish("trace", {"seq": 1, "agent_id": "a01", "message": "Collector initialized"})
    ev_trace = await anext(gen)
    assert "event: trace" in ev_trace
    assert "Collector initialized" in ev_trace

    await gen.aclose()


# ---------------------------------------------------------------------------
# 6. V2 Smoke Still Passes
# ---------------------------------------------------------------------------


def test_v2_smoke_still_passes(client: TestClient) -> None:
    # Verify existing v2 endpoints operate normally
    r_v2_health = client.get("/api/health")
    assert r_v2_health.status_code == 200

    r_v2_alerts = client.get("/api/alerts")
    assert r_v2_alerts.status_code == 200

    r_v2_identities = client.get("/api/identities")
    assert r_v2_identities.status_code == 200

    r_root = client.get("/", follow_redirects=False)
    assert r_root.status_code in (200, 307)
