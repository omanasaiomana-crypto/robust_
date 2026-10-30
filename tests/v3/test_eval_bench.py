"""Unit and integration tests for IdentityShield v3 Evaluation & Benchmark engines.

Follows context.md Section 14, 17 and Phase P17 specification:
- Tests metric math on tiny synthetic fixture (event P/R/F1, session precision, chain recall, explanation quality)
- Tests calibration math, 10-bin reliability diagram, and strict weight floors (D-PE >= 0.6, D-DEF >= 0.6)
- Tests dataset splitting logic (70/30, seed 42)
- Tests evaluation results file schema in data/eval/latest.json
- Tests benchmark runner multiplier 1 completes on fixture in < 30 s with full schema (latencies, RAM, machine info)
- Tests API endpoints GET /api/v3/metrics/kpi, GET /api/v3/metrics/perf, and POST /api/v3/bench/run
"""
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.v3 import config
from app.v3.bench import (
    get_machine_info,
    run_benchmark,
)
from app.v3.evaluate import (
    _calibrate_detection_weights,
    _compute_metrics_for_run,
    run_evaluation,
    split_dataset,
)
from app.v3.models import Source
from app.v3.store import close_connection, create_tables, set_db_path


@pytest.fixture
def client(tmp_db: Path):
    set_db_path(tmp_db)
    create_tables(tmp_db)
    with TestClient(app) as test_client:
        yield test_client
    close_connection(tmp_db)


# ---------------------------------------------------------------------------
# 1. Metric Math on Labeled Fixture
# ---------------------------------------------------------------------------


def test_metric_math_on_fixture() -> None:
    """Validate mathematical precision of event/session metrics, recall, and quality ratios."""
    # 5 events: 3 malicious (ev1, ev2, ev3), 2 benign (ev4, ev5)
    events: list[tuple[float, Source, dict[str, Any]]] = [
        (100.0, Source.okta, {"uuid": "ev1", "label": "token_abuse", "actor": {"alternateId": "alice"}, "authenticationContext": {"externalSessionId": "sess-1"}}),
        (110.0, Source.okta, {"uuid": "ev2", "label": "privilege_escalation", "actor": {"alternateId": "alice"}, "authenticationContext": {"externalSessionId": "sess-1"}}),
        (120.0, Source.cloudtrail, {"eventID": "ev3", "label": "unusual_api", "userIdentity": {"userName": "bob"}, "sourceIPAddress": "sess-2"}),
        (130.0, Source.okta, {"uuid": "ev4", "label": "benign", "actor": {"alternateId": "charlie"}, "authenticationContext": {"externalSessionId": "sess-3"}}),
        (140.0, Source.cloudtrail, {"eventID": "ev5", "label": "benign", "userIdentity": {"userName": "charlie"}, "sourceIPAddress": "sess-3"}),
    ]

    # Pipeline output:
    # Predicts ev1 and ev2 (TP=2) and ev4 (FP=1). Missed ev3 (FN=1).
    # sess-1 predicted (TP=1), sess-3 predicted (FP=1). sess-2 missed (FN=1).
    mock_run_results = {
        "cases": [
            {
                "case_id": "case-01",
                "session_id": "sess-1",
                "reasons": json.dumps([
                    {"title": "Abuse", "evidence_event_ids": ["ev1", "ev2"]},
                ]),
                "counterfactuals": json.dumps([{"signal_id": "sig-1", "score_drop": 25.0}]),
                "case_steps": json.dumps([
                    {"step": 1, "mitre_technique": "T1078", "evidence_event_ids": ["ev1"]},
                    {"step": 2, "mitre_technique": "T1098", "evidence_event_ids": ["ev2"]},
                ]),
            },
            {
                "case_id": "case-02",
                "session_id": "sess-3",
                "reasons": json.dumps([
                    {"title": "False Alarm", "evidence_event_ids": ["ev4"]},
                ]),
                "counterfactuals": json.dumps([]),
                "case_steps": json.dumps([]),
            },
        ],
        "signals": [
            {"signal_id": "s1"},
            {"signal_id": "s2"},
            {"signal_id": "s3"},
            {"signal_id": "s4"},
        ],
        "events": [],
    }

    metrics = _compute_metrics_for_run(events, mock_run_results)

    # Event TP=2 (ev1, ev2), FP=1 (ev4), FN=1 (ev3)
    # Event Precision = 2 / (2 + 1) = 0.6667
    # Event Recall = 2 / (2 + 1) = 0.6667
    # Event F1 = 0.6667
    assert metrics["event_precision"] == 0.6667
    assert metrics["event_recall"] == 0.6667
    assert metrics["event_f1"] == 0.6667

    # Session Precision: 2 sessions alerted (sess-1, sess-3). True malicious = sess-1. 1 / 2 = 0.5
    assert metrics["session_precision"] == 0.5

    # Ordered step recall: sess-1 has true chain [ev1, ev2], both found -> 1.0
    assert metrics["chain_reconstruction_recall"] == 1.0

    # Explanation quality:
    # 2 reasons total, both cite evidence -> 1.0
    assert metrics["explanation_quality"]["evidence_citing_ratio"] == 1.0
    # 1 of 2 cases has counterfactual -> 0.5
    assert metrics["explanation_quality"]["counterfactual_present_ratio"] == 0.5
    # 1 of 2 cases has mitre -> 0.5
    assert metrics["explanation_quality"]["mitre_present_ratio"] == 0.5

    # Alert reduction: 4 signals -> 2 cases: (1 - 2/4) * 100 = 50.0%
    assert metrics["alert_reduction_pct"] == 50.0


# ---------------------------------------------------------------------------
# 2. Calibration & Weight Floors
# ---------------------------------------------------------------------------


def test_calibration_and_floors() -> None:
    """Verify LogisticRegression calibration respects strict weight floors and 10 bins."""
    train_events: list[tuple[float, Source, dict[str, Any]]] = [
        (10.0, Source.okta, {"uuid": f"e{i}", "label": "attack" if i % 2 == 0 else "benign", "actor": {"alternateId": f"user{i}"}, "authenticationContext": {"externalSessionId": f"s{i}"}})
        for i in range(20)
    ]
    test_events: list[tuple[float, Source, dict[str, Any]]] = [
        (20.0, Source.okta, {"uuid": f"te{i}", "label": "attack" if i % 2 == 0 else "benign", "actor": {"alternateId": f"tuser{i}"}, "authenticationContext": {"externalSessionId": f"ts{i}"}})
        for i in range(10)
    ]

    train_signals: list[dict[str, Any]] = [
        {"session_id": f"s{i}", "detection_id": "D-PE-01", "strength": 0.9 if i % 2 == 0 else 0.1}
        for i in range(20)
    ]
    test_signals: list[dict[str, Any]] = [
        {"session_id": f"ts{i}", "detection_id": "D-DEF-01", "strength": 0.85 if i % 2 == 0 else 0.15}
        for i in range(10)
    ]

    calib = _calibrate_detection_weights(
        train_signals=train_signals,
        train_events=train_events,
        test_signals=test_signals,
        test_events=test_events,
    )

    # Check Brier score non-negative
    assert 0.0 <= calib["brier_score"] <= 1.0

    # Check 10 bins
    diagram = calib["reliability_diagram"]
    assert len(diagram) == 10
    for b in diagram:
        assert "bin" in b
        assert "predicted_mean" in b
        assert "observed_frequency" in b
        assert "count" in b

    # Check strict floors: D-PE >= 0.6, D-DEF >= 0.6
    weights = calib["calibrated_weights"]
    assert weights["D-PE"] >= 0.6
    assert weights["D-DEF"] >= 0.6
    for w in weights.values():
        assert 0.0 <= w <= 1.0


# ---------------------------------------------------------------------------
# 3. Dataset Splitting Logic
# ---------------------------------------------------------------------------


def test_split_dataset_ratio_and_seed() -> None:
    """Verify split_dataset produces exact 70/30 distribution and determinism with seed."""
    okta_recs = [
        {"uuid": f"ok-{i}", "published": f"2026-10-30T12:{i:02d}:00Z", "actor": {"alternateId": f"user-{i % 10}"}, "label": "benign" if i < 30 else "attack"}
        for i in range(40)
    ]
    ct_recs = [
        {"eventID": f"ct-{i}", "eventTime": f"2026-10-30T13:{i:02d}:00Z", "userIdentity": {"userName": f"user-{i % 10}"}, "label": "benign"}
        for i in range(60)
    ]

    # Identity split
    train_ev, test_ev = split_dataset(okta_recs, ct_recs, split_method="identity", seed=42, test_size=0.3)
    total = len(train_ev) + len(test_ev)
    assert total == 100
    assert 20 <= len(test_ev) <= 40  # Close to 30%

    # Determinism
    train_ev2, _ = split_dataset(okta_recs, ct_recs, split_method="identity", seed=42, test_size=0.3)
    assert len(train_ev) == len(train_ev2)

    # Time split
    train_t, test_t = split_dataset(okta_recs, ct_recs, split_method="time", seed=42, test_size=0.3)
    assert len(train_t) == 70
    assert len(test_t) == 30


# ---------------------------------------------------------------------------
# 4. Evaluation Results File Shapes
# ---------------------------------------------------------------------------


def test_evaluation_latest_json_shape() -> None:
    """Verify latest.json schema in data/eval conforms to PRD §22."""
    latest_path = config.ROOT_DIR / "data" / "eval" / "latest.json"
    if not latest_path.is_file():
        # Run a minimal evaluation if not present
        run_evaluation(split_method="identity", seed=42, test_size=0.3)

    assert latest_path.is_file()
    payload = json.loads(latest_path.read_text(encoding="utf-8"))

    assert payload["status"] == "completed"
    assert "dataset_hash" in payload
    assert "config_hash" in payload
    assert "split" in payload
    assert "configurations" in payload

    cfgs = payload["configurations"]
    for mode in ("rules_only", "ml_only", "hybrid"):
        assert mode in cfgs
        m = cfgs[mode]
        for metric_key in ("event_precision", "event_recall", "event_f1", "session_precision", "alert_reduction_pct"):
            assert metric_key in m

    assert "calibration" in payload
    cal = payload["calibration"]
    assert "brier_score" in cal
    assert "reliability_diagram" in cal
    assert len(cal["reliability_diagram"]) == 10
    assert "calibrated_weights" in cal


# ---------------------------------------------------------------------------
# 5. Benchmark Runner (Multiplier 1 on Fixtures < 30s)
# ---------------------------------------------------------------------------


def test_benchmark_multiplier_1_on_fixture(tmp_path: Path) -> None:
    """Verify benchmark run at multiplier 1 runs quickly and writes full schema."""
    fixture_okta = [
        {"uuid": "b-ok-1", "published": "2026-10-30T10:00:00Z", "actor": {"alternateId": "alice"}, "label": "benign"},
        {"uuid": "b-ok-2", "published": "2026-10-30T10:01:00Z", "actor": {"alternateId": "alice"}, "label": "token_abuse"},
    ]
    fixture_ct = [
        {"eventID": "b-ct-1", "eventTime": "2026-10-30T10:02:00Z", "userIdentity": {"userName": "alice"}, "label": "privilege_escalation"},
    ]

    with patch("app.v3.bench._load_base_records", return_value=(fixture_okta, fixture_ct)):
        t0 = time.monotonic()
        results = run_benchmark(multiplier=1, output_dir=tmp_path)
        duration = time.monotonic() - t0

    assert duration < 30.0  # Must be fast (< 30s)
    assert results["status"] == "completed"
    assert results["total_events"] == 3
    assert results["multiplier"] == 1
    assert results["events_per_second"] > 0
    assert results["peak_memory_mb"] > 0
    assert "latencies" in results
    assert "receive_to_signal" in results["latencies"]
    assert "session_close_to_case" in results["latencies"]
    assert "machine_info" in results

    # Verify files created in tmp_path
    latest_file = tmp_path / "latest.json"
    assert latest_file.is_file()
    saved = json.loads(latest_file.read_text(encoding="utf-8"))
    assert saved["total_events"] == 3


def test_machine_info_fields() -> None:
    """Verify host machine specs metadata format."""
    info = get_machine_info()
    assert "os" in info
    assert "cpu" in info
    assert "cores" in info
    assert info["cores"] >= 1
    assert "ram_gb" in info
    assert info["ram_gb"] > 0
    assert "python_version" in info


# ---------------------------------------------------------------------------
# 6. API Metrics & Benchmark Endpoints
# ---------------------------------------------------------------------------


def test_api_metrics_kpi_and_perf(client: TestClient) -> None:
    """Verify /api/v3/metrics/kpi and /api/v3/metrics/perf endpoints."""
    # 1. KPI endpoint
    resp = client.get("/api/v3/metrics/kpi")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    if data["status"] == "completed":
        assert "configurations" in data
        assert "calibration" in data

    # 2. Perf endpoint
    resp_perf = client.get("/api/v3/metrics/perf")
    assert resp_perf.status_code == 200
    perf_data = resp_perf.json()
    assert "alert_reduction_pct" in perf_data or "events_per_second" in perf_data

    # 3. Benchmark run endpoint
    resp_bench = client.post("/api/v3/bench/run?multiplier=1")
    assert resp_bench.status_code == 200
    bench_ack = resp_bench.json()
    assert bench_ack["status"] in ("started", "already_running")
    assert bench_ack["multiplier"] == 1
