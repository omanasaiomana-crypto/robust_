"""IdentityShield v3 Performance & Throughput Benchmark Engine.

Conforms to context.md Section 14, 17 and PRD §22, §23:
- Replays official dataset with fresh IDs at given multiplier (1, 5, 10) in drain mode.
- Measures:
  * Per-event receive->signal latency percentiles (p50, p95, max in ms)
  * Session-close->case latency percentiles (p50, p95, max in ms)
  * Events per second throughput
  * Peak queue depth across all bus topics
  * Peak memory via tracemalloc (MB)
  * Alert reduction ratio: 1 - (cases / signals)
- Gathers hardware & host platform metadata (CPU, cores, RAM, OS, Python version).
- Writes data/bench/results_<timestamp>.json and data/bench/latest.json.
- Prints clean ASCII benchmark table to stdout.

CLI Runner: `python -m app.v3.bench --multiplier 1|5|10`
API Runner: `POST /api/v3/bench/run` (calls run_benchmark in background thread)
"""
import argparse
import copy
import json
import logging
import os
import platform
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from app.v3 import audit, config, store
from app.v3.agents import register_all
from app.v3.agents.a01_collector import to_timestamp
from app.v3.agents.base import Agent, AgentContext
from app.v3.bus import Bus
from app.v3.models import Case, Event, Message, RawLog, Signal, Source
from app.v3.pipeline_v3 import StoreAdapter, _persist_event, _persist_signal
from app.v3.supervisor import Supervisor

log = logging.getLogger("identityshield.bench")
ROOT_DIR = config.ROOT_DIR
BENCH_DIR = ROOT_DIR / "data" / "bench"
SAMPLE_DIR = ROOT_DIR / "data" / "sample"


def get_machine_info() -> dict[str, Any]:
    """Gather host machine specs for hardware normalization."""
    # CPU
    cpu = platform.processor() or os.environ.get("PROCESSOR_IDENTIFIER", "x86_64")
    cores = os.cpu_count() or 1

    # RAM (via psutil or Windows GlobalMemoryStatusEx fallback)
    ram_gb = 16.0
    try:
        import psutil
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 1)
    except Exception:  # noqa: BLE001
        try:
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            ram_gb = round(stat.ullTotalPhys / (1024 ** 3), 1)
        except Exception:  # noqa: BLE001, S110
            pass

    return {
        "os": f"{platform.system()} {platform.release()}",
        "cpu": cpu,
        "cores": cores,
        "ram_gb": ram_gb,
        "python_version": platform.python_version(),
    }


def _load_base_records() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load sample Okta and CloudTrail events."""
    okta_path = SAMPLE_DIR / "okta.json"
    ct_path = SAMPLE_DIR / "cloudtrail.json"

    okta_records: list[dict[str, Any]] = []
    ct_records: list[dict[str, Any]] = []

    if okta_path.is_file():
        try:
            data = json.loads(okta_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                okta_records = data
            elif isinstance(data, dict) and "okta" in data:
                okta_records = data["okta"]
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to load %s: %s", okta_path, exc)

    if ct_path.is_file():
        try:
            data = json.loads(ct_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                ct_records = data
            elif isinstance(data, dict) and "Records" in data:
                ct_records = data["Records"]
            elif isinstance(data, dict) and "cloudtrail" in data:
                ct_records = data["cloudtrail"]
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to load %s: %s", ct_path, exc)

    return okta_records, ct_records


def generate_multiplied_events(
    okta_records: list[dict[str, Any]],
    ct_records: list[dict[str, Any]],
    multiplier: int = 1,
) -> list[tuple[float, Source, dict[str, Any], str]]:
    """Clone dataset with fresh IDs at the requested multiplier factor."""
    all_events: list[tuple[float, Source, dict[str, Any], str]] = []

    for m in range(multiplier):
        suffix = f"-m{m}" if m > 0 else ""

        for orig in okta_records:
            ev = copy.deepcopy(orig)
            ev_id = str(ev.get("uuid") or "") + suffix
            ev["uuid"] = ev_id

            if suffix:
                actor = ev.get("actor")
                if isinstance(actor, dict):
                    if "alternateId" in actor:
                        actor["alternateId"] = f"{actor['alternateId']}{suffix}"
                    if "id" in actor:
                        actor["id"] = f"{actor['id']}{suffix}"
                ctx = ev.get("authenticationContext")
                if isinstance(ctx, dict) and ctx.get("externalSessionId"):
                    ctx["externalSessionId"] = f"{ctx['externalSessionId']}{suffix}"

            t = to_timestamp(ev.get("published") or ev.get("eventTime"))
            all_events.append((t, Source.okta, ev, ev_id))

        for orig in ct_records:
            ev = copy.deepcopy(orig)
            ev_id = str(ev.get("eventID") or "") + suffix
            ev["eventID"] = ev_id

            if suffix:
                ui = ev.get("userIdentity")
                if isinstance(ui, dict):
                    for k in ("userName", "principalId", "arn"):
                        if ui.get(k):
                            ui[k] = f"{ui[k]}{suffix}"
                    sess_ctx = ui.get("sessionContext")
                    if isinstance(sess_ctx, dict):
                        issuer = sess_ctx.get("sessionIssuer")
                        if isinstance(issuer, dict) and issuer.get("userName"):
                            issuer["userName"] = f"{issuer['userName']}{suffix}"

            t = to_timestamp(ev.get("eventTime") or ev.get("published"))
            all_events.append((t, Source.cloudtrail, ev, ev_id))

    all_events.sort(key=lambda x: x[0])
    return all_events


def _calc_latency_stats(latencies: list[float]) -> dict[str, float]:
    """Calculate p50, p95, max latency in milliseconds."""
    if not latencies:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    arr = np.array(latencies)
    p50 = float(np.percentile(arr, 50))
    p95 = float(np.percentile(arr, 95))
    mx = float(np.max(arr))
    return {
        "p50_ms": round(max(0.01, p50), 2),
        "p95_ms": round(max(0.01, p95), 2),
        "max_ms": round(max(0.01, mx), 2),
    }


def run_benchmark(
    multiplier: int = 1,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Replay dataset at given multiplier, measure performance & write metrics."""
    out_dir = output_dir or BENCH_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    okta_recs, ct_recs = _load_base_records()
    events = generate_multiplied_events(okta_recs, ct_recs, multiplier=multiplier)
    total_events = len(events)

    # Machine info
    machine_info = get_machine_info()

    # Latency tracking state
    receive_times: dict[str, float] = {}
    receive_to_signal_latencies: list[float] = []
    session_close_times: dict[str, float] = {}
    session_to_case_latencies: list[float] = []
    peak_queue_depth = 0

    tracemalloc.start()
    start_wall_time = time.monotonic()

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        bench_db = Path(tmp_dir) / "bench.db"
        store.create_tables(db_path=bench_db)
        adapter = StoreAdapter(bench_db)

        sup = Supervisor()
        bus = Bus(
            supervisor=sup,
            queue_max=max(config.QUEUE_MAX, total_events * 4),
            ctx=AgentContext(settings=config.get_settings(), store=adapter),
        )
        register_all(sup, bus)

        # Hook publish to track event ingestion, latencies, and persistence
        orig_publish = bus.publish

        def _bench_instrumented_publish(message: Message, agent: Agent | None = None) -> bool:
            nonlocal peak_queue_depth
            now_p = time.perf_counter()

            # Record receive time for raw events or normalized events
            if message.topic.startswith("raw."):
                if isinstance(message.payload, RawLog):
                    for r in message.payload.records:
                        rid = str(r.get("uuid") or r.get("eventID") or "")
                        if rid:
                            receive_times[rid] = now_p
            elif message.topic == "events" and isinstance(message.payload, Event):
                _persist_event(adapter, message.payload)
                if message.payload.event_id not in receive_times:
                    receive_times[message.payload.event_id] = now_p

            # Record receive->signal latency
            elif message.topic == "signals" and isinstance(message.payload, Signal):
                _persist_signal(adapter, message.payload, message.created_at)
                for eid in message.payload.evidence_event_ids:
                    if eid in receive_times:
                        lat_ms = (now_p - receive_times[eid]) * 1000.0
                        if lat_ms >= 0:
                            receive_to_signal_latencies.append(lat_ms)

            # Record session activity / close time
            elif message.topic == "sessions":
                sess_payload = message.payload
                sess_id = getattr(sess_payload, "session_id", None) or (
                    sess_payload.get("session_id") if isinstance(sess_payload, dict) else None
                )
                if sess_id:
                    session_close_times[str(sess_id)] = now_p

            # Record session-close->case latency
            elif message.topic == "cases" and isinstance(message.payload, Case):
                s_id = str(message.payload.session_id or "")
                if s_id and s_id in session_close_times:
                    lat_ms = (now_p - session_close_times[s_id]) * 1000.0
                    if lat_ms >= 0:
                        session_to_case_latencies.append(lat_ms)

            # Track peak queue depth
            current_depth = sum(len(q) for q in bus._queues.values())
            peak_queue_depth = max(peak_queue_depth, current_depth)

            return orig_publish(message, agent=agent)

        bus.publish = _bench_instrumented_publish

        try:
            # Replay all events through the bus with periodic draining
            for idx, (_, source, ev, ev_id) in enumerate(events):
                topic = "raw.okta" if source == Source.okta else "raw.cloudtrail"
                receive_times[ev_id] = time.perf_counter()
                msg = bus.ctx.new_message(
                    topic=topic,
                    payload=RawLog(source=source, records=[ev]),
                    producer="benchmarker",
                )
                bus.publish(msg)
                if (idx + 1) % 500 == 0:
                    bus.run_until_idle()

            # Drain pipeline
            bus.run_until_idle()

            # Final tick to flush sliding windows and session closures
            for ag in sup.get_registered_agents():
                ag_state = bus._agent_states.get(ag.agent_id, {})
                for t_msg in ag.on_tick(ag_state, bus.ctx):
                    bus.publish(t_msg)
            bus.run_until_idle()

            total_cases = len(adapter.fetch_all("SELECT case_id FROM cases_v3"))
            total_signals = len(adapter.fetch_all("SELECT signal_id FROM signals_v3"))
        finally:
            store.close_connection(bench_db)

    duration_sec = max(0.001, time.monotonic() - start_wall_time)
    _current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_memory_mb = round(peak_mem / (1024.0 * 1024.0), 2)
    events_per_sec = round(total_events / duration_sec, 2)
    alert_reduct_pct = (
        round((1.0 - (total_cases / total_signals)) * 100.0, 2) if total_signals > 0 else 0.0
    )

    rec_sig_stats = _calc_latency_stats(receive_to_signal_latencies)
    sess_case_stats = _calc_latency_stats(session_to_case_latencies)

    now_iso = datetime.now(UTC).isoformat()
    ts_compact = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    bench_results = {
        "status": "completed",
        "timestamp": now_iso,
        "multiplier": multiplier,
        "total_events": total_events,
        "duration_seconds": round(duration_sec, 2),
        "events_per_second": events_per_sec,
        "peak_queue_depth": peak_queue_depth,
        "peak_memory_mb": peak_memory_mb,
        "alert_reduction_pct": alert_reduct_pct,
        "counts": {
            "total_signals": total_signals,
            "total_cases": total_cases,
        },
        "latencies": {
            "receive_to_signal": rec_sig_stats,
            "session_close_to_case": sess_case_stats,
        },
        "machine_info": machine_info,
    }

    # Write results_<timestamp>.json and latest.json
    res_file = out_dir / f"results_{ts_compact}.json"
    latest_file = out_dir / "latest.json"

    res_file.write_text(json.dumps(bench_results, indent=2), encoding="utf-8")
    latest_file.write_text(json.dumps(bench_results, indent=2), encoding="utf-8")

    audit.append("bench", "benchmark_completed", {
        "multiplier": multiplier,
        "events_per_sec": events_per_sec,
        "p50_signal_ms": rec_sig_stats["p50_ms"],
        "peak_memory_mb": peak_memory_mb,
    })

    return bench_results


def print_benchmark_report(res: dict[str, Any]) -> None:
    """Print ASCII benchmark report to stdout per PRD §22."""
    sep = "=" * 84
    dash = "-" * 84

    m = res["machine_info"]
    lat_sig = res["latencies"]["receive_to_signal"]
    lat_case = res["latencies"]["session_close_to_case"]

    print("\n" + sep)
    print(" IdentityShield v3 — Pipeline Benchmark & Throughput Report")
    print(sep)
    print(f" Multiplier Factor : {res['multiplier']}x ({res['total_events']:,} events processed)")
    print(f" Execution Time    : {res['duration_seconds']}s")
    print(f" Throughput        : {res['events_per_second']:,} events/sec")
    print(f" Peak Memory       : {res['peak_memory_mb']} MB (tracemalloc)")
    print(f" Peak Queue Depth  : {res['peak_queue_depth']} messages")
    print(f" Alert Reduction   : {res['alert_reduction_pct']}% ({res['counts']['total_signals']} signals -> {res['counts']['total_cases']} cases)")
    print(dash)
    print(" [Latency Percentiles (Wall Clock)]")
    print(f"  • Receive -> Signal  : p50={lat_sig['p50_ms']}ms | p95={lat_sig['p95_ms']}ms | max={lat_sig['max_ms']}ms")
    print(f"  • Session -> Case    : p50={lat_case['p50_ms']}ms | p95={lat_case['p95_ms']}ms | max={lat_case['max_ms']}ms")
    print(dash)
    print(" [Host Hardware & Environment]")
    print(f"  • OS / Kernel        : {m['os']}")
    print(f"  • CPU & Cores        : {m['cpu']} ({m['cores']} logical cores)")
    print(f"  • System RAM         : {m['ram_gb']} GB")
    print(f"  • Python Runtime     : v{m['python_version']}")
    print(sep + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IdentityShield v3 Throughput & Latency Benchmark")
    parser.add_argument("--multiplier", type=int, choices=[1, 5, 10], default=1, help="Dataset replay multiplier")
    args = parser.parse_args()

    results = run_benchmark(multiplier=args.multiplier)
    print_benchmark_report(results)
