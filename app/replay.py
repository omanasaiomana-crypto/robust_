"""Empirical latency replay under load (batch prefix replay).

Measures wall-clock latency per event batch prefix to evaluate detection
throughput and response latency under load.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import time

import numpy as np
import pandas as pd

from app.config import (
    LABELS_DIR,
    METADATA_DIR,
    OUTPUT_DIR,
    RAW_CLOUDTRAIL,
    RAW_OKTA,
    SAMPLE_DIR,
    USE_SAMPLE_IF_NO_DATA,
)
from app import sample_data
from app.correlate.sessions import assign_sessions
from app.ingest.enrich import enrich
from app.ingest.loaders import load_cloudtrail, load_labels, load_metadata, load_okta
from app.ingest.normalize import normalize_all
from app.pipeline import detect_and_score

log = logging.getLogger("app.replay")


def load_and_prepare_data(use_sample: bool = False) -> tuple[pd.DataFrame, str]:
    """Load and normalize events once without running detection."""
    has_raw = False
    if RAW_CLOUDTRAIL.exists() and any(p.is_file() for p in RAW_CLOUDTRAIL.iterdir() if not p.name.startswith(".")):
        has_raw = True
    elif RAW_OKTA.exists() and any(p.is_file() for p in RAW_OKTA.iterdir() if not p.name.startswith(".")):
        has_raw = True

    if use_sample or not has_raw:
        data_mode = "sample"
        ct_folder = SAMPLE_DIR
        okta_folder = SAMPLE_DIR
        if not (SAMPLE_DIR / "cloudtrail.json").exists() or not (SAMPLE_DIR / "okta.json").exists():
            log.info("Sample data missing; generating sample dataset in %s", SAMPLE_DIR)
            sample_data.generate(SAMPLE_DIR)
    else:
        data_mode = "official"
        ct_folder = RAW_CLOUDTRAIL
        okta_folder = RAW_OKTA

    raw_ct, _ = load_cloudtrail(ct_folder)
    raw_okta, _ = load_okta(okta_folder)
    metadata = load_metadata(METADATA_DIR)
    labels = load_labels(LABELS_DIR)

    events_df, _ = normalize_all(raw_ct, raw_okta)
    if labels and not events_df.empty:
        for idx, row in events_df.iterrows():
            eid = str(row["event_id"])
            if eid in labels and (not row.get("label") or row.get("label") in ("benign", "None", "")):
                events_df.at[idx, "label"] = labels[eid]

    events_df = enrich(events_df, metadata=metadata)
    if not events_df.empty:
        events_df = assign_sessions(events_df)

    return events_df, data_mode


def run_replay(
    batch_size: int = 500,
    use_sample: bool = False,
    max_batches: int | None = None,
    out_dir: Path | None = None,
) -> dict:
    """Run batch prefix replay and record empirical latency profile."""
    target_dir = Path(out_dir) if out_dir else OUTPUT_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    log.info("Loading and normalizing events for replay...")
    events_df, data_mode = load_and_prepare_data(use_sample=use_sample)

    if events_df.empty:
        log.warning("No events found to replay")
        empty_result = {
            "events": 0,
            "batches": 0,
            "batch_size": batch_size,
            "data_mode": data_mode,
            "throughput": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "max": 0.0,
            "sampled": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(target_dir / "latency.json", "wt", encoding="utf-8") as f:
            json.dump(empty_result, f, indent=2)
        return empty_result

    # Sort events by timestamp
    events_df = events_df.sort_values(by="timestamp").reset_index(drop=True)
    total_events = len(events_df)
    log.info("Starting replay on %d events (mode=%s, batch=%d)", total_events, data_mode, batch_size)

    event_latencies_ms: list[float] = []
    batches_processed = 0
    sampled = False
    loop_start = time.perf_counter()

    for start_idx in range(0, total_events, batch_size):
        if max_batches is not None and batches_processed >= max_batches:
            sampled = True
            log.info("Reached max_batches (%d); stopping early", max_batches)
            break

        elapsed_so_far = time.perf_counter() - loop_start
        if elapsed_so_far > 180.0:
            sampled = True
            log.warning("Replay exceeded 3 minutes (%.1fs); stopping early (sampled=True)", elapsed_so_far)
            break

        end_idx = min(start_idx + batch_size, total_events)
        batch_count = end_idx - start_idx
        prefix = events_df.iloc[:end_idx]

        t0 = time.perf_counter()
        detect_and_score(prefix)
        wall_ms = (time.perf_counter() - t0) * 1000.0

        # Latency of every event in batch k = wall time of prefix detection
        event_latencies_ms.extend([wall_ms] * batch_count)
        batches_processed += 1
        log.info(
            "Batch %d: events %d-%d (prefix %d) -> %.2f ms",
            batches_processed,
            start_idx,
            end_idx,
            end_idx,
            wall_ms,
        )

    total_wall_sec = time.perf_counter() - loop_start
    events_replayed = len(event_latencies_ms)
    throughput = (events_replayed / total_wall_sec) if total_wall_sec > 0 else 0.0

    if event_latencies_ms:
        p50 = float(np.percentile(event_latencies_ms, 50))
        p95 = float(np.percentile(event_latencies_ms, 95))
        max_lat = float(np.max(event_latencies_ms))
    else:
        p50 = p95 = max_lat = 0.0

    result = {
        "events": events_replayed,
        "total_events": total_events,
        "batches": batches_processed,
        "batch_size": batch_size,
        "data_mode": data_mode,
        "throughput": round(throughput, 2),
        "p50": round(p50, 4),
        "p95": round(p95, 4),
        "max": round(max_lat, 4),
        "sampled": sampled,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    out_file = target_dir / "latency.json"
    with open(out_file, "wt", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    log.info("Latency replay completed: %s", result)
    return result


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="Empirical latency replay under load.")
    parser.add_argument("--batch", type=int, default=500, help="Batch size for replay")
    parser.add_argument("--sample", action="store_true", help="Force sample dataset")
    parser.add_argument("--max-batches", type=int, default=None, help="Max batches to process")
    parser.add_argument("--out", type=Path, default=None, help="Output directory")

    args = parser.parse_args()
    res = run_replay(
        batch_size=args.batch,
        use_sample=args.sample,
        max_batches=args.max_batches,
        out_dir=args.out,
    )
    print(f"REPLAY RESULT: events={res['events']} batches={res['batches']} throughput={res['throughput']} ev/s "
          f"p50={res['p50']}ms p95={res['p95']}ms max={res['max']}ms sampled={res['sampled']}")


if __name__ == "__main__":
    main()
