"""Predictions and evaluation artifacts exporter for official scoring and submission."""
import argparse
import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Any

from app import evaluation
from app.config import EXPORT_MIN_RISK, OUTPUT_DIR
from app.pipeline import run_pipeline
from app.utils import clean_json

log = logging.getLogger(__name__)


def export_all(output_dir: Path, use_sample: bool = False) -> dict:
    """Run pipeline and export event_predictions, session_predictions, alerts, and summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log.info("Running pipeline for export (use_sample=%s)...", use_sample)

    result = run_pipeline(use_sample=True if use_sample else None)
    events_df = result.events
    alerts = result.alerts or []

    # Map evidence events to alerts meeting risk threshold
    event_alert_map: dict[str, dict] = {}
    for a in alerts:
        if a.risk >= EXPORT_MIN_RISK:
            for eid in a.evidence_event_ids:
                if not eid:
                    continue
                eid_str = str(eid)
                if eid_str not in event_alert_map or a.risk > event_alert_map[eid_str]["risk"]:
                    event_alert_map[eid_str] = {
                        "risk": a.risk,
                        "patterns": set(a.patterns),
                        "alert_id": a.alert_id,
                    }
                else:
                    event_alert_map[eid_str]["patterns"].update(a.patterns)

    # 1. event_predictions.csv
    event_csv_path = output_dir / "event_predictions.csv"
    with open(event_csv_path, "wt", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["event_id", "session_id", "identity_id", "predicted", "risk", "patterns", "alert_id"])

        if events_df is not None and not events_df.empty:
            for _, row in events_df.iterrows():
                try:
                    eid = str(row.get("event_id", ""))
                    sess = str(row.get("session_id", ""))
                    uid = str(row.get("identity_id", ""))

                    if eid in event_alert_map:
                        match = event_alert_map[eid]
                        writer.writerow([
                            eid,
                            sess,
                            uid,
                            1,
                            match["risk"],
                            "|".join(sorted(match["patterns"])),
                            match["alert_id"],
                        ])
                    else:
                        writer.writerow([eid, sess, uid, 0, 0.0, "", ""])
                except Exception as exc:
                    log.warning("Skipping error row in event export: %s", exc)

    # 2. session_predictions.csv
    # Map alerts by session_id
    alerts_by_sess: dict[str, Any] = {}
    for a in alerts:
        if a.session_id:
            alerts_by_sess[str(a.session_id)] = a

    session_csv_path = output_dir / "session_predictions.csv"
    with open(session_csv_path, "wt", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["session_id", "identity_id", "predicted", "risk", "band", "patterns", "alert_id"])

        if events_df is not None and not events_df.empty and "session_id" in events_df.columns:
            # Group events by session to identify distinct sessions and identity
            for sess_id, sgroup in events_df.groupby("session_id", sort=False):
                try:
                    sess_str = str(sess_id)
                    uid = str(sgroup["identity_id"].iloc[0]) if not sgroup.empty else "unknown"

                    if sess_str in alerts_by_sess:
                        al = alerts_by_sess[sess_str]
                        pred = 1 if al.risk >= EXPORT_MIN_RISK else 0
                        writer.writerow([
                            sess_str,
                            uid,
                            pred,
                            al.risk,
                            al.band,
                            "|".join(al.patterns),
                            al.alert_id,
                        ])
                    else:
                        writer.writerow([sess_str, uid, 0, 0.0, "monitor", "", ""])
                except Exception as exc:
                    log.warning("Skipping error session in session export: %s", exc)

    # 3. alerts.jsonl
    alerts_jsonl_path = output_dir / "alerts.jsonl"
    with open(alerts_jsonl_path, "wt", encoding="utf-8") as f:
        for a in alerts:
            try:
                f.write(a.model_dump_json() + "\n")
            except Exception as exc:
                log.warning("Skipping unparseable alert in jsonl export: %s", exc)

    # 4. summary.json
    summary_path = output_dir / "summary.json"
    summary_data = {
        "total_events": len(events_df) if events_df is not None else 0,
        "total_alerts": len(alerts),
        "data_mode": result.data_mode,
        "metrics": clean_json(result.metrics.model_dump()) if result.metrics else {},
        "baseline_source": evaluation.BASELINE_SOURCE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(summary_path, "wt", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    log.info("Export completed successfully into %s", output_dir)
    return summary_data


def main():
    parser = argparse.ArgumentParser(description="Export IdentityShield predictions and metrics.")
    parser.add_argument("--out", type=str, default=str(OUTPUT_DIR), help="Output directory path")
    parser.add_argument("--sample", action="store_true", help="Force sample dataset run")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    out_dir = Path(args.out)
    summary = export_all(out_dir, use_sample=args.sample)
    print(f"Export finished: {summary['total_events']} events, {summary['total_alerts']} alerts exported to {out_dir}")


if __name__ == "__main__":
    main()
