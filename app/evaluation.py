"""Evaluation metrics calculation: Event precision/recall/F1, session precision, and baseline comparison."""
import logging
import pandas as pd

from app.models import Alert, Metrics, Signal

log = logging.getLogger(__name__)

BASELINE_SOURCE: str = "fallback"


def compute_metrics(
    events_df: pd.DataFrame,
    alerts: list[Alert],
    signals: list[Signal],
    skipped: int = 0,
    elapsed_detection_sec: float = 0.0,
) -> Metrics:
    """Compute performance metrics against labeled data and baseline simple heuristic."""
    total_events = len(events_df) if events_df is not None else 0
    total_alerts = len(alerts) if alerts is not None else 0

    # Latency: load from OUTPUT_DIR/latency.json if present, else fallback to batch average
    median_latency_ms = None
    try:
        from app.config import OUTPUT_DIR
        lat_file = OUTPUT_DIR / "latency.json"
        if lat_file.exists():
            import json
            with open(lat_file, "rt", encoding="utf-8") as f:
                lat_data = json.load(f)
                if isinstance(lat_data, dict) and "p50" in lat_data:
                    median_latency_ms = round(float(lat_data["p50"]), 4)
                    log.info("median_latency_ms set to %s ms from %s", median_latency_ms, lat_file)
    except Exception as exc:
        log.debug("Could not read latency.json: %s", exc)

    if median_latency_ms is None and total_events > 0 and elapsed_detection_sec > 0:
        median_latency_ms = round((elapsed_detection_sec / total_events) * 1000.0, 4)
        log.info("median_latency_ms set to %s ms (estimate from batch mean)", median_latency_ms)

    # Check if ground truth labels exist
    has_labels = (
        events_df is not None
        and not events_df.empty
        and "label" in events_df.columns
        and events_df["label"].dropna().str.lower().ne("benign").any()
    )

    if not has_labels:
        return Metrics(
            event_precision=None,
            event_recall=None,
            event_f1=None,
            session_precision=None,
            baseline_event_f1=None,
            median_latency_ms=median_latency_ms,
            total_events=total_events,
            total_alerts=total_alerts,
            skipped_records=skipped,
        )

    # Ground truth malicious events: label present and not benign
    is_malicious = (
        events_df["label"].notna()
        & (events_df["label"] != "")
        & (events_df["label"] != "None")
        & (events_df["label"].str.lower() != "benign")
    )
    truth_event_ids = set(events_df.loc[is_malicious, "event_id"].dropna().astype(str))

    # Predicted malicious events: evidence events cited across all generated alerts
    pred_event_ids: set[str] = set()
    for a in alerts:
        for eid in a.evidence_event_ids:
            if eid:
                pred_event_ids.add(str(eid))

    # Event-level Precision, Recall, F1
    tp_events = len(pred_event_ids & truth_event_ids)
    fp_events = len(pred_event_ids - truth_event_ids)
    fn_events = len(truth_event_ids - pred_event_ids)

    prec = tp_events / (tp_events + fp_events) if (tp_events + fp_events) > 0 else 0.0
    rec = tp_events / (tp_events + fn_events) if (tp_events + fn_events) > 0 else 0.0
    f1 = (2.0 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    # Session-level precision: fraction of alerts whose session contains at least one ground-truth malicious event
    true_sessions = set(events_df.loc[is_malicious, "session_id"].dropna().astype(str))
    malicious_alerts = sum(1 for a in alerts if str(a.session_id) in true_sessions)
    session_prec = (malicious_alerts / total_alerts) if total_alerts > 0 else 0.0

    # Baseline detector: if official baseline output exists in data/labels, use it instead
    from app.config import LABELS_DIR
    baseline_pred_ids: set[str] = set()
    found_official = False
    if LABELS_DIR.exists():
        for p in sorted(LABELS_DIR.iterdir()):
            if p.is_file() and "baseline" in p.name.lower():
                try:
                    import csv
                    import json
                    if p.suffix.lower() == ".json":
                        with open(p, "rt", encoding="utf-8") as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                baseline_pred_ids = {str(x.get("event_id", x)) for x in data}
                                found_official = True
                    elif p.suffix.lower() == ".csv":
                        with open(p, "rt", encoding="utf-8") as f:
                            reader = csv.DictReader(f)
                            baseline_pred_ids = {str(r.get("event_id", "")) for r in reader if r.get("event_id")}
                            found_official = True
                except Exception as exc:
                    log.warning("Failed to load baseline file %s: %s", p, exc)

    global BASELINE_SOURCE
    if found_official:
        BASELINE_SOURCE = "official"
    else:
        BASELINE_SOURCE = "fallback"
    log.info("Evaluation using baseline source: %s", BASELINE_SOURCE)

    if not found_official:
        # Simple detector flags failed logins and any event from an IP seen with >= 3 failures
        failures = events_df[events_df["outcome"] == "failure"]
        ip_failure_counts = failures["src_ip"].value_counts()
        suspicious_ips = set(ip_failure_counts[ip_failure_counts >= 3].index)

        baseline_mask = (
            (events_df["outcome"] == "failure")
            | (events_df["src_ip"].isin(suspicious_ips))
        )
        baseline_pred_ids = set(events_df.loc[baseline_mask, "event_id"].dropna().astype(str))

    base_tp = len(baseline_pred_ids & truth_event_ids)
    base_fp = len(baseline_pred_ids - truth_event_ids)
    base_fn = len(truth_event_ids - baseline_pred_ids)

    base_prec = base_tp / (base_tp + base_fp) if (base_tp + base_fp) > 0 else 0.0
    base_rec = base_tp / (base_tp + base_fn) if (base_tp + base_fn) > 0 else 0.0
    baseline_f1 = (2.0 * base_prec * base_rec) / (base_prec + base_rec) if (base_prec + base_rec) > 0 else 0.0

    return Metrics(
        event_precision=round(prec, 3),
        event_recall=round(rec, 3),
        event_f1=round(f1, 3),
        session_precision=round(session_prec, 3),
        baseline_event_f1=round(baseline_f1, 3),
        median_latency_ms=median_latency_ms,
        total_events=total_events,
        total_alerts=total_alerts,
        skipped_records=skipped,
    )
