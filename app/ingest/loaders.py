"""File loaders for CloudTrail, Okta, metadata, and labels supporting multiple formats."""
import csv
import gzip
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _read_records_from_file(path: Path) -> tuple[list[dict], int]:
    """Read records from a single file supporting JSON, JSON Lines, CSV, and .gz."""
    records: list[dict] = []
    skipped = 0

    try:
        is_gz = path.suffix.lower() == ".gz"
        open_fn = gzip.open if is_gz else open
        
        # Determine actual format
        stem = path.stem.lower() if is_gz else path.name.lower()
        if stem.endswith(".csv"):
            with open_fn(path, "rt", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    records.append(dict(r))
            return records, skipped

        with open_fn(path, "rt", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        if not content:
            return records, skipped

        # Attempt full JSON parse first
        if content.startswith("{"):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    if "Records" in data and isinstance(data["Records"], list):
                        return data["Records"], skipped
                    return [data], skipped
            except json.JSONDecodeError:
                # May be JSON Lines where each line is a JSON object
                pass

        if content.startswith("["):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    return [item for item in data if isinstance(item, dict)], skipped
            except json.JSONDecodeError:
                pass

        # Parse as JSON Lines
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
                if isinstance(item, dict):
                    records.append(item)
                else:
                    skipped += 1
            except Exception:
                skipped += 1

    except Exception as exc:
        log.warning("Failed to read file %s: %s", path, exc)
        skipped += 1

    return records, skipped


def load_cloudtrail(folder: Path) -> tuple[list[dict], int]:
    """Load CloudTrail events from folder. Handles {"Records": [...]}, arrays, JSONL, CSV, .gz."""
    if not folder.exists() or not folder.is_dir():
        return [], 0

    records: list[dict] = []
    total_skipped = 0

    files = sorted(folder.iterdir(), key=lambda p: p.name)
    # If folder has dedicated files, prefer those matching cloudtrail, or files not named okta/metadata/labels
    ct_files = [p for p in files if p.is_file() and not p.name.startswith(".")]
    named_ct = [p for p in ct_files if "cloudtrail" in p.name.lower()]
    target_files = named_ct if named_ct else [
        p for p in ct_files if not any(x in p.name.lower() for x in ("okta", "metadata", "label"))
    ]

    for p in target_files:
        recs, sk = _read_records_from_file(p)
        records.extend(recs)
        total_skipped += sk

    return records, total_skipped


def load_okta(folder: Path) -> tuple[list[dict], int]:
    """Load Okta events from folder. Handles arrays, JSONL, CSV, .gz."""
    if not folder.exists() or not folder.is_dir():
        return [], 0

    records: list[dict] = []
    total_skipped = 0

    files = sorted(folder.iterdir(), key=lambda p: p.name)
    target_files = [
        p for p in files if p.is_file() and not p.name.startswith(".") and "okta" in p.name.lower()
    ]
    if not target_files:
        # If no explicit okta name, inspect files that aren't cloudtrail/metadata/labels
        target_files = [
            p for p in files if p.is_file() and not p.name.startswith(".")
            and not any(x in p.name.lower() for x in ("cloudtrail", "metadata", "label"))
        ]

    for p in target_files:
        recs, sk = _read_records_from_file(p)
        records.extend(recs)
        total_skipped += sk

    return records, total_skipped


def load_metadata(folder: Path) -> dict[str, dict]:
    """Load identity metadata mapping: identity_id -> attributes dict."""
    if not folder.exists() or not folder.is_dir():
        return {}

    mapping: dict[str, dict] = {}
    files = sorted(folder.iterdir(), key=lambda p: p.name)
    meta_files = [p for p in files if p.is_file() and "meta" in p.name.lower()]
    if not meta_files:
        meta_files = [p for p in files if p.is_file() and not p.name.startswith(".")]

    for p in meta_files:
        recs, _ = _read_records_from_file(p)
        for r in recs:
            ident = r.get("identity_id") or r.get("userName") or r.get("id")
            if not ident and "email" in r:
                ident = str(r["email"]).split("@")[0].lower()
            if ident:
                ident_clean = str(ident).strip().lower()
                mapping[ident_clean] = r

    return mapping


def load_labels(folder: Path) -> dict[str, str]:
    """Load labels mapping: event_id -> label string."""
    if not folder.exists() or not folder.is_dir():
        return {}

    mapping: dict[str, str] = {}
    files = sorted(folder.iterdir(), key=lambda p: p.name)
    label_files = [p for p in files if p.is_file() and "label" in p.name.lower()]
    if not label_files:
        label_files = [p for p in files if p.is_file() and not p.name.startswith(".")]

    for p in label_files:
        recs, _ = _read_records_from_file(p)
        for r in recs:
            eid = r.get("event_id") or r.get("eventID") or r.get("uuid")
            lbl = r.get("label") or r.get("attack_type") or r.get("scenario")
            if eid and lbl:
                mapping[str(eid).strip()] = str(lbl).strip()

    return mapping
