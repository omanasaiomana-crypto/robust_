"""Enrich events with privilege levels, resource sensitivity, and geo data."""
import logging
import pandas as pd

from app.config import SENSITIVE_ACTIONS

log = logging.getLogger(__name__)


def _infer_privilege(identity_id: str, meta: dict | None) -> int:
    """Determine privilege level (1-5) from metadata or name heuristics."""
    if meta and "privilege_level" in meta and meta["privilege_level"] is not None:
        try:
            return int(meta["privilege_level"])
        except (ValueError, TypeError):
            pass

    id_str = identity_id.lower()
    if meta:
        groups = [str(g).lower() for g in meta.get("groups", [])]
        if any("admin" in g for g in groups) or "admin" in id_str:
            return 5
        if any(any(k in g for k in ("power", "ops", "infra", "security")) for g in groups):
            return 3

    if "admin" in id_str:
        return 5
    if any(k in id_str for k in ("power", "ops", "infra", "sec")):
        return 3
    return 1


def _infer_sensitivity(action: str, resource: str | None) -> int:
    """Infer resource sensitivity 1-5 according to TECH_PRD 9.6."""
    act = str(action)
    res = str(resource).lower() if resource else ""

    # 5 for IAM, secrets, KMS, CloudTrail or SENSITIVE_ACTIONS
    if act in SENSITIVE_ACTIONS:
        return 5
    if any(k in res for k in (":iam::", ":secretsmanager:", ":kms:", ":cloudtrail:", "adminrole", "administratoraccess")):
        return 5
    if any(k in act.lower() for k in ("accesskey", "userpolicy", "rolepolicy", "secret", "trail")):
        return 5

    # 4 for S3 buckets / resources with finance, secret, prod, backup
    if any(k in res for k in ("finance", "secret", "prod", "backup")):
        return 4

    return 2


def enrich(df: pd.DataFrame, metadata: dict | None = None) -> pd.DataFrame:
    """Enrich Event DataFrame in place or return copy with privilege, sensitivity, and geo data."""
    if df is None or df.empty:
        return df

    meta = metadata or {}
    out = df.copy()

    # 1. Enrich privilege_level
    out["privilege_level"] = out["identity_id"].apply(lambda uid: _infer_privilege(str(uid), meta.get(str(uid).lower())))

    # 2. Enrich resource_sensitivity
    out["resource_sensitivity"] = out.apply(
        lambda r: _infer_sensitivity(r.get("action", ""), r.get("resource")), axis=1
    )

    # 3. Geo-enrichment for CloudTrail from closest previous Okta login with same src_ip
    try:
        okta_mask = (out["source"] == "okta") & out["lat"].notna() & out["src_ip"].notna()
        ct_mask = (out["source"] == "cloudtrail") & out["lat"].isna() & out["src_ip"].notna()

        if okta_mask.any() and ct_mask.any():
            okta_geo = out[okta_mask][["timestamp", "identity_id", "src_ip", "country", "city", "lat", "lon", "asn"]].copy()
            okta_geo = okta_geo.sort_values(by="timestamp").reset_index(drop=True)

            ct_sub = out[ct_mask].copy()
            ct_sub = ct_sub.sort_values(by="timestamp").reset_index(drop=True)

            merged = pd.merge_asof(
                ct_sub,
                okta_geo,
                on="timestamp",
                by=["identity_id", "src_ip"],
                direction="backward",
                suffixes=("", "_okta"),
            )

            # Update back onto out DataFrame using event_id as key
            geo_map = merged.set_index("event_id")
            for col in ("country", "city", "lat", "lon", "asn"):
                col_okta = f"{col}_okta"
                if col_okta in geo_map.columns:
                    valid_updates = geo_map[col_okta].dropna().to_dict()
                    if valid_updates:
                        current_vals = out.set_index("event_id")[col].to_dict()
                        for eid, val in valid_updates.items():
                            if current_vals.get(eid) is None:
                                current_vals[eid] = val
                        out[col] = out["event_id"].map(current_vals)

    except Exception as exc:
        log.warning("Geo-enrichment merge_asof failed: %s; leaving default None", exc)

    return out
