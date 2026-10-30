"""Offline context and enrichment provider for IdentityShield v3.

Follows context.md Section 8, 12, 15 and PRD §8, §12:
- Loads tor_exits.txt, hosting_asns.txt, trusted_ips.txt, geo_seed.csv, and context_rules.yaml once
- lookup_ip(ip, attrs) -> dict: prefers Okta securityContext/geo values, falls back to geo_seed CIDR match,
  sets is_tor, is_hosting, is_proxy, trusted_ip, context_complete
- Pure helpers get_privilege_level and get_resource_sensitivity based on context_rules.yaml
"""
import csv
import ipaddress
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from app.v3.config import ROOT_DIR

log = logging.getLogger(__name__)

DATA_DIR = ROOT_DIR / "app" / "v3" / "data"

_TOR_EXITS: set[str] | None = None
_HOSTING_ASNS: set[int] | None = None
_TRUSTED_IPS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None
_GEO_SEED: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict[str, Any]]] | None = None
_CONTEXT_RULES: dict[str, Any] | None = None


def load_offline_data(data_dir: Path | None = None) -> None:
    """Load all offline reference datasets into memory once."""
    global _TOR_EXITS, _HOSTING_ASNS, _TRUSTED_IPS, _GEO_SEED, _CONTEXT_RULES

    target_dir = data_dir or DATA_DIR

    # 1. Tor Exits
    tor_file = target_dir / "tor_exits.txt"
    tor_set = set()
    if tor_file.exists():
        with tor_file.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    tor_set.add(s)
    _TOR_EXITS = tor_set

    # 2. Hosting ASNs
    hosting_file = target_dir / "hosting_asns.txt"
    hosting_set = set()
    if hosting_file.exists():
        with hosting_file.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    parts = s.split()
                    try:
                        hosting_set.add(int(parts[0]))
                    except (ValueError, IndexError):
                        continue
    _HOSTING_ASNS = hosting_set

    # 3. Trusted IPs
    trusted_file = target_dir / "trusted_ips.txt"
    trusted_list = []
    if trusted_file.exists():
        with trusted_file.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    try:
                        trusted_list.append(ipaddress.ip_network(s, strict=False))
                    except ValueError:
                        continue
    _TRUSTED_IPS = trusted_list

    # 4. Geo Seed CSV
    geo_file = target_dir / "geo_seed.csv"
    geo_list = []
    if geo_file.exists():
        with geo_file.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cidr = row.get("cidr", "").strip()
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    asn_val = None
                    try:
                        asn_val = int(row.get("asn", 0)) if row.get("asn") else None
                    except ValueError:
                        asn_val = None

                    lat_val = None
                    lon_val = None
                    try:
                        lat_val = float(row.get("lat", 0)) if row.get("lat") else None
                        lon_val = float(row.get("lon", 0)) if row.get("lon") else None
                    except ValueError:
                        pass

                    geo_list.append(
                        (
                            net,
                            {
                                "country": row.get("country"),
                                "city": row.get("city"),
                                "lat": lat_val,
                                "lon": lon_val,
                                "asn": asn_val,
                                "as_org": row.get("as_org"),
                            },
                        )
                    )
                except ValueError:
                    continue
    _GEO_SEED = geo_list

    # 5. Context Rules YAML
    rules_file = target_dir / "context_rules.yaml"
    rules_dict: dict[str, Any] = {}
    if rules_file.exists():
        with rules_file.open("r", encoding="utf-8") as f:
            try:
                rules_dict = yaml.safe_load(f) or {}
            except (yaml.YAMLError, OSError, ValueError):
                rules_dict = {}
    _CONTEXT_RULES = rules_dict


def ensure_loaded() -> None:
    """Ensure offline data is initialized."""
    if _TOR_EXITS is None:
        load_offline_data()


def lookup_ip(ip: str | None, attrs: dict[str, Any] | None = None) -> dict[str, Any]:
    """Look up geo, ASN, and security flags for an IP address.

    Prefers Okta securityContext/geographicalContext attributes when available.
    Falls back to geo_seed CIDR matching. Sets context_complete=False if IP is unknown.
    """
    ensure_loaded()
    assert _TOR_EXITS is not None
    assert _HOSTING_ASNS is not None
    assert _TRUSTED_IPS is not None
    assert _GEO_SEED is not None

    clean_ip = (ip or "").strip()
    attrs = attrs or {}

    country = None
    city = None
    lat = None
    lon = None
    asn = None
    as_org = None
    is_proxy = False
    context_complete = False

    # 1. Prefer Okta securityContext & client.geographicalContext
    sec_ctx = attrs.get("securityContext") or {}
    geo_ctx = attrs.get("geographicalContext") or {}

    if sec_ctx or geo_ctx:
        if geo_ctx.get("country"):
            country = geo_ctx["country"]
            city = geo_ctx.get("city")
            geo_loc = geo_ctx.get("geolocation") or {}
            if isinstance(geo_loc, dict):
                lat = geo_loc.get("lat")
                lon = geo_loc.get("lon")
            context_complete = True

        if sec_ctx.get("asNumber"):
            asn_raw = sec_ctx["asNumber"]
            try:
                if isinstance(asn_raw, str) and asn_raw.upper().startswith("AS"):
                    asn = int(asn_raw[2:])
                else:
                    asn = int(asn_raw)
            except (ValueError, TypeError):
                asn = None
            as_org = sec_ctx.get("asOrg")
            is_proxy = bool(sec_ctx.get("isProxy", False))
            context_complete = True

    # 2. Fall back to geo_seed.csv CIDR match if needed
    if not context_complete and clean_ip:
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            for net, meta in _GEO_SEED:
                if ip_obj in net:
                    country = meta["country"]
                    city = meta["city"]
                    lat = meta["lat"]
                    lon = meta["lon"]
                    asn = meta["asn"]
                    as_org = meta["as_org"]
                    context_complete = True
                    break
        except ValueError:
            pass

    # 3. Security flags
    is_tor = clean_ip in _TOR_EXITS
    is_hosting = asn in _HOSTING_ASNS if asn is not None else False

    trusted_ip = False
    if clean_ip:
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            trusted_ip = any(ip_obj in t_net for t_net in _TRUSTED_IPS)
        except ValueError:
            trusted_ip = False

    return {
        "country": country,
        "city": city,
        "lat": lat,
        "lon": lon,
        "asn": asn,
        "as_org": as_org,
        "is_proxy": is_proxy,
        "is_tor": is_tor,
        "is_hosting": is_hosting,
        "trusted_ip": trusted_ip,
        "context_complete": context_complete,
    }


def get_privilege_level(
    identity_id: str,
    policies: list[str] | None = None,
    role_arn: str | None = None,
) -> int:
    """Determine privilege level (1-5) using context_rules.yaml."""
    ensure_loaded()
    rules = (_CONTEXT_RULES or {}).get("privilege_rules", {})
    all_targets = list(policies or [])
    if role_arn:
        all_targets.append(role_arn)
    all_targets.append(identity_id)

    # Check level 5
    lvl5 = rules.get("level_5", {})
    for target in all_targets:
        for p in lvl5.get("policies", []):
            if p == target or (p.startswith("*") and p[1:] in target):
                return 5
        for pattern in lvl5.get("patterns", []):
            if re.match(pattern, target):
                return 5

    # Check level 4
    lvl4 = rules.get("level_4", {})
    for target in all_targets:
        for p in lvl4.get("policies", []):
            if p == target:
                return 4
        for pattern in lvl4.get("patterns", []):
            if re.match(pattern, target):
                return 4

    # Check level 3
    lvl3 = rules.get("level_3", {})
    for target in all_targets:
        for pattern in lvl3.get("patterns", []):
            if re.match(pattern, target):
                return 3

    # Check level 2
    lvl2 = rules.get("level_2", {})
    for target in all_targets:
        for pattern in lvl2.get("patterns", []):
            if re.match(pattern, target):
                return 2

    return int(rules.get("default", 1))


def get_resource_sensitivity(resource_arn: str | None) -> int:
    """Determine resource sensitivity level (1-5) using context_rules.yaml."""
    if not resource_arn:
        return 1

    ensure_loaded()
    rules = (_CONTEXT_RULES or {}).get("sensitivity_rules", {})

    # Check level 5
    lvl5 = rules.get("level_5", {})
    for s in lvl5.get("services", []):
        if f":{s}:" in resource_arn or resource_arn.startswith(s):
            return 5
    for pattern in lvl5.get("patterns", []):
        if re.search(pattern, resource_arn):
            return 5

    # Check level 4
    lvl4 = rules.get("level_4", {})
    for s in lvl4.get("services", []):
        if f":{s}:" in resource_arn or resource_arn.startswith(s):
            return 4
    for pattern in lvl4.get("patterns", []):
        if re.search(pattern, resource_arn):
            return 4

    # Check level 3
    lvl3 = rules.get("level_3", {})
    for s in lvl3.get("services", []):
        if f":{s}:" in resource_arn or resource_arn.startswith(s):
            return 3
    for pattern in lvl3.get("patterns", []):
        if re.search(pattern, resource_arn):
            return 3

    # Check level 2
    lvl2 = rules.get("level_2", {})
    for s in lvl2.get("services", []):
        if f":{s}:" in resource_arn or resource_arn.startswith(s):
            return 2
    for pattern in lvl2.get("patterns", []):
        if re.search(pattern, resource_arn):
            return 2

    return int(rules.get("default", 1))
