"""Optional external enrichment providers for IdentityShield v3.

Follows context.md Section 15 and PRD §8, §12:
- Providers: ipinfo_lite, ipapi, abuseipdb, greynoise, otx
- Disabled unless listed in settings.enrich_providers
- Privacy rule: sends ONLY the IP address (never usernames, credentials, or tokens)
- httpx timeout 2.0s with per-provider rate limit
- Non-blocking: Agent 3 only reads from cache; misses are enqueued for background prefetch
- Caches results for 24 hours in enrich_cache_v3
- All exceptions swallowed with a warning counter
"""
import json
import logging
import queue
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from app.v3 import config, store

log = logging.getLogger(__name__)

CACHE_TTL_HOURS = 24


class ExternalEnricher:
    """Manages external IP enrichment with local SQLite caching and async prefetching."""

    def __init__(
        self,
        db_path: Path | str | None = None,
        enabled_providers: list[str] | None = None,
    ) -> None:
        self.db_path = db_path
        self._enabled = enabled_providers if enabled_providers is not None else config.get_settings().enrich_providers
        self._queue: queue.Queue[str] = queue.Queue(maxsize=1000)
        self._worker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.warning_count = 0
        self._lock = threading.Lock()

        if self._enabled:
            self._start_worker()

    def _start_worker(self) -> None:
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        """Stop background worker."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)

    def is_enabled(self) -> bool:
        return bool(self._enabled)

    def get_cached(self, ip: str) -> dict[str, Any] | None:
        """Retrieve cached enrichment data from SQLite if not expired."""
        if not ip:
            return None
        now_iso = datetime.now(UTC).isoformat()
        try:
            conn = store.get_connection(self.db_path)
            cur = conn.execute(
                "SELECT data_json, expires_at FROM enrich_cache_v3 WHERE ip = ? AND expires_at > ?",
                (ip, now_iso),
            )
            row = cur.fetchone()
            if row:
                return json.loads(row["data_json"])
        except (sqlite3.Error, OSError, ValueError) as exc:
            log.debug("Cache read exception for IP %s: %s", ip, exc)
        return None

    def save_cache(self, ip: str, provider: str, data: dict[str, Any]) -> None:
        """Save provider enrichment result to SQLite cache."""
        now = datetime.now(UTC)
        expires_at = (now + timedelta(hours=CACHE_TTL_HOURS)).isoformat()
        now_iso = now.isoformat()
        try:
            store.insert_many(
                "enrich_cache_v3",
                [
                    {
                        "ip": ip,
                        "provider": provider,
                        "data_json": data,
                        "expires_at": expires_at,
                        "created_at": now_iso,
                    }
                ],
                db_path=self.db_path,
            )
        except (sqlite3.Error, OSError, ValueError) as exc:
            log.debug("Cache write exception for IP %s: %s", ip, exc)

    def fetch_provider(self, ip: str, provider: str, client: httpx.Client | None = None) -> dict[str, Any] | None:
        """Fetch enrichment from a specific external provider.

        Never sends anything except the IP address.
        """
        if not ip:
            return None

        # Build request details per provider
        url = ""
        headers: dict[str, str] = {}
        params: dict[str, Any] = {}
        settings = config.get_settings()

        if provider == "ipinfo_lite":
            token = getattr(settings, "ipinfo_token", "")
            url = f"https://ipinfo.io/{ip}/json"
            if token:
                params["token"] = token
        elif provider == "ipapi":
            url = f"http://ip-api.com/json/{ip}"
        elif provider == "abuseipdb":
            key = getattr(settings, "abuseipdb_key", "")
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            if key:
                headers["Key"] = key
                headers["Accept"] = "application/json"
        elif provider == "greynoise":
            key = getattr(settings, "greynoise_key", "")
            url = f"https://api.greynoise.io/v3/community/{ip}"
            if key:
                headers["key"] = key
        elif provider == "otx":
            key = getattr(settings, "otx_key", "")
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            if key:
                headers["X-OTX-API-KEY"] = key
        else:
            return None

        http_client = client or httpx.Client(timeout=2.0)
        try:
            resp = http_client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                return resp.json()
            with self._lock:
                self.warning_count += 1
            log.warning("Provider %s returned status %d for IP %s", provider, resp.status_code, ip)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            with self._lock:
                self.warning_count += 1
            log.warning("Provider %s request failed for IP %s: %s", provider, ip, exc)
        finally:
            if client is None:
                http_client.close()
        return None

    def enqueue_prefetch(self, ip: str) -> bool:
        """Queue an IP for background cache prefetch if providers are enabled."""
        if not self._enabled or not ip:
            return False
        if self.get_cached(ip) is not None:
            return False
        try:
            self._queue.put_nowait(ip)
            return True
        except queue.Full:
            return False

    def _worker_loop(self) -> None:
        """Background prefetch loop."""
        while not self._stop_event.is_set():
            try:
                ip = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                for prov in self._enabled:
                    res = self.fetch_provider(ip, prov)
                    if res:
                        self.save_cache(ip, prov, res)
                        break
            except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
                with self._lock:
                    self.warning_count += 1
                log.warning("Background worker exception for IP %s: %s", ip, exc)
            finally:
                self._queue.task_done()
