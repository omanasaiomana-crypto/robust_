"""Security controls for IdentityShield v3 Ingest Service.

Implements HMAC-SHA256 signature verification, TTL nonce replay protection,
and token-bucket rate limiting per key ID.
"""
import hashlib
import hmac
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping

from app.v3 import config


class AuthError(Exception):
    """Raised when authentication or signature verification fails (HTTP 401)."""


class TooLarge(Exception):
    """Raised when request body exceeds maximum allowed size (HTTP 413)."""


class RateLimited(Exception):
    """Raised when request rate or event volume exceeds limits (HTTP 429)."""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: float = 1.0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class SchemaError(Exception):
    """Raised when request body or event payload schema is invalid (HTTP 422)."""


class NonceCache:
    """Thread-safe nonce cache with TTL and maximum size bound."""

    def __init__(
        self,
        ttl_seconds: float | None = None,
        max_size: int = 100000,
    ) -> None:
        self.ttl = float(ttl_seconds or config.INGEST_NONCE_TTL_SECONDS)
        self.max_size = max_size
        self._cache: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_add(self, key_id: str, nonce: str, now: float | None = None) -> bool:
        """Check if nonce has been seen. Returns True if fresh, False if replay."""
        cur_time = now if now is not None else time.time()
        key = (key_id, nonce)

        with self._lock:
            # Purge expired entries
            cutoff = cur_time - self.ttl
            while self._cache:
                oldest_k, oldest_t = next(iter(self._cache.items()))
                if oldest_t < cutoff:
                    self._cache.pop(oldest_k)
                else:
                    break

            if key in self._cache:
                return False

            # Bound maximum size
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)

            self._cache[key] = cur_time
            return True


class TokenBucket:
    """Token bucket rate limiter tracking requests/sec and events/min per key."""

    def __init__(
        self,
        rps_limit: float | None = None,
        epm_limit: float | None = None,
    ) -> None:
        self.req_capacity = float(rps_limit or config.INGEST_RATE_RPS)
        self.req_fill_rate = self.req_capacity  # tokens per second

        self.evt_capacity = float(epm_limit or config.INGEST_RATE_EVENTS_PER_MIN)
        self.evt_fill_rate = self.evt_capacity / 60.0  # tokens per second

        # Per-key state: {key_id: (req_tokens, evt_tokens, last_time)}
        self._buckets: dict[str, tuple[float, float, float]] = {}
        self._lock = threading.Lock()

    def consume(
        self,
        key_id: str,
        event_count: int = 1,
        now: float | None = None,
    ) -> tuple[bool, float]:
        """Attempt to consume tokens. Returns (allowed, retry_after_seconds)."""
        cur_time = now if now is not None else time.time()

        with self._lock:
            req_tokens, evt_tokens, last_time = self._buckets.get(
                key_id,
                (self.req_capacity, self.evt_capacity, cur_time),
            )

            # Refill tokens
            elapsed = max(0.0, cur_time - last_time)
            req_tokens = min(self.req_capacity, req_tokens + (elapsed * self.req_fill_rate))
            evt_tokens = min(self.evt_capacity, evt_tokens + (elapsed * self.evt_fill_rate))

            # Check limits
            if req_tokens < 1.0:
                retry_after = (1.0 - req_tokens) / self.req_fill_rate
                return False, max(1.0, round(retry_after, 2))

            if evt_tokens < float(event_count):
                retry_after = (float(event_count) - evt_tokens) / self.evt_fill_rate
                return False, max(1.0, round(retry_after, 2))

            # Consume tokens
            req_tokens -= 1.0
            evt_tokens -= float(event_count)
            self._buckets[key_id] = (req_tokens, evt_tokens, cur_time)
            return True, 0.0


# Shared default instances
default_nonce_cache = NonceCache()
default_rate_limiter = TokenBucket()


def _get_header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return str(v).strip()
    return None


def verify_signature(
    headers: Mapping[str, str],
    raw_body: bytes,
    keys: dict[str, str],
    now: float | None = None,
    nonce_cache: NonceCache | None = None,
) -> str:
    """Verify HMAC-SHA256 signature and replay protection.

    Format: hex HMAC-SHA256(secret, timestamp + "\n" + nonce + "\n" + sha256_hex(raw_body))
    Returns authenticated key_id or raises AuthError.
    """
    cur_time = now if now is not None else time.time()
    cache = nonce_cache or default_nonce_cache

    key_id = _get_header(headers, "X-IS-Key-Id")
    timestamp = _get_header(headers, "X-IS-Timestamp")
    nonce = _get_header(headers, "X-IS-Nonce")
    signature = _get_header(headers, "X-IS-Signature")

    if not (key_id and timestamp and nonce and signature):
        raise AuthError("Missing required signature headers (X-IS-Key-Id, X-IS-Timestamp, X-IS-Nonce, X-IS-Signature)")

    if key_id not in keys:
        raise AuthError(f"Unknown key ID '{key_id}'")

    secret = keys[key_id]

    try:
        ts_float = float(timestamp)
    except (ValueError, TypeError) as exc:
        raise AuthError(f"Invalid timestamp format: {timestamp}") from exc

    # Timestamp skew check
    skew = abs(cur_time - ts_float)
    if skew > config.INGEST_SKEW_SECONDS:
        raise AuthError(
            f"Timestamp outside allowed skew window ({skew:.1f}s > {config.INGEST_SKEW_SECONDS}s)"
        )

    # Nonce replay check
    if not cache.check_and_add(key_id, nonce, cur_time):
        raise AuthError("Replayed nonce detected")

    # Compute expected signature
    body_hash = hashlib.sha256(raw_body).hexdigest()
    string_to_sign = f"{timestamp}\n{nonce}\n{body_hash}".encode()
    expected_sig = hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig.lower(), signature.lower()):
        raise AuthError("Invalid signature")

    return key_id
