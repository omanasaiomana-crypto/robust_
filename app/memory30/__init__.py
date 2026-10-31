"""IdentityShield 30-day identity memory.

Self-contained add-on: reads Okta System Log and AWS CloudTrail JSON, keeps a tiered 30-day memory per identity
in SQLite (7 days raw events, permanent evidence, 30 days of compact daily summaries and attack-stage hits),
links slow multi-day attack chains, and exposes the results under /api/memory.
"""
__all__ = ["engine", "store", "normalize", "catalog", "synth", "config"]
