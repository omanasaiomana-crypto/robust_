"""Run: python smoke_test.py   (the server does NOT need to be running)."""
import sys

from fastapi.testclient import TestClient


def main() -> int:
    from app.main import app
    with TestClient(app) as c:
        checks = {
            "health": c.get("/api/health"),
            "summary": c.get("/api/summary"),
            "alerts": c.get("/api/alerts"),
            "metrics": c.get("/api/metrics"),
            "audit_verify": c.get("/api/audit/verify"),
            "index_page": c.get("/index.html"),
        }
        failed = [k for k, r in checks.items() if r.status_code >= 500]
        for k, r in checks.items():
            print(f"{k:14s} {r.status_code}")
        if failed:
            print("FAILED:", failed)
            return 1
        print("SMOKE TEST PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
