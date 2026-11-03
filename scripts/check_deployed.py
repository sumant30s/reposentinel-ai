"""Authenticate and verify a controlled demo scan against an already running service."""

import json
import sys
import time
from pathlib import Path

import httpx
from app.core.config import get_settings

settings = get_settings()
url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
with httpx.Client(
    base_url=url,
    timeout=20,
    trust_env=False,
    headers={"Authorization": f"Bearer {settings.api_token.get_secret_value()}"},
) as client:
    response = client.post("/api/v1/scans", json={"source": "demo"})
    response.raise_for_status()
    scan_id = response.json()["id"]
    for _ in range(120):
        scan = client.get(f"/api/v1/scans/{scan_id}").json()
        if scan["status"] not in {"queued", "running"}:
            break
        time.sleep(2)
    if scan["status"] not in {"completed", "partial"}:
        raise SystemExit("Controlled deployed demo did not finish successfully")
    report = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
    report.raise_for_status()
    if not report.json()["findings"]:
        raise SystemExit("Controlled vulnerable fixture produced no findings")
    result = {
        "health": client.get("/health").json(),
        "scan": scan,
        "findings": len(report.json()["findings"]),
    }
    Path("docs/evidence/deployed-smoke.json").write_text(json.dumps(result, indent=2))
    print(f"Controlled demo verified: {scan['status']}, {result['findings']} findings")
