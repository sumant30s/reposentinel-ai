"""Launch the real API + worker, exercise HTTP, record facts, and stop both."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
from app.core.config import get_settings

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    settings = get_settings()
    with (ROOT / "docs/evidence/http-server.log").open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "scripts/run_services.py"],
            cwd=ROOT,
            env={**os.environ, "PORT": "8017"},
            stdout=log,
            stderr=log,
        )
        try:
            with httpx.Client(
                base_url="http://127.0.0.1:8017",
                trust_env=False,
                timeout=15,
                headers={"Authorization": f"Bearer {settings.api_token.get_secret_value()}"},
            ) as client:
                for _ in range(25):
                    try:
                        if client.get("/health").status_code == 200:
                            break
                    except httpx.ConnectError:
                        pass
                    time.sleep(0.5)
                facts = {
                    "health": client.get("/health").json(),
                    "frontend_status": client.get("/").status_code,
                    "unauthenticated_status": client.get(
                        "/api/v1/scans", headers={"Authorization": "Bearer invalid"}
                    ).status_code,
                }
                response = client.post("/api/v1/scans", json={"source": "demo"})
                response.raise_for_status()
                scan_id = response.json()["id"]
                for _ in range(190):
                    scan = client.get(f"/api/v1/scans/{scan_id}").json()
                    if scan["status"] not in {"queued", "running"}:
                        break
                    time.sleep(0.5)
                assert scan["status"] in {"completed", "partial"}, scan
                facts["scan"] = scan
                facts["reports"] = {
                    fmt: client.get(f"/api/v1/scans/{scan_id}/report?format={fmt}").status_code
                    for fmt in ["json", "html", "csv", "sarif"]
                }
                findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
                facts["finding_count"] = len(findings)
                facts["guidance"] = client.post(
                    f"/api/v1/findings/{findings[0]['id']}/explain", json={"use_ai": True}
                ).json()
                assert facts["frontend_status"] == 200 and facts["unauthenticated_status"] == 401
                assert all(status == 200 for status in facts["reports"].values())
                (ROOT / "docs/evidence/http-smoke.json").write_text(
                    json.dumps(facts, indent=2), encoding="utf-8"
                )
                print(
                    json.dumps(
                        {
                            "health": facts["health"],
                            "frontend": facts["frontend_status"],
                            "scan_status": scan["status"],
                            "findings": len(findings),
                            "reports": facts["reports"],
                        }
                    )
                )
                return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
