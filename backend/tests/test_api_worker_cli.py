import json
from datetime import timedelta

from app.cli import main, policy_exit
from app.models.database import Scan, now, sessions
from app.workers.jobs import claim_job, execute_job, recover_jobs

from tests.test_intake import zipped


def finish(client, settings):
    created = client.post("/api/v1/scans", json={"source": "demo"})
    assert created.status_code == 202
    scan_id = created.json()["id"]
    with sessions(settings.database_url)() as session:
        assert claim_job(session, 180) == scan_id
        assert claim_job(session, 180) is None
    execute_job(settings, scan_id)
    result = client.get(f"/api/v1/scans/{scan_id}").json()
    assert result["status"] == "partial", result
    return scan_id


def test_auth_settings_health(client):
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/health").json()["demo_mode"] is False
    assert client.get("/api/v1/scans", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/v1/scans/not-found").status_code == 404
    settings = client.get("/api/v1/settings").json()
    assert "api_token" not in settings and "ai_api_key" not in settings
    saved = client.put(
        "/api/v1/settings",
        json={
            "exposure": "internet",
            "critical_asset": True,
            "exclusions": ["generated/*"],
            "fail_on": "medium",
        },
    )
    assert saved.status_code == 200
    assert client.get("/api/v1/settings").json()["critical_asset"]
    assert client.put("/api/v1/settings", json={"exposure": "unknown"}).status_code == 422
    assert client.get("/openapi.json").json()["info"]["title"] == "RepoSentinel AI"
    assert client.get("/health").headers["x-content-type-options"] == "nosniff"


def test_complete_scan_reports_suppression_compare(client, settings):
    scan_id = finish(client, settings)
    findings = client.get(f"/api/v1/scans/{scan_id}/findings").json()
    assert len(findings) >= 8
    assert "fictional-training-value" not in json.dumps(findings)
    assert client.get(f"/api/v1/scans/{scan_id}/findings?severity=low").json() == []
    query = client.get(f"/api/v1/scans/{scan_id}/findings?rule=RS001&language=Python&q=SQL").json()
    assert len(query) == 1
    for format in ["json", "html", "csv", "sarif"]:
        report = client.get(f"/api/v1/scans/{scan_id}/report?format={format}")
        assert report.status_code == 200 and "attachment" in report.headers["content-disposition"]
    assert len(client.get(f"/api/v1/scans/{scan_id}/dependencies").json()) == 1
    finding = findings[0]
    assert (
        client.post(f"/api/v1/findings/{finding['id']}/explain", json={"use_ai": True}).json()[
            "provider"
        ]
        == "local-guidance"
    )
    assert (
        client.post(
            f"/api/v1/findings/{finding['id']}/suppress",
            json={"reason": "Known intentionally vulnerable fixture; reviewed in tests"},
        ).status_code
        == 200
    )
    assert client.get(f"/api/v1/scans/{scan_id}/summary").json()["suppressed"] == 1
    assert (
        len(client.get(f"/api/v1/scans/{scan_id}/findings?include_suppressed=false").json())
        == len(findings) - 1
    )
    baseline = client.get(f"/api/v1/scans/{scan_id}/baseline").json()
    assert baseline["fingerprints"] == [finding["fingerprint"]]
    second = finish(client, settings)
    compared = client.get(f"/api/v1/scans/{second}/compare/{scan_id}").json()
    assert compared["new"] == [] and compared["resolved"] == []
    assert client.get(f"/api/v1/scans/{second}/summary").json()["suppressed"] == 1
    assert not (settings.data_dir / "jobs" / scan_id).exists()


def test_upload_and_validation(client, settings):
    assert (
        client.post(
            "/api/v1/scans/upload", content=b"zip", headers={"Content-Type": "application/zip"}
        ).status_code
        == 422
    )
    assert client.post("/api/v1/scans/upload?authorized=true", content=b"zip").status_code == 415
    assert (
        client.post(
            "/api/v1/scans/upload?authorized=true",
            content=zipped("../bad.py"),
            headers={"Content-Type": "application/zip"},
        ).status_code
        == 422
    )
    response = client.post(
        "/api/v1/scans/upload?authorized=true",
        content=zipped(),
        headers={"Content-Type": "application/zip"},
    )
    assert response.status_code == 202
    scan_id = response.json()["id"]
    assert client.get(f"/api/v1/scans/{scan_id}/report").status_code == 409
    with sessions(settings.database_url)() as session:
        assert claim_job(session, 180) == scan_id
    execute_job(settings, scan_id)
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "completed"
    assert (
        client.post(
            "/api/v1/scans/upload?authorized=true",
            content=b"1234",
            headers={
                "Content-Type": "application/zip",
                "Content-Length": str(settings.max_archive_bytes + 2000),
            },
        ).status_code
        == 413
    )


def test_git_access_queue_and_rate(client, settings):
    assert (
        client.post(
            "/api/v1/scans", json={"source": "git", "url": "https://github.com/a/b"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/scans", json={"source": "git", "url": "file:///etc/passwd", "authorized": True}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/scans",
            json={"source": "git", "url": "https://github.com/a/b", "authorized": True},
        ).status_code
        == 403
    )
    settings.allowed_repos = "a/b"
    assert (
        client.post(
            "/api/v1/scans",
            json={"source": "git", "url": "https://github.com/a/b", "authorized": True},
        ).status_code
        == 202
    )
    settings.max_pending = 1
    assert client.post("/api/v1/scans", json={}).status_code == 429
    settings.rate_limit_per_minute = 0
    assert client.post("/api/v1/scans", json={}).status_code == 429


def test_failed_and_recovered_jobs(client, settings, monkeypatch):
    scan_id = client.post("/api/v1/scans", json={}).json()["id"]
    with sessions(settings.database_url)() as session:
        claim_job(session, 180)
        scan = session.get(Scan, scan_id)
        scan.lease_until = now() - timedelta(seconds=1)
        session.commit()
    assert recover_jobs(settings) == 1
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "failed"
    other = client.post("/api/v1/scans", json={}).json()["id"]
    with sessions(settings.database_url)() as session:
        claim_job(session, 180)
    monkeypatch.setattr(
        "app.workers.jobs.scan_tree",
        lambda *args: (_ for _ in ()).throw(RuntimeError("DO-NOT-DISCLOSE")),
    )
    execute_job(settings, other)
    failed = client.get(f"/api/v1/scans/{other}").json()
    assert failed["status"] == "failed" and "DO-NOT-DISCLOSE" not in failed["error"]
    assert client.post("/api/v1/findings/missing/explain", json={}).status_code == 404
    assert (
        client.post(
            "/api/v1/findings/missing/suppress", json={"reason": "A reason with sufficient detail"}
        ).status_code
        == 404
    )


def test_cli_exit_and_baseline(tmp_path):
    project = tmp_path / "source"
    project.mkdir()
    (project / "app.py").write_text("eval(user)")
    output = tmp_path / "report.json"
    args = [
        "scan",
        str(project),
        "--offline",
        "--engines",
        "",
        "--format",
        "json",
        "--output",
        str(output),
    ]
    assert main(args) == 1
    result = json.loads(output.read_text())
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"version": 1, "fingerprints": [f["fingerprint"] for f in result["findings"]]})
    )
    assert main(args + ["--baseline", str(baseline)]) == 0
    baseline.write_text("{}")
    assert main(args + ["--baseline", str(baseline)]) == 2
    assert main(["scan", str(project / "missing")]) == 2
    result["summary"]["engines"] = {"semgrep": {"status": "failed"}}
    assert policy_exit(result, "high") == 2


def test_api_without_configured_token(settings, engine):
    from app.main import create_app
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    with TestClient(create_app(settings.model_copy(update={"api_token": SecretStr("")}))) as client:
        assert client.get("/api/v1/scans").status_code == 503
