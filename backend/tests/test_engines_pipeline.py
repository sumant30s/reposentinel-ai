import subprocess
import sys

import pytest
from app.scanners.external import external_scan, relative_file, run_json
from app.services.pipeline import scan_tree


def test_adapter_normalization_and_status(tmp_path, settings, monkeypatch):
    settings.engines = "bandit,detect-secrets,semgrep,pip-audit"
    settings.osv_enabled = True
    monkeypatch.setattr("app.scanners.external.shutil.which", lambda name: name)

    def response(command, root, timeout, acceptable):
        if command[0] == "bandit":
            return {
                "results": [
                    {
                        "test_id": "B307",
                        "filename": str(root / "app.py"),
                        "line_number": 1,
                        "issue_confidence": "HIGH",
                    }
                ]
            }
        if command[0] == "detect-secrets":
            return {"results": {"config.env": [{"line_number": 2}]}}
        if command[0] == "semgrep":
            return {"results": [{"check_id": "RS003", "path": "index.js", "start": {"line": 3}}]}
        assert "--disable-pip" in command and "--no-deps" in command
        return {"dependencies": [{"vulns": [{"id": "TEST-1"}]}]}

    monkeypatch.setattr("app.scanners.external.run_json", response)
    deps = [
        {"name": "example", "version": "1.0", "ecosystem": "PyPI", "version_kind": "declared-exact"}
    ]
    findings, statuses = external_scan(tmp_path, settings, deps)
    assert len(findings) == 3
    assert statuses["pip-audit"]["advisory_matches"] == 1
    assert all(s["status"] == "completed" for s in statuses.values())
    assert external_scan(tmp_path, settings, [])[1]["pip-audit"]["status"] == "not-applicable"
    monkeypatch.setattr(
        "app.scanners.external.run_json",
        lambda *a: (_ for _ in ()).throw(subprocess.TimeoutExpired("engine", 1)),
    )
    assert external_scan(tmp_path, settings, deps)[1]["bandit"]["status"] == "failed"
    with pytest.raises(ValueError):
        relative_file("../../escape.py", tmp_path)


def test_run_json_exit_invalid_and_success(tmp_path):
    assert run_json(
        [sys.executable, "-c", "import json;print(json.dumps({'ok': True}))"], tmp_path, 5, {0}
    ) == {"ok": True}
    with pytest.raises(ValueError):
        run_json([sys.executable, "-c", "raise SystemExit(4)"], tmp_path, 5, {0})
    with pytest.raises(ValueError):
        run_json([sys.executable, "-c", "print('not json')"], tmp_path, 5, {0})


def test_pipeline_live_advisory_branch(tmp_path, session, settings, monkeypatch):
    (tmp_path / "requirements.txt").write_text("example==1.0\nother>=2")
    (tmp_path / "app.py").write_text("cursor.execute('SELECT ' + value)")
    settings.osv_enabled = True
    monkeypatch.setattr(
        "app.services.pipeline.OSVClient.query",
        lambda *a: (
            [
                {
                    "id": "TEST-1",
                    "summary": "Test-only advisory",
                    "database_specific": {"severity": "HIGH"},
                },
                {"id": "WITHDRAWN", "withdrawn": "2020-01-01"},
            ],
            "live",
        ),
    )
    result = scan_tree(tmp_path, settings, session)
    assert len(result["findings"]) == 2
    assert result["summary"]["coverage"] == "partial"
    assert result["dependencies"][0]["advisories"][0]["id"] == "TEST-1"


def test_worker_git_archive(client, settings, monkeypatch):
    from app.models.database import sessions
    from app.workers.jobs import claim_job, execute_job

    from tests.test_intake import zipped

    settings.allowed_repos = "owner/repo"
    scan_id = client.post(
        "/api/v1/scans",
        json={"source": "git", "url": "https://github.com/owner/repo", "authorized": True},
    ).json()["id"]
    monkeypatch.setattr(
        "app.workers.jobs.download_repository", lambda *a: zipped("repo-main/app.py", b"eval(user)")
    )
    with sessions(settings.database_url)() as session:
        claim_job(session, 30)
    execute_job(settings, scan_id)
    assert client.get(f"/api/v1/scans/{scan_id}/findings").json()[0]["file"] == "app.py"
