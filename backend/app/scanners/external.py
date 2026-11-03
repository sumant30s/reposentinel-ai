import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from app.core.config import Settings
from app.scanners.python_ast import make_finding
from app.schemas.contracts import FindingData

BANDIT_RULES = {
    "B608": "RS001",
    "B105": "RS002",
    "B106": "RS002",
    "B107": "RS002",
    "B307": "RS003",
    "B301": "RS004",
    "B602": "RS005",
    "B324": "RS006",
    "B501": "RS007",
    "B201": "RS008",
}


def run_json(command: list[str], root: Path, timeout: int, acceptable: set[int]) -> dict:
    # File-backed output avoids unbounded memory; the worker parent also enforces a hard deadline.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=error,
            timeout=timeout,
            check=False,
            env={
                **os.environ,
                "SEMGREP_SEND_METRICS": "off",
                "OTEL_SDK_DISABLED": "true",
                "OTEL_PROPAGATORS": "none",
                "PYTHONPATH": "",
            },
        )
        if result.returncode not in acceptable:
            raise ValueError(f"engine exit {result.returncode}")
        if output.tell() > 8 * 1024 * 1024:
            raise ValueError("engine output limit")
        output.seek(0)
        return json.load(output)


def relative_file(value: str, root: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    if root.resolve() not in resolved.parents:
        raise ValueError("Analyzer returned an out-of-root path")
    return resolved.relative_to(root.resolve()).as_posix()


def external_scan(
    root: Path, settings: Settings, dependencies: list[dict]
) -> tuple[list[FindingData], dict]:
    findings: list[FindingData] = []
    statuses: dict = {}
    requested = {s.strip() for s in settings.engines.split(",") if s.strip()}
    for engine in ["bandit", "detect-secrets", "semgrep", "pip-audit"]:
        if engine not in requested:
            statuses[engine] = {"status": "disabled"}
            continue
        binary = shutil.which(engine)
        if binary is None:
            # The venv may be invoked via an absolute interpreter without activating PATH.
            candidate = Path(sys.executable).parent / (engine + (".exe" if os.name == "nt" else ""))
            binary = str(candidate) if candidate.exists() else None
        if binary is None:
            statuses[engine] = {"status": "unavailable", "detail": "Executable is not installed"}
            continue
        try:
            if engine == "bandit":
                payload = run_json(
                    [
                        binary,
                        "-r",
                        str(root),
                        "-f",
                        "json",
                        "-q",
                        "--ignore-nosec",
                        "-t",
                        ",".join(BANDIT_RULES),
                    ],
                    root,
                    settings.engine_timeout,
                    {0, 1},
                )
                for row in payload.get("results", []):
                    rule = BANDIT_RULES.get(row["test_id"])
                    if rule:
                        item = make_finding(
                            rule,
                            relative_file(row["filename"], root),
                            row["line_number"],
                            engine,
                            row["issue_confidence"].lower(),
                        )
                        findings.append(item)
                if payload.get("errors"):
                    raise ValueError("Bandit reported skipped files")
            elif engine == "detect-secrets":
                payload = run_json(
                    [binary, "scan", "--all-files", "--no-verify", str(root)],
                    root,
                    settings.engine_timeout,
                    {0},
                )
                for path, rows in payload.get("results", {}).items():
                    for row in rows:
                        item = make_finding(
                            "RS002", relative_file(path, root), row["line_number"], engine
                        )
                        item.language = "Python" if path.endswith(".py") else "Text"
                        findings.append(item)
            elif engine == "semgrep":
                rules = Path(__file__).resolve().parents[1] / "rules/semgrep.yml"
                payload = run_json(
                    [
                        binary,
                        "scan",
                        "--config",
                        str(rules),
                        "--json",
                        "--metrics=off",
                        "--disable-version-check",
                        "--no-git-ignore",
                        "--no-rewrite-rule-ids",
                        "--jobs",
                        "1",
                        str(root),
                    ],
                    root,
                    settings.engine_timeout,
                    {0, 1},
                )
                for row in payload.get("results", []):
                    rule = row["check_id"].split(".")[-1]
                    item = make_finding(
                        rule, relative_file(row["path"], root), row["start"]["line"], engine
                    )
                    item.language = "JavaScript/TypeScript"
                    findings.append(item)
                if payload.get("errors"):
                    raise ValueError("Semgrep reported parse or engine errors")
            else:
                exact = [
                    d
                    for d in dependencies
                    if d["ecosystem"] == "PyPI" and d["version_kind"] == "declared-exact"
                ]
                if not exact:
                    statuses[engine] = {"status": "not-applicable"}
                    continue
                if not settings.osv_enabled:
                    statuses[engine] = {"status": "disabled", "detail": "Offline mode"}
                    continue
                # Never resolve/install attacker-controlled requirements, URLs, build backends or setup.py.
                with tempfile.TemporaryDirectory() as folder:
                    req = Path(folder) / "requirements.txt"
                    req.write_text(
                        "\n".join(f"{d['name']}=={d['version']}" for d in exact), encoding="utf-8"
                    )
                    payload = run_json(
                        [
                            binary,
                            "-r",
                            str(req),
                            "--no-deps",
                            "--disable-pip",
                            "--vulnerability-service",
                            "osv",
                            "--format",
                            "json",
                            "--progress-spinner",
                            "off",
                        ],
                        root,
                        settings.engine_timeout,
                        {0, 1},
                    )
                # OSV is the canonical advisory normalizer; this provides an independent cross-check count.
                count = sum(len(d.get("vulns", [])) for d in payload.get("dependencies", []))
                statuses[engine] = {
                    "status": "completed",
                    "advisory_matches": count,
                    "detail": "Cross-check; OSV findings are normalized separately",
                }
                continue
            statuses[engine] = {"status": "completed"}
        except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, TypeError) as exc:
            statuses[engine] = {"status": "failed", "detail": type(exc).__name__}
    return findings, statuses
