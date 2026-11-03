"""Retain the full audit and fail on every unreviewed or expired advisory."""

import json
import subprocess
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
output = ROOT / "docs/evidence/python-audit.json"
output.parent.mkdir(parents=True, exist_ok=True)
result = subprocess.run(
    [
        "pip-audit",
        "-r",
        str(ROOT / "backend/requirements.lock"),
        "--no-deps",
        "--disable-pip",
        "-f",
        "json",
        "-o",
        str(output),
    ],
    check=False,
)
if result.returncode not in {0, 1} or not output.exists():
    raise SystemExit("Dependency audit failed to complete")
audit = json.loads(output.read_text())
review = json.loads((ROOT / "security/advisory-exceptions.json").read_text())
exceptions = (
    {(x["package"], x["version"], x["id"]): x for x in review["exceptions"]}
    if date.today() <= date.fromisoformat(review["expires"])
    else {}
)
accepted, blocking = [], []
for dependency in audit.get("dependencies", []):
    if dependency.get("skip_reason"):
        blocking.append({"package": dependency.get("name"), "reason": "dependency not audited"})
    for finding in dependency.get("vulns", []):
        key = (dependency["name"], dependency["version"], finding["id"])
        row = {"package": key[0], "version": key[1], "id": key[2]}
        (accepted if key in exceptions else blocking).append(row)
summary = {
    "reviewed_exceptions": accepted,
    "blocking": blocking,
    "exception_expiry": review["expires"],
    "notice": "Known advisories remain installed through Semgrep; see documented reachability assessments.",
}
(ROOT / "docs/evidence/dependency-gate.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
raise SystemExit(1 if blocking else 0)
