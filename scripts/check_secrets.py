"""Gate tracked production files; intentionally vulnerable fixtures and test data are excluded."""

import json
import subprocess
from pathlib import Path

exclude = r"(^|/)(sample_projects/|backend/tests/|docs/evidence/)|package-lock\.json$|uv\.lock$|requirements.*\.lock$"
result = subprocess.run(
    ["detect-secrets", "scan", "--no-verify", "--exclude-files", exclude],
    capture_output=True,
    text=True,
    check=True,
)
data = json.loads(result.stdout)
findings = [
    {"file": path, "line": item["line_number"], "type": item["type"]}
    for path, rows in data["results"].items()
    for item in rows
]
Path("docs/evidence").mkdir(parents=True, exist_ok=True)
Path("docs/evidence/secret-scan.json").write_text(
    json.dumps(
        {
            "scope": "tracked production files excluding labelled fixtures/tests/evidence/locks",
            "findings": findings,
        },
        indent=2,
    )
)
print(f"Secret scan: {len(findings)} candidate findings (values omitted).")
raise SystemExit(1 if findings else 0)
