"""Reproducible narrow AST/secret benchmark; never labeled as a laptop/full-engine result."""

import json
import platform
import time
from datetime import UTC, datetime
from pathlib import Path

from app.scanners.python_ast import analyze_python
from app.scanners.secrets import analyze_secrets

ROOT = Path(__file__).resolve().parents[1]
positives = [
    "cursor.execute(f'SELECT {user}')",
    "cursor.execute('SELECT '+user)",
    "eval(user)",
    "exec(user)",
    "pickle.loads(data)",
    "subprocess.run(user,shell=True)",
    "hashlib.md5(data)",
    "requests.get(url,verify=False)",
    "DEBUG=True",
    'password="fictional-fixture-only"',  # pragma: allowlist secret - invented benchmark fixture
]
negatives = [
    "cursor.execute('SELECT * FROM t WHERE id=?',(user,))",
    "json.loads(data)",
    "subprocess.run(['echo',user],shell=False)",
    "hashlib.md5(data,usedforsecurity=False)",
    "hashlib.sha256(data)",
    "requests.get(url,verify=True)",
    "DEBUG=False",
    "password=os.environ['PASSWORD']",
    "app.run(debug=False)",
    "print('eval(user)')",
]
started = time.perf_counter()
lines = 100000
files = 200
findings = 0
for i in range(files):
    source = "value = 1 + 2\n" * (lines // files)
    findings += len(analyze_python(source, f"generated_{i}.py")[0]) + len(
        analyze_secrets(source, f"generated_{i}.py")
    )
elapsed = time.perf_counter() - started


def detected(s):
    return bool(analyze_python(s, "labelled.py")[0] or analyze_secrets(s, "labelled.py"))


tp, fp = sum(map(detected, positives)), sum(map(detected, negatives))
result = {
    "measured_at": datetime.now(UTC).isoformat(),
    "environment": platform.platform(),
    "python": platform.python_version(),
    "scope": "In-memory Python AST + secret patterns only; excludes intake, external engines, advisory network and UI. Synthetic container workload; NOT a representative laptop benchmark.",
    "lines": lines,
    "files": files,
    "seconds": round(elapsed, 4),
    "within_120_seconds_for_this_scope": elapsed < 120,
    "corpus": {
        "positive_examples": len(positives),
        "negative_examples": len(negatives),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": len(positives) - tp,
        "false_positive_rate": fp / len(negatives),
        "false_discovery_rate": fp / max(tp + fp, 1),
        "limitation": "Small project-authored synthetic corpus; not independent validation or a general accuracy claim.",
    },
    "full_pipeline_laptop_target": "NOT MEASURED",
}
(ROOT / "docs/evidence/benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result, indent=2))
