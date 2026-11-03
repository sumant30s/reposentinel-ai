"""Generate local secrets without printing or overwriting existing values."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / ".env"
if path.exists():
    print("Existing .env preserved. Review it before starting.")
else:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    text = text.replace("RS_API_TOKEN=\n", f"RS_API_TOKEN={secrets.token_urlsafe(40)}\n")
    text = text.replace("POSTGRES_PASSWORD=\n", f"POSTGRES_PASSWORD={secrets.token_hex(24)}\n")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)
    print(
        "Created .env with random local credentials. Open it locally to obtain your workspace token."
    )
(ROOT / "data").mkdir(exist_ok=True, mode=0o700)
