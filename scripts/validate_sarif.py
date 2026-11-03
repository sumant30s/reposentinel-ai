"""Validate generated SARIF with the checked-in official JSON schema."""

import json
import sys
from pathlib import Path

import jsonschema

root = Path(__file__).resolve().parents[1]
schema = json.loads((root / "docs/schemas/sarif-2.1.0.json").read_text())
for name in sys.argv[1:]:
    jsonschema.Draft7Validator(schema).validate(json.loads(Path(name).read_text()))
    print(f"Valid SARIF: {name}")
