"""Safe counterparts for the limited rules exercised by this demonstration."""
import hashlib
import json
import os
import subprocess


def safe_examples(cursor, username, payload, requests):
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    document = json.loads(payload)
    password = os.environ.get("SERVICE_PASSWORD")
    subprocess.run(["python", "--version"], check=True, shell=False)
    checksum = hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()
    response = requests.get("https://example.invalid", timeout=5, verify=True)
    return document, bool(password), checksum, response.status_code
