"""Trigger a configured Render Git-backed service without logging the deployment-hook secret."""

import json
import os
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


open_https = build_opener(NoRedirect).open

hook, health, commit = (
    os.getenv(k, "") for k in ["RENDER_DEPLOY_HOOK_URL", "RENDER_HEALTH_URL", "COMMIT_SHA"]
)
parts = urlsplit(hook)
if (
    parts.scheme != "https"
    or parts.hostname != "api.render.com"
    or not health.startswith("https://")
    or not commit
):
    raise SystemExit("Configure the HTTPS Render deploy hook, health URL and commit SHA.")
query = dict(parse_qsl(parts.query))
query["ref"] = commit
url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
try:
    with open_https(Request(url, method="POST"), timeout=20) as response:
        if response.status not in {200, 201, 202}:
            raise ValueError("Deploy hook rejected")
except (OSError, ValueError):
    raise SystemExit("Render deploy hook failed; secret URL is intentionally not logged.") from None
for _ in range(90):
    try:
        with open_https(health, timeout=10) as response:
            payload = json.load(response)
        if payload.get("status") == "ok" and payload.get("revision") == commit:
            print(f"Verified healthy deployment of commit {commit}")
            sys.exit(0)
    except (OSError, ValueError):
        print("Waiting for requested healthy revision.")
    time.sleep(10)
raise SystemExit("Health check never verified the requested commit. Check Render service logs.")
