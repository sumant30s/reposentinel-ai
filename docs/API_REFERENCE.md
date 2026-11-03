# API reference

Base path: `/api/v1`. Interactive OpenAPI: `/docs`; schema: `/openapi.json`. Authenticate with `Authorization: Bearer <RS_API_TOKEN>`. The application has one owner, not multiple roles/users.

| Method / path | Request | Response / behavior |
|---|---|---|
| GET /health | None | 200 status/version/revision; 503 when DB/schema cannot be read; no sensitive data |
| POST /api/v1/scans | `{ "source":"demo" }` or `{ "source":"git", "url":"https://github.com/owner/repo", "authorized":true }` | 202 ScanView; Git URL must be allowlisted |
| POST /api/v1/scans/upload?authorized=true | Raw `application/zip` body; not multipart | 202 after bounded validation; no local paths accepted |
| GET /api/v1/scans | `limit` 1–100, `offset` ≥0 | Newest scans first |
| GET /api/v1/scans/{id} | Scan UUID | Status, summary, timestamps, repository name |
| GET /api/v1/scans/{id}/findings | `severity`, `rule`, `language`, `q`, `include_suppressed` | Normalized finding objects; descending priority |
| GET /api/v1/scans/{id}/summary | None | Counts, engine states, coverage, duration and warnings |
| GET /api/v1/scans/{id}/dependencies | None | Exact/unresolved declarations, lookup states and advisory references |
| GET /api/v1/scans/{id}/report | `format=json|html|sarif|csv` | Attachment download; 409 before a scan is finished |
| GET /api/v1/scans/{id}/baseline | None | Reviewed suppressed fingerprints, version 1 |
| GET /api/v1/scans/{id}/compare/{previous} | Same repository identity, completed runs | New/resolved fingerprints and unchanged count |
| POST /api/v1/findings/{id}/explain | `{ "use_ai":false, "consent_external":false }` | Validated explanation or honestly labeled local fallback |
| POST /api/v1/findings/{id}/suppress | `{ "reason":"A specific reviewed reason, at least 12 characters" }` | Decision recorded and current counters updated |
| GET /api/v1/settings | None | Preferences and nonsensitive server capability configuration |
| PUT /api/v1/settings | fail_on, exposure, critical_asset, exclusions | Validated preferences for future scans |

## Scan response

`id`, `repository_id`, `name`, `status`, ISO timestamp strings, `summary`, and nullable `error` are described by `ScanView`. Status values are queued, running, completed, partial or failed. `completed` means selected bounded operations completed; it does not imply a comprehensive assessment. `partial` can mean unsupported declarations, disabled advisory intelligence, parse failures, skipped source or unavailable engines.

## Finding response

The response contains a UUID, scan ID, rule ID, fingerprint, location, language, title, potential-impact description, remediation, masked evidence, source severity, normalized severity, derived priority/score/reason, confidence, CWE, OWASP, engines, advisory ID/aliases, supplied CVSS vectors, references and suppression state. Unknown authoritative values remain absent/null. A supplied CVSS vector is not converted into an invented numeric score.

## Error semantics

401 means missing/invalid token. 403 means forbidden repository or missing external-AI consent. 404 means unknown resource. 409 means report/compare requires a finished scan. 413 means body limit. 415 means upload media type is wrong. 422 means validation/intake error. 429 means queue/mutation limit. 503 means token setup or database readiness problem. Scanner subprocess failures become a durable failed scan, not a long blocking HTTP request.

## Python client example

```python
import os
import httpx

with httpx.Client(base_url="http://127.0.0.1:8000", timeout=15,
                  headers={"Authorization": f"Bearer {os.environ['RS_API_TOKEN']}"}) as client:
    response = client.post("/api/v1/scans", json={"source": "demo"})
    response.raise_for_status()
    scan_id = response.json()["id"]
    print(client.get(f"/api/v1/scans/{scan_id}").json()["status"])
```

This immediately reads status; it does not assume the queued scan already finished. `.env` is loaded by the server; a separate client must load/export its token explicitly.
