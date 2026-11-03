# Project build journal — observed work

This records actual implementation/verification activity. It does not invent developer incidents, deployments or performance claims. Initial implementation was authored by an AI coding assistant under the user's autonomous-build request.

## Requirements and environment

- Read the supplied RepoSentinel AI build prompt and created a new local Git repository with `git init -b main`.
- Observed Python 3.12.14, Node 24.22.1 and Git 2.51.1. Docker and gh were not installed.
- Direct DNS lookups were unavailable, but package installation through the environment's configured proxy worked. An initial `uv pip install --retries 0` failed because that flag was unsupported; retried with `UV_HTTP_RETRIES=0`.
- Inspected the connected GitHub profile/repositories; `reposentinel-ai` did not exist. The native connector could not create repositories, so the authorized GitHub browser session created a **private** repository with an initial README. Actual initial remote commit: `caadb55768ac47009b1c369e302e96470293e527`.

## Backend and scanning

- Added typed settings, request/finding/explanation schemas, SQLAlchemy tables and an Alembic-generated explicit initial migration.
- Implemented token authentication, bounded body middleware, queue limits, API routes and same-origin static frontend serving.
- Implemented bounded local snapshots, ZIP validation and fixed-host GitHub source download without running target code.
- Added Python AST rules, secret patterns and actual Bandit/detect-secrets/Semgrep/pip-audit adapters with timeouts and structured statuses.
- Parsed supported dependency declarations, integrated real OSV requests/cache behavior, and separated source severity from heuristic priority.
- Added durable database claims, worker subprocess deadlines, lease recovery and staging cleanup.
- Added exports, source-omitting explanations, external consent, provider abstractions and deterministic fallback.

## Observed failures and fixes

| Observation | Actual correction |
|---|---|
| First CLI scan raised ImportError: httpx needed SOCKS support for this environment's proxy | Added `httpx[socks]`, installed/locked socksio, reran successfully |
| mypy rejected generic strings assigned to constrained severity/confidence types | Added explicit type narrowing/casts and typed exposure; reran type checking |
| First dependency parser draft referenced a nonexistent defusedxml exception export | Imported DefusedXmlException from its actual module before test verification |
| Initial live advisory report counted GHSA/PYSEC aliases separately | Added alias-connected merging, preserved IDs/references and a regression test; final HTTP scan returned 17 location/advisory findings instead of the initial 22 |
| Initial frontend test dependency audit reported critical Tinypool/Vitest advisories and a minimatch advisory | Upgraded Vitest to 5.1.0, used a compatible minimatch 11 override, reran frontend build/lint/tests; final npm audit returned zero |
| Attempting to update Vite/plugin versions together hit an npm peer-resolution conflict | Retained the compatible Vite 7/plugin 5 pair; upgraded the actually vulnerable test tool independently |
| Python audit found five advisories pinned by Semgrep | Kept the raw findings, documented exact currently unused feature paths and a 2026-12-02 expiry; gate fails other/new/expired issues; no fabricated patched status |
| Bandit flagged a literal all-interface development bind and URL opening | Defaulted local bind to loopback; Docker explicitly sets its host; deploy helper validates HTTPS and rejects redirects |
| Secret scan flagged an Alembic revision hex and an invented benchmark password | Added narrow inline allowlist comments explaining each non-secret, not a broad production-path exclusion |
| Managed browser preview failed because the preview environment lacked the Python .venv | Recorded browser QA/screenshot as unverified; did not fabricate a screenshot or substitute mock UI results |
| A server launched in a separate terminal execution was not reachable from another execution | Added `http_smoke.py` to start server/worker and make real HTTP requests within one execution context; smoke test passed |
| Ordinary git transport could not authenticate to the private GitHub repository | Kept credentials out of files/logs and used the connected GitHub Git-data API for authorized publication |

## Verification reached locally

- Backend tests grew from 67 passing with 85% coverage to 72 passing with 91.39% coverage, then 90.34% overall statement coverage after additional URL validation/security-summary code in the final local run.
- Frontend ESLint, TypeScript/Vite production build and four UI/API tests passed after dependency updates.
- Real offline analyzer scan completed with 12 location findings and explicitly disabled dependency intelligence.
- Real online scan exercised all four external analyzers and OSV. After advisory alias grouping, the HTTP smoke run completed with 17 findings; this is a count of candidate locations/advisories, not unique exploitable vulnerabilities.
- `/health`, React static serving, invalid-token rejection and all report downloads were exercised over actual HTTP.
- The generated SARIF report validated against the full checked-in schema.
- The 100,000-line synthetic AST/pattern benchmark measured 1.1476 seconds in this container. The 10 positive/10 negative snippet corpus had no misses/false positives in that narrow run. Neither result establishes laptop/full-pipeline or independent real-world accuracy targets.
- Docker/PostgreSQL, live model inference, browser rendering and Render deployment were not represented as locally verified.

## Evidence commands

```bash
uv pip install --python .venv/bin/python -e 'backend[dev,semgrep]'
uv lock --project backend
uv export --project backend --extra semgrep --no-dev --no-emit-project --format requirements-txt --output-file backend/requirements.lock
uv export --project backend --extra dev --extra semgrep --no-emit-project --format requirements-txt --output-file backend/requirements-dev.lock
ruff check --config backend/pyproject.toml backend scripts
ruff format --config backend/pyproject.toml --check backend scripts
mypy --config-file backend/pyproject.toml backend/app
pytest backend/tests --cov=app --cov-config=backend/pyproject.toml --cov-report=json:docs/evidence/coverage.json --junitxml=docs/evidence/pytest.xml
npm run lint --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
python scripts/http_smoke.py
python scripts/benchmark.py
python scripts/audit_dependencies.py
python scripts/check_secrets.py
python scripts/validate_sarif.py docs/evidence/sample.sarif
```

## Observed remote publication and validation — 2026-11-03

Created the private [sumant30s/reposentinel-ai](https://github.com/sumant30s/reposentinel-ai) repository and published 117 project files through the connected GitHub Git-data API. The implementation commit is `e7a917da2154480330afadbeb18ec944b57e8cf6`, tree `680c97ecd0f510769246b13bec3cc969c5dee141`. No executor Git credentials were embedded in files.

[Actions run 41593022163](https://github.com/sumant30s/reposentinel-ai/actions/runs/41593022163) completed successfully at 06:59:13 UTC. The actual runner logs reported 72 backend tests with 90.26% statement coverage and four frontend tests. All checks passed, including locked installs, lint/format/types, frontend build, security gates with the documented dependency exceptions, real analyzer/SARIF validation, Docker build and PostgreSQL Compose smoke testing. The deployed controlled scan completed with 17 candidate findings and the services were torn down afterwards. No CI code fixes were needed for this first published run.

The workflow uploaded validation evidence (artifact `13210724226`, expires 2026-11-17). `docs/evidence/github-ci.json` preserves the observed metadata and result summary. A documentation-only follow-up records these results without rerunning unchanged code.

GHCR `publish` and Render `deploy` were skipped because their activation variables were unset. No Render account, deployment hook, model API key or running local model was supplied to the build. Public cloud hosting, browser visual QA, native Windows and live model inference remain unverified. The owner must review the paid Render plan and connect the account before provisioning can proceed.
