# Deployment and account-owner steps

## What is included

The Docker image builds the React production bundle, installs hash-locked Python dependencies, packages the backend, runs as UID 10001 and uses tini. The supervisor applies Alembic migrations, starts one Uvicorn process and one worker, and terminates its peer when either process exits. Compose adds PostgreSQL, a health-dependent start, persistent volumes, a read-only app filesystem, writable private data/tmp, dropped capabilities, CPU/memory/process limits and a loopback host port.

The implementation workspace had no Docker executable/daemon. Local Docker execution is therefore not claimed. Check `docs/TESTING.md` and the GitHub Actions run for subsequent remote evidence.

## Run Docker locally

1. Install/start Docker Desktop with Linux containers on Windows 11.
2. In this repository, run `py -3.12 scripts\bootstrap.py`.
3. Run `docker compose up --build -d`.
4. Run `docker compose ps` and `docker compose logs app`.
5. Visit `http://localhost:8000/health`, then log into `http://localhost:8000` with the generated `.env` token.
6. Run a demo scan, verify engine statuses, download a report, stop/start the containers and confirm history persists.

Never remove volumes unless you intend to delete scan history. The sample vulnerable requirements are scan input, not application dependencies.

## GitHub Actions

The repository workflow triggers on PRs, main pushes and manual dispatch. The checks job installs locked dependencies with caching, runs Ruff/format/mypy, pytest with coverage, frontend ESLint/tests/build, Bandit, bundled Semgrep rules, dependency auditing with visible time-limited exceptions, tracked-file secret scanning, real fixture analysis and SARIF schema validation, then Docker build and PostgreSQL Compose health checks. It uploads evidence even on failure.

Owner setup:

1. Protect `main` with the `checks` status and your desired review rule. Do not disable a failing security check to merge.
2. Create a GitHub environment named `production` and add a required reviewer when your account/plan supports it.
3. Leave `PUBLISH_GHCR` and `DEPLOY_RENDER` unset until the relevant account and configuration are ready. These are repository variables, not secrets.
4. To publish images, set repository variable `PUBLISH_GHCR=true`. The job receives only `contents:read` and `packages:write`, uses `GITHUB_TOKEN`, and pushes `ghcr.io/<owner>/<repository>:<full-commit-SHA>`. It does not push images from PRs or create mutable “latest” claims.

The deployment job depends on successful checks and the production environment. A configured workflow is not evidence that it has run; record the actual Actions URL/conclusion.

## Render — not provisioned automatically

`render.yaml` defines a Docker web service, persistent scan-staging disk and PostgreSQL database. These resources can incur charges. The account owner must approve the actual plan/costs in Render before provisioning. No credentials or paid services were invented or purchased by the build.

1. Sign into the intended Render account and grant it access to the private `reposentinel-ai` repository.
2. Review the Blueprint. Select an instance with sufficient memory for Semgrep and the application; increase it if real scans exhaust the instance. Review the database and persistent-disk charges.
3. Set `RS_DATABASE_URL` from the Render PostgreSQL connection string. The app translates postgres/postgresql URL schemes to SQLAlchemy's psycopg driver.
4. Use a strong `RS_API_TOKEN`; the Blueprint can generate one. Keep `RS_AI_PROVIDER=none` until you explicitly configure a model. Keep `RS_ALLOWED_REPOS` empty or set exact sample repositories you authorize.
5. Keep automatic deploys off so the GitHub quality gate is authoritative.
6. Deploy the reviewed commit initially, confirm `/health`, log in, run the labeled demo and inspect statuses. `/health` includes `RENDER_GIT_COMMIT` as its revision.
7. Add the Render **Deploy Hook URL** as GitHub secret `RENDER_DEPLOY_HOOK_URL`. The URL itself is a credential; never paste it into a tracked file or workflow logs.
8. Add repository variable `RENDER_HEALTH_URL` containing the deployed HTTPS `/health` URL, and `DEPLOY_RENDER=true`.
9. On a subsequent approved main push, the workflow passes `ref=<verified commit SHA>` to the hook and polls until the same revision is healthy. A healthy older deployment is insufficient.

The deploy hook targets the Git-backed Render service. GHCR publishing is an optional separate delivery path; this configuration does not falsely imply Render automatically consumes the GHCR image.

Relevant official references: [Docker deployment on Render](https://render.com/docs/docker), [deploy hooks and exact commit refs](https://render.com/docs/deploy-hooks), [Blueprint specification](https://render.com/docs/blueprint-spec).

## AI setup

For an installed local model: set `RS_AI_PROVIDER=ollama`, `RS_AI_MODEL` to its actual name and `RS_OLLAMA_URL` to the reachable Ollama service. A Docker container's `127.0.0.1` is itself, not your laptop; configure an appropriate host/service address. The model service must be under your control.

For an approved external provider: set `RS_AI_PROVIDER=openai-compatible`, the real model name, an HTTPS API base and the provider key. The user must check the external-consent checkbox for each requested explanation. This adapter expects a chat-completions-style JSON response and may fall back if the selected model does not support that contract. Live model requests were not verified without a key/local model.

## Operational checklist

- Restore a database backup in a disposable environment before relying on it.
- Run one application instance and share the staging directory with its worker.
- Confirm lease recovery after an intentional worker restart.
- Use HTTPS at the hosting edge; never expose bearer tokens over public HTTP.
- Keep reports private; paths and package names may be commercially sensitive even when credentials are omitted.
- Review the five Semgrep transitive advisory assessments before deployment; their expiry fails the gate.
- On migration failure, preserve the database, inspect logs and back up before attempting changes. Do not blindly recreate tables.
- Review provider costs before enabling paid model calls. RepoSentinel does not estimate or cap your provider bill beyond request-rate/output limits.
