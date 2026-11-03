# Free Render interview demo

The owner authorized a free deployment to Render's **My Workspace** on 2026-11-03. This profile uses one Docker web service in Singapore, containing the API, built React frontend and one scanner worker. SQLite and staging files live on the service's temporary filesystem. No paid database, persistent disk or paid compute is requested.

**Live URL:** [https://reposentinel-ai-demo.onrender.com/](https://reposentinel-ai-demo.onrender.com/)

**Owner dashboard:** [reposentinel-ai-demo on Render](https://dashboard.render.com/web/srv-dbkoq9m7bikc73fg65qg)

## Storage and availability

This is an interview demonstration, not durable hosting. On Render's free plan the service sleeps after inactivity, may take about a minute to wake, and loses local files on restarts, redeploys and spin-down. Scan history, settings, suppressions and uploaded snapshots can disappear. Download reports you need to keep. Do not upload the only copy of any work.

The login and dashboard display this limit when `RS_DEMO_MODE=true`. Authentication remains required for every scan, setting and report. A public HTTPS URL does not make scan results or administrative access anonymous. The UI gets only the public boolean flag from `/health`; credentials are never sent to it without the owner's login entry.

## Configuration and ownership

Initial creation used the connected Render API tools. Render service settings are the live source of truth. `render.free.yaml` records the recreation configuration, but it is **not** attached to a Blueprint sync. The creation tool does not expose an HTTP health-check-path field, so the live service uses Render's default TCP health checks; our verification separately checks `/health` over HTTPS. The recreation Blueprint sets `/health` explicitly. The root `render.yaml` remains the separate paid persistent deployment option and must not be applied unintentionally.

The free profile keeps the real Bandit, detect-secrets, Semgrep, pip-audit and OSV integration enabled. Lower CPU can make scans slower, so per-engine timeout is 60 seconds and overall scan timeout is 300 seconds, with at most two pending scans. These limits do not guarantee all repositories fit the 512 MB memory allowance. Failures and partial coverage remain visible; the deployment will not silently upgrade to paid compute.

Automatic deploys are disabled. Verify a source commit in GitHub Actions before manually deploying it. The optional GitHub `deploy` job can be enabled later with an approved Render deploy hook and health URL; no hook credential is committed.

## Sign in

Open the Render service dashboard, choose **Environment**, and reveal/copy `RS_API_TOKEN` into the app's **Workspace token** field. Keep the token private. It is generated for this deployment independently of local development credentials. Refreshing the app clears the browser's in-memory token and requires login again.

The generated token is stored as a Render environment variable; it is not included in this repository or a source archive. Rotate it in Render and redeploy if it is exposed. An AI provider key is optional and remains unconfigured until the owner supplies an approved provider. Deterministic local guidance still works.

## Verification record

Implementation commit `7997cd2fe677bd8e5d2eb9d49f09c626634a8ea3` passed [GitHub Actions run 41595665902](https://github.com/sumant30s/reposentinel-ai/actions/runs/41595665902), including 72 backend tests, five frontend tests, the security gates, Docker build and PostgreSQL smoke test. The free recreation Blueprint also passed validation against Render's current public JSON Schema.

The first create-service request returned HTTP 400 because Render could not fetch the private repository. After the owner connected GitHub and granted repository access, the next request created service `srv-dbkoq9m7bikc73fg65qg`. This resolved the access blocker without making the source repository public.

Deployment `dep-dbkoqae7bikc73fg67s0` reached **live** on 2026-11-03 at 13:00:28 IST (07:30:28 UTC). It runs commit `c9a6499b7112e826c512fc60d353faae7c6fdbe2`; the change from the CI-verified `7997cd2` commit is documentation only. The deployed `/health` response confirmed that exact revision and `demo_mode=true`.

The authenticated public HTTPS smoke test completed a real demo scan with **17 candidate findings**, with Bandit, detect-secrets, Semgrep and pip-audit all reporting `completed`, live OSV advisories, and no coverage warnings. JSON, HTML, CSV and SARIF downloads all returned HTTP 200. Unauthenticated scan access returned HTTP 401. Deterministic `local-guidance` explanations worked; live model inference is still unconfigured and unverified.

The recorded scan's analysis duration was 59.682 seconds; its stored start/finish timestamps span about 70 seconds. These are distinct measurements for this three-file fixture on free compute, not general performance claims. See `docs/evidence/render-smoke.json` for actual responses and `render-deployment.json` for service/deploy metadata. A later health/login check after service sleep/start succeeded and showed zero retained scans, consistent with the disclosed temporary-storage behavior.

Browser visual inspection verified the public login page and storage notice. The genuine screenshot is `docs/evidence/render-login.jpg`. The authenticated scanner flow was verified via HTTP, not by browser sign-in; dashboard visual interaction remains unverified. No paid resources or live model calls were created.

Official constraints: [Render free services](https://render.com/docs/free), [environment variables](https://render.com/docs/configure-environment-variables), [deployment lifecycle](https://render.com/docs/deploys).
