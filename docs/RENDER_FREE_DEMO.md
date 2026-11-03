# Free Render interview demo

The owner authorized a free deployment to Render's **My Workspace** on 2026-11-03. This profile uses one Docker web service in Singapore, containing the API, built React frontend and one scanner worker. SQLite and staging files live on the service's temporary filesystem. No paid database, persistent disk or paid compute is requested.

## Storage and availability

This is an interview demonstration, not durable hosting. On Render's free plan the service sleeps after inactivity, may take about a minute to wake, and loses local files on restarts, redeploys and spin-down. Scan history, settings, suppressions and uploaded snapshots can disappear. Download reports you need to keep. Do not upload the only copy of any work.

The login and dashboard display this limit when `RS_DEMO_MODE=true`. Authentication remains required for every scan, setting and report. A public HTTPS URL does not make scan results or administrative access anonymous. The UI gets only the public boolean flag from `/health`; credentials are never sent to it without the owner's login entry.

## Configuration and ownership

Initial creation uses the connected Render API tools. Render service settings are the live source of truth. `render.free.yaml` records the equivalent recreation configuration, but it is **not** attached to a Blueprint sync. The root `render.yaml` remains the separate paid persistent deployment option and must not be applied unintentionally.

The free profile keeps the real Bandit, detect-secrets, Semgrep, pip-audit and OSV integration enabled. Lower CPU can make scans slower, so per-engine timeout is 60 seconds and overall scan timeout is 300 seconds, with at most two pending scans. These limits do not guarantee all repositories fit the 512 MB memory allowance. Failures and partial coverage remain visible; the deployment will not silently upgrade to paid compute.

Automatic deploys are disabled. Verify a source commit in GitHub Actions before manually deploying it. The optional GitHub `deploy` job can be enabled later with an approved Render deploy hook and health URL; no hook credential is committed.

## Sign in

Open the Render service dashboard, choose **Environment**, and reveal/copy `RS_API_TOKEN` into the app's **Workspace token** field. Keep the token private. It is generated for this deployment independently of local development credentials. Refreshing the app clears the browser's in-memory token and requires login again.

The generated token is stored as a Render environment variable; it is not included in this repository or a source archive. Rotate it in Render and redeploy if it is exposed. An AI provider key is optional and remains unconfigured until the owner supplies an approved provider. Deterministic local guidance still works.

## Verification record

Implementation commit `7997cd2fe677bd8e5d2eb9d49f09c626634a8ea3` passed [GitHub Actions run 41595665902](https://github.com/sumant30s/reposentinel-ai/actions/runs/41595665902), including 72 backend tests, five frontend tests, the security gates, Docker build and PostgreSQL smoke test. The free recreation Blueprint also passed validation against Render's current public JSON Schema.

On 2026-11-03 the connected Render create-service operation returned HTTP 400: the repository URL was invalid or unfetchable. GitHub independently confirmed that `sumant30s/reposentinel-ai` exists and is private. Render's service list remained empty. The likely blocker is missing Git deployment credentials or missing repository permission for Render; the connector's authentication alone does not grant Render GitHub access.

**No service or public URL was created, and no live HTTP test is claimed.** `docs/evidence/render-deployment.json` records the attempt and the verified CI result. To unblock, connect GitHub under Render Account Settings → Account Security → Git Deployment Credentials, then grant the Render GitHub app access specifically to this repository. The owner has already authorized this workspace and free plan; no new plan approval is needed when retrying the same deployment.

Official constraints: [Render free services](https://render.com/docs/free), [environment variables](https://render.com/docs/configure-environment-variables), [deployment lifecycle](https://render.com/docs/deploys).
