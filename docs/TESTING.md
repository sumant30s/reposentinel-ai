# Actual verification record

Build session: 2026-11-02–03. Execution environment: Linux x86_64, Python 3.12.14, Node.js 24.22.1. Windows 11 is the user's target environment but was not available for direct execution.

## Evidence and limits

| Verification | Observed result | Evidence |
|---|---|---|
| Backend unit/integration tests | 72 passing in the recorded run; ≥80% overall application coverage gate passed | `evidence/pytest-output.txt`, `pytest.xml`, `coverage.json` |
| Overall statement coverage | 90.34% in the final local run; no excluded application modules | `evidence/coverage.json` |
| Python lint/format/type checks | Passed locally after fixes | Ruff + mypy commands in README/build journal |
| Frontend | Five Vitest tests, TypeScript/Vite build and ESLint passed after adding the free-demo notice | [Run 41595665902](https://github.com/sumant30s/reposentinel-ai/actions/runs/41595665902); earlier four-test results are retained as historical evidence |
| Frontend dependency audit | Zero known vulnerabilities returned after upgrading Vitest and overriding minimatch | `evidence/npm-audit.json` |
| Python dependency audit | Five known advisories in Semgrep's pinned MCP/OpenTelemetry dependencies | `evidence/python-audit.json` |
| Scoped dependency gate | No unreviewed blocking advisories; five exact exceptions expire 2026-12-02 | `evidence/dependency-gate.json`, `../security/advisory-exceptions.json` |
| Bandit self-scan | Medium/high gate passed; full initial low-priority subprocess/import notices retained | `evidence/bandit-ci.json`, `bandit-self.json` |
| Semgrep self-scan | Three bundled JS/TS rules: zero matches in application scan | `evidence/semgrep-ci.json`; this is not the full Semgrep registry |
| Real analyzer adapters | Bandit, detect-secrets, Semgrep and pip-audit completed on labeled demo | `evidence/http-smoke.json` |
| Live OSV | Exact Jinja2 2.11.2 declaration returned real advisories; alias grouping reduced duplicate records | `evidence/http-smoke.json`; initial ungrouped CLI report retained as build evidence |
| Real HTTP application smoke | /health 200; React static index 200; invalid token 401; worker scan completed; JSON/HTML/CSV/SARIF exports 200 | `evidence/http-smoke.json` |
| SARIF | Generated demo report validated against the checked-in full 2.1.0 JSON schema | `evidence/sample.sarif`, `../scripts/validate_sarif.py` |
| Synthetic performance | 100,000 lines / 200 generated inputs, 1.1476 seconds for AST + secret patterns in the measured run | `evidence/benchmark.json` |
| Synthetic labeled corpus | 10/10 positives detected; 0/10 negative snippets flagged | `evidence/benchmark.json`; small self-authored corpus only |
| Live AI inference | Not tested: no model key or running Ollama model was supplied | Valid/invalid provider contracts and fallback/consent behavior tested with clearly mocked HTTP responses |
| Browser visual QA / screenshot | Public Render login page and free-demo notice visually verified; signed-in dashboard interaction remains unverified | `evidence/render-login.jpg`; replaces the earlier blocked managed-preview attempt for login-screen verification only |
| Docker / PostgreSQL | Passed on GitHub's Linux runner: image built, both services healthy, controlled scan completed with 17 candidate findings | Actions run 41593022163 and `evidence/github-ci.json`; not run locally or on Windows |
| GitHub Actions | Latest implementation run passed: 72 backend tests, 90.27% CI statement coverage and five frontend tests | [Run 41595665902](https://github.com/sumant30s/reposentinel-ai/actions/runs/41595665902) |
| Render public deployment | Live free Docker/SQLite service; correct revision, real completed scan with 17 candidate findings, all four report formats HTTP 200 | `evidence/render-deployment.json`, `evidence/render-smoke.json` |
| GHCR / automatic CD | Image publication and GitHub deploy-hook jobs remain disabled | Initial public deployment was performed directly through Render after verified CI |

## Verified GitHub publication and CI

The private repository is [sumant30s/reposentinel-ai](https://github.com/sumant30s/reposentinel-ai). Implementation commit `e7a917da2154480330afadbeb18ec944b57e8cf6` contains the 117 initial project files. [Actions run 41593022163](https://github.com/sumant30s/reposentinel-ai/actions/runs/41593022163) completed successfully on 2026-11-03 at 06:59:13 UTC. The checked-in `evidence/github-ci.json` records the observed run, job steps and results.

The runner used Python 3.12.15. Its 72 backend tests passed with 90.26% statement coverage, compared with 90.34% in the final local Python 3.12.14 run. These are separate actual measurements, not interchangeable rounded claims. Frontend lint, four tests and the production build passed. Bandit, bundled Semgrep rules, the scoped dependency gate, npm audit, tracked-file secret check and SARIF validation passed. The raw Python audit still reported five known advisories covered by exact expiring exceptions.

The Docker image built successfully. Compose started PostgreSQL and the application, both became healthy, `/health` returned `ok`, and the authenticated deployed smoke check reported `completed` with 17 candidate findings. Compose then removed its disposable containers and volumes. This is evidence of a successful ephemeral Docker/PostgreSQL deployment in CI, not a public website.

The run uploaded `validation-evidence`, artifact ID `13210724226`, digest `sha256:7046011acb643761929774cf2c94305fadf138bcebcf448850f5b205e09ffbc8`, with expiration 2026-11-17. Download it from the run before that date for the runner-generated XML/JSON reports. GitHub's job logs corroborate the summarized results. The source repository separately retains local evidence and the remote result summary.

The initial run's `publish` and `deploy` jobs were **skipped** because their activation variables were unset. That run did not deploy Render. It also emitted nonfatal upstream TestClient/Node deprecation and frontend bundle-size warnings; those are maintenance items, not test failures. A later direct Render deployment is recorded below. Native Windows and live model inference remain unverified.

## Public free Render deployment

The free-demo implementation passed [Actions run 41595665902](https://github.com/sumant30s/reposentinel-ai/actions/runs/41595665902): 72 backend tests, 90.27% CI coverage, five frontend tests and all existing security/Docker/PostgreSQL gates. On 2026-11-03 the authorized direct deployment reached `live` at [reposentinel-ai-demo.onrender.com](https://reposentinel-ai-demo.onrender.com/), running commit `c9a6499b7112e826c512fc60d353faae7c6fdbe2` (documentation-only changes after the tested implementation).

Actual HTTPS checks verified the expected `/health` revision, `demo_mode=true`, static index HTTP 200, unauthenticated API HTTP 401, authenticated demo scan completion with all four engines and live OSV, 17 candidate findings, all four report downloads HTTP 200 and deterministic local guidance. The recorded analysis duration was 59.682 seconds for three fixture files; scan start/finish timestamps span about 70 seconds. No large-repository throughput claim follows from this run.

The browser rendered the login screen and temporary-storage warning correctly; `evidence/render-login.jpg` is a real screenshot. Browser login/dashboard interaction was not performed. The free service's SQLite data is temporary; a later authenticated check found zero retained scans after the service had slept/restarted. Download reports for retention. `evidence/render-deployment.json` and `evidence/render-smoke.json` preserve the observed deployment and test results without credentials.

## What the automated tests actually cover

- Positive and safe SQL patterns, function scope, import aliases, eval/exec, pickle, shell, hashes, TLS, debug and credential literals.
- Omission of raw fixture credentials from findings and model payloads.
- URL scheme/host/userinfo/path constraints; ZIP traversal, drive/backslash paths, duplicates, symlinks, bombs, invalid files and quotas.
- Binary/encoding/generated-folder exclusion and safe snapshots.
- requirements/PEP 621/npm/Maven parsing; unknown ranges and invalid/XML entity input.
- Live/empty/cached/stale/failed OSV contract behavior and advisory alias merging.
- All external adapter normalization branches using deterministic fixtures; separate real-engine execution evidence.
- API authentication, settings validation, queue limits, rate limits, uploads, scan lifecycle, failure/recovery, summaries, filtering, reports, suppression and comparisons.
- AI consent, missing configuration, successful structured contracts, invalid JSON/schema/provider failure and local fallback.
- HTML escaping, CSV formula handling, SARIF fields and policy exits 0/1/2.

Test mocks are intentionally used for network edge cases and contract isolation. They are not presented as live production integrations. The real HTTP smoke script starts a subprocess supervisor and performs requests to the actual bound server in the same execution environment; it is not just TestClient.

## Performance/accuracy interpretation

The requested 100,000-line/two-minute **representative laptop, complete pipeline** target has not been measured. The included 1.1476-second result excludes archive intake, external analyzers, advisory lookups, persistence and UI and ran in a Linux container. It establishes only that narrow test's behavior.

The requested <20% false-positive goal cannot be generalized from twenty project-authored snippets. Both false-positive rate and false-discovery rate are zero in that small corpus, but a real independent corpus may behave differently. Collect labeled repositories, define denominators and language mix, include hard negatives, record false negatives and report confidence/limitations before making a broader claim.

## Reproduction and acceptance

Use the exact commands in README. The hash-locked Python requirements and npm lockfile reproduce package inputs. Expected vulnerable fixture CLI exit is **1**, not 0. A missing/failed analyzer is **2**, not a silently clean result. Offline dependency state is visibly unverified even if intentional offline mode is not itself an execution error.

Coverage changes with code; inspect the latest JSON rather than memorizing the number in a prior message. Full third-party audits may change when new advisories are published. Do not replace actual new failures with old stored green results.
