# Actual verification record

Build session: 2026-11-02–03. Execution environment: Linux x86_64, Python 3.12.14, Node.js 24.22.1. Windows 11 is the user's target environment but was not available for direct execution.

## Evidence and limits

| Verification | Observed result | Evidence |
|---|---|---|
| Backend unit/integration tests | 72 passing in the recorded run; ≥80% overall application coverage gate passed | `evidence/pytest-output.txt`, `pytest.xml`, `coverage.json` |
| Overall statement coverage | 90.34% in the final local run; no excluded application modules | `evidence/coverage.json` |
| Python lint/format/type checks | Passed locally after fixes | Ruff + mypy commands in README/build journal |
| Frontend | Four Vitest tests passed; TypeScript/Vite build and ESLint passed | Actual local command runs; package-lock fixes recorded below |
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
| Browser visual QA / screenshot | Unverified: managed preview lacked the project's Python virtual environment | Preview attempt failed before application health |
| Docker / PostgreSQL | Not executable locally: Docker unavailable | Compose smoke check is configured in GitHub Actions; remote result tracked separately |
| GHCR / Render | Configured but not provisioned/published by local tests | Requires account settings, credentials, environment and hosting-cost approval |

The final GitHub Actions publication result is appended below after it is observed. Until that entry exists, this document does not claim a successful remote workflow or cloud deployment.

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
