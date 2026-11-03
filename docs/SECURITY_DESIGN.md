# Security design and threat model

## Protected assets and assumptions

Assets include uploaded source, credentials that may be embedded in it, finding history, API/model/database tokens and host resources. Threats include malicious archive paths, decompression bombs, SSRF through repository URLs, expensive parsing, accidental source execution, credential leakage, prompt injection, forged report markup, CSV formulas and unauthenticated scan abuse.

The supported deployment is a single trusted owner with a long random bearer token. It is not a hardened multi-tenant sandbox. Docker process/memory/CPU restrictions reduce blast radius, but the API and scanner still share a container. Parser bugs and hostile input are residual risks. Do not expose unrestricted public scanning.

| Threat | Implemented control | Residual limitation |
|---|---|---|
| Arbitrary local disk reads | No web API accepts paths; CLI path is an explicit local-user action | Local snapshot of a changing tree is not a race-proof filesystem sandbox |
| SSRF | GitHub URL parser, fixed codeload host, HTTPS, no redirects, exact web allowlist | Administrator controls AI endpoints; owner must choose trusted hosts |
| ZIP escape/special files | Reject absolute paths, `..`, backslashes, drives, duplicate casefolded names, symlinks/devices | ZIP only; unsupported archives are rejected |
| Resource exhaustion | 8 MiB compressed, 20 MiB expanded, 512 KiB/file, 500 discovered files, bounded entry count, ratio limit, job deadline | Large repositories intentionally unsupported; one instance only |
| Source execution | Parse/snapshot only; no pip installs from target; pip-audit uses sanitized exact requirements with --disable-pip --no-deps | Trusted analyzer binaries still parse attacker-controlled bytes |
| Raw secret disclosure | No source snippets/values persisted in findings; detector output normalized; generic errors | Temporary source exists until job cleanup; backup/host access needs protection |
| AI prompt injection | No repository strings sent to model; trusted rule catalog metadata only | Model advice may still be incorrect; output schema validates structure, not truth |
| AI data transfer | Explicit per-request consent for external provider; no tool execution or auto-commit | Actual model behavior/live availability requires owner verification |
| Stored/reflected XSS | React text rendering, HTML escaping, no injected HTML, CSP and nosniff | External links remain untrusted destinations |
| CSV formula injection | Prefix formula-leading cell content with apostrophe | Spreadsheet behavior varies; inspect imported reports |
| Unauthorized data | Constant-time token comparison on all /api/v1 routes; token in browser memory | No per-user roles, SSO, audit user identity or token rotation UI |
| Job interruption | Durable DB queue, conditional claim, lease expiry, atomic final persistence | Stale jobs fail visibly; they are not resumed mid-engine |
| CI secret exposure | No deploy jobs on PRs; SHA-pinned actions; env-only secrets; no credentials persisted by checkout | Production environment and branch rules must be configured by owner |

All exceptions and “partial” results should be surfaced to a reviewer. Logging records job IDs/events, not raw source or model keys. OSV package coordinates are disclosed to an external service in online mode; disable it for offline work.

## Rule scope and false positives

RS001 identifies string-built queries at SQL-looking execution calls, including a limited local assignment case. It does not prove attacker influence. RS002 catches credential-looking literals/patterns, not all secrets. RS003 flags eval/exec. RS004 flags pickle load calls. RS005 flags subprocess shell=True; constant commands have lower confidence. RS006 flags MD5/SHA1 except explicit usedforsecurity=False. RS007 flags disabled TLS verification. RS008 flags debug=True. RS009 correlates declared exact dependency versions with advisory data.

An imported function alias is recognized for selected calls. The engine does not implement complete alias, control-flow or interprocedural taint analysis. Bandit may flag a query-construction line while AST flags its execution line, leaving separate location findings for a reviewer. Deduplication does not claim to count unique exploitable vulnerabilities.

The selected OWASP mapping is explicitly **OWASP Top 10 2021**. It is a versioned educational mapping; do not present it as the latest edition or an exhaustive control mapping. CWE is a weakness category; CVE/advisory IDs identify published issues; CVSS is an external severity framework. The heuristic priority score is separate.

## Dependency advisory decisions

The raw `pip-audit` result reports five advisories in Semgrep's pinned transitive dependencies. The build does not conceal them or force incompatible package overrides. `security/advisory-exceptions.json` stores exact package, version, advisory, source reference, reachability rationale and expiry (2026-12-02). `scripts/audit_dependencies.py` fails on any other advisory, skipped package, expired exception or audit execution failure.

Four issues affect `mcp==1.29.0`: stateful HTTP session retention, HTTP client redirects, MCP bearer audience validation and remote tool-schema resolution. This application does not use MCP servers/clients, authentication or tool calls. Its Semgrep invocation is only `semgrep scan` with trusted local rules. Those features are not part of this application path.

The remaining issue affects OpenTelemetry trace-state parsing. There is no OpenTelemetry middleware/header extraction in FastAPI. Scanner children explicitly set `OTEL_SDK_DISABLED=true` and `OTEL_PROPAGATORS=none`; Semgrep metrics are off. Uvicorn uses its standard h11 path. This is a version-specific exposure assessment, not proof that the installed package is patched. Reassess immediately before enabling MCP/tracing, changing scanner behavior or deploying to unknown users. Replace exceptions with compatible upstream patched dependencies as soon as available.

Primary advisory references are recorded in the JSON exception file, including [OpenTelemetry advisory](https://github.com/advisories/GHSA-xcq7-p3pf-p88h). Inspect source reachability and deployment configuration before accepting this assessment for your environment.

## Suppression baseline

Suppress a finding only after checking context and recording evidence, such as “This literal is an invented test value; fixture is excluded from deployment.” A reason of 12–1000 characters is required. The database retains decisions by repository/fingerprint; the baseline export contains only reviewed fingerprints. The CLI applies a baseline only when explicitly provided. Repository comments such as `nosec` do not automatically suppress the built-in rules, and Bandit is invoked with `--ignore-nosec`.

Baseline v1:

```json
{"version":1,"fingerprints":["a real 64-character fingerprint copied from a reviewed finding"]}
```

The example is descriptive, not a valid ready-to-use baseline. Export the actual file from Reports. Fingerprints include line numbers, so moving code can invalidate a suppression. Scan comparison is a review aid, not a definitive “fixed vulnerability” decision.

## Production hardening still required for broader use

Before multi-user/public scanning: dedicated ephemeral per-job containers with no host mounts, restricted egress, stronger OS sandboxing, queue/storage quotas per tenant, distributed rate limiting, identity-scoped data access, formal retention/deletion controls, dependency refresh automation, security review and backup/restore drills. This build does not represent those measures as already implemented.
