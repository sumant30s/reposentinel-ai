# Architecture and engineering decisions

## Boundaries

RepoSentinel is a single-owner application with two processes: FastAPI and one worker. PostgreSQL/SQLite stores the job queue and all normalized findings. The filesystem holds a bounded temporary source snapshot. Browser code never receives a server filesystem path, model key, database password or source archive after intake.

The web process only validates, queues and reads results. The worker claims a queued row through an update conditional on `status='queued'`. Only one contender can change that row to `running`. It launches a child interpreter for that job. The parent enforces a wall-clock deadline and terminates its process group on Unix or its process tree on Windows. A lease expiration records a failed job after a worker crash; it does not silently turn partial work into a successful result.

## A request's lifecycle

1. React's in-memory bearer token enters the Authorization header.
2. A body-limiting ASGI middleware rejects unauthenticated writes before buffering; JSON is limited to 64 KiB and archive bodies to 8 MiB.
3. FastAPI validates the request with Pydantic and checks the shared mutation limit.
4. Intake rejects arbitrary hosts, URL credentials, traversal, special archive files, oversized/overcompressed input and unsupported formats.
5. `enqueue` stores a repository row and queued scan with a snapshot of current risk preferences.
6. The worker claims the job, writes a filtered snapshot and runs only trusted scanner executables/configurations.
7. Python AST walks call/assignment nodes; secret detectors return locations without values. Manifest parsing only extracts declarations.
8. OSV receives exact package coordinates, caches successful responses and explicitly labels failed/stale/partial lookups. Connected advisory aliases collapse to one advisory record.
9. External analyzer output becomes the same `FindingData` schema. Raw output/source is not committed to result tables.
10. Fingerprint deduplication merges matching rule/file/line/advisory locations. Contextual priority is calculated without changing source severity.
11. One transaction stores normalized findings/dependencies and the final scan summary. Source staging is removed in `finally`.
12. TanStack Query polls scan status and refreshes results. Exports are created on demand. Explanations are never auto-applied.

## Database

| Table | Key fields | Purpose |
|---|---|---|
| repositories | id, name, source | Intake identity shared by scans |
| scans | repository_id, status, timestamps, lease_until, attempts, options, summary, error | Durable work and actual analysis status |
| findings | scan_id, fingerprint, rule_id, severity, priority, file, line, payload, suppressed | Normalized review records |
| dependencies | scan_id, payload | Declared coordinates and lookup results |
| advisories | key, fetched_at, payload | Successful OSV cache by ecosystem/name/version |
| suppressions | repository_id, fingerprint, reason, created_at | Persistent reviewed decisions |
| preferences | id, payload | Single-owner thresholds/exposure/exclusions |

`JSON` columns keep bounded engine metadata flexible; indexed relational columns support common scans/findings queries. This is a conscious simplicity tradeoff. There is no row-level multi-user ownership because the product explicitly has one owner. Adding users requires a user model, scoped queries, per-user limits and isolation, not simply adding a login screen.

Alembic's initial migration explicitly creates these tables. Runtime startup uses `alembic upgrade head`. `Base.metadata.create_all` appears only in ephemeral CLI/test databases, not as the production migration mechanism.

## Rule algorithm and complexity

Parsing source takes approximately O(n) time for normal-sized source; the AST visitor examines each node once. Local assignment tracking recognizes `query=f'...'; cursor.execute(query)` without claiming interprocedural taint analysis. Function bindings are reset at boundaries. Complex control flow, rebinding, aliases and custom database wrappers can produce false positives/negatives.

Fingerprinting is SHA-256 over rule ID, relative path, line and advisory ID. It does not hash raw secrets. A dictionary merges exact fingerprint matches in expected O(f), where f is the finding count. Findings sort by score in O(f log f). Line movement changes the fingerprint; reviewers must not equate a changed fingerprint with a newly introduced vulnerability.

Priority score = severity base (20/45/70/90) + confidence adjustment (-10/0/+5) + internet context (0/+10) + critical-asset context (0/+10), clamped to 0–100. Bands: low <40, medium 40–64, high 65–84, critical ≥85. This is a transparent heuristic, not CVSS, EPSS, likelihood or patient-harm probability.

## Important tradeoffs

- A relational queue is easier to inspect and recover for this small project than Redis/Celery, but deployment stays single instance with shared staging. Horizontal scaling is explicitly unsupported.
- SQLite is convenient for local work; PostgreSQL provides persistent cloud data. Both use the same ORM/migration model. PostgreSQL execution depends on the Compose/CI verification result, not on model definitions alone.
- GitHub source arrives through the fixed codeload host instead of a general `git clone`. This avoids hooks, submodules, Git configuration and arbitrary remote transports. Other Git hosts/history are unsupported.
- Raw snippets are omitted entirely from stored findings. This sacrifices code-specific AI patches to sharply reduce secret exposure. Locations and trusted remediation remain useful.
- AST and established analyzers coexist. The project demonstrates rule design while retaining real Bandit/Semgrep/detect-secrets/pip-audit integrations. It does not claim those tools' entire rule coverage.
- The same-origin frontend keeps CORS simple. API tokens stay only in React module memory; refreshing requires reauthentication.
- An authenticated owner can upload a constrained archive. This is still not an Internet-scale isolation boundary. Restrict access and add sandboxed per-job workers before offering scanning to unknown users.
