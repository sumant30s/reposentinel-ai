# Honest scope and limitations

1. **Single owner only.** One bearer token, one queue worker and one API instance. No tenant isolation, SSO or role system.
2. **Bounded scanning.** Small ZIP/source snapshots only; fixed size/file/time limits. GitHub default HEAD only. No submodules, branches selection, private repositories or Git history scanning.
3. **Incomplete language/data-flow coverage.** Python intraprocedural heuristics plus selected Bandit checks and three JavaScript/TypeScript Semgrep rules. No full taint engine, Java/C#/Go rules, runtime exploitation or DAST.
4. **Dependency declarations are not an SBOM of the deployed system.** No complete lockfile/transitive/environment resolution. Ranges, dynamic metadata and unsupported formats are explicitly unresolved. No package install/build is performed.
5. **Version age is not vulnerability evidence.** There is no blanket “all old packages are vulnerable” rule and no lifecycle/EOL service integration. OSV matches published advisories, not every outdated release.
6. **No numeric CVSS invention.** Supplied vectors/source severity are retained. Unknown authoritative severity defaults to a documented medium triage level, without claiming that source assigned that value. No EPSS or KEV integration was requested for this project's core and none is claimed.
7. **AI proposes generic patterns.** No raw snippets, filenames or source are transmitted. There is no context-specific automatic patch, test generation execution or commit. External/Ollama adapters are contract-tested; live model output requires credentials/a running model and was not verified here.
8. **Line fingerprints move.** A refactor may create “new/resolved” locations without changing risk. Different engines can flag different lines of one underlying issue.
9. **Source retention is operational.** Finished/failed/stale-running job directories are removed. A host crash can leave queued/orphaned staging; operator cleanup/retention policy and encrypted storage/backups are still needed.
10. **Container configuration is not a complete sandbox.** Parsing untrusted inputs can exploit analyzer vulnerabilities. Public multi-tenant deployment requires dedicated isolated jobs, stronger egress controls and quotas.
11. **Known dependency advisories remain.** Five exact Semgrep transitive advisories have recorded reachability exceptions, expiring 2026-12-02. The raw audit remains available; do not call the environment patched or vulnerability-free.
12. **Measurements have a limited scope.** The 100,000-line measurement covers synthetic in-memory AST/pattern scanning in this Linux container. The 20-snippet corpus is project-authored. Neither establishes representative laptop end-to-end performance or <20% false positives on real repositories.
13. **Environment-dependent verification.** Windows, Docker/PostgreSQL, browser visual QA, GitHub CI, GHCR and cloud deployment have separate verification statuses in TESTING.md. A passing SQLite test cannot stand in for a PostgreSQL deployment.
14. **Not regulated-product certification.** The project demonstrates relevant engineering habits. It does not validate a medical device, prove regulatory compliance, implement a quality-management system or establish clinical safety.

Future improvements should be evidence-driven: expand an independent labeled corpus, add lockfile resolution, improve stable fingerprints, split scanner isolation, introduce multi-user authorization and strengthen source retention. None of those features is silently presented as done.
