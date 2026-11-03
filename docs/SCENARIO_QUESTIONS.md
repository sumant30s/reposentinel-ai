# Fifteen scenario-based interview questions

Use this answer pattern: **clarify scope → collect evidence → reduce immediate risk → propose a change → verify → record the decision**. The answers below describe reasoning, not invented production experience.

## 1. The scanner flags SQL injection but the developer says it is safe

Ask where the inserted value comes from and whether the function is reachable. Read the execution call and trace the relevant input. A string assembled only from fixed internal constants can be a false positive; user-controlled text deserves deeper review. Prefer parameterized values and allowlisted identifiers even when current input seems trusted. Add unsafe/safe regression examples and document any suppression reason. Do not argue from the scanner label alone.

## 2. A credential appears in a repository

Do not paste it into a ticket, model or screenshot. Confirm whether it is real through the approved process. If exposed, revoke/rotate it, assess use and notify the responsible owner. Removing one current file line does not remove Git history or invalidate the credential. Replace the code's access with an approved secret-management interface and add a test/scan check. In this project's demo, values are invented and clearly labeled.

## 3. OSV times out and returns no usable response

Mark the lookup failed or stale-cache if an old cached answer exists. Keep source-analysis results visible and mark coverage partial. Retry within a bounded policy; do not block forever or treat an empty error result as no vulnerabilities. The CLI uses exit 2 for advisory execution failures so a broken intelligence step cannot silently pass CI.

## 4. The same CVE appears as GHSA and PYSEC

Use supplied aliases to identify connected advisory records. Preserve their IDs/references while counting the grouped issue once per dependency declaration. Do not merge unrelated issues just because their titles look similar. RepoSentinel includes an alias-merging regression test; inspect the actual IDs when demonstrating it.

## 5. A dependency manifest says `package>=1`

That is a range, not an installed version. Mark it unresolved. Obtain the resolved lockfile/build inventory or actual deployment evidence before querying a specific version. This implementation does not install the target project's dependencies to resolve the range, because that could run attacker-controlled build code.

## 6. A user uploads a ZIP with `../../config.py`

Reject it before normal analysis. Resolve archive names structurally; reject traversal, absolute paths, platform-specific separators/drives and symlink/device entries. Validate expanded sizes and compression ratio as well as compressed size. Do not call a general extract-all function and hope the destination directory alone contains the writes.

## 7. A scan consumes CPU for several minutes

Check job status, source limits and engine status. The parent process enforces a hard deadline and terminates the scan process tree. Record a failure and clean staging. Investigate whether parsing, external analysis or network waiting caused the delay; reduce scope or improve the relevant limit after measurement. Do not disable every limit to make one demo look successful.

## 8. The web server restarts while a scan is queued

The database row survives if its storage survives. The worker reads queued jobs independently. Check that web and worker use the same database and staging directory. A running job whose worker died eventually fails through lease expiry; this application does not claim resumable mid-engine execution.

## 9. The AI suggests an insecure fix

Treat the model output as a suggestion. Compare it against the actual rule, source and library documentation; test the proposed behavior and reject harmful advice. Structured JSON validation only checks shape. The app never applies or commits a patch automatically, and its generic metadata-only prompt cannot know the full application context.

## 10. A repository comment tells the AI to reveal secrets

Treat repository content as untrusted data. This project prevents the comment from entering the model request by sending only trusted catalog metadata. System instructions reinforce the boundary, but minimization is more robust than hoping a model ignores every malicious string. Do not add arbitrary tool execution to the explanation feature.

## 11. A report contains a malicious filename or spreadsheet formula

Render text through React escaping, HTML-escape generated report fields, and neutralize formula-leading CSV cells. Restrict reference links to safe schemes. Avoid embedding untrusted text as executable markup. Review exports as part of application security rather than assuming that a security tool's own UI is automatically safe.

## 12. A high-severity advisory affects a shipped medical product

Establish affected component versions/products, advisory conditions, deployment exposure and reachable behavior. Coordinate with product security, engineering, safety/quality and responsible owners. Select an approved mitigation/update strategy and regression-test it; record decisions and rollout evidence. Do not independently conclude patient harm from CVSS or promise an immediate unvalidated device patch. RepoSentinel supports triage evidence, not the complete regulated-product process.

## 13. A dependency audit finds issues in the security scanner itself

Security tools also have dependencies. Preserve the raw audit, investigate reachability and seek a compatible patched release. If a documented exception is necessary, scope it to exact versions/advisories, explain mitigations and set expiry. New/expired issues must fail the gate. RepoSentinel currently records five Semgrep transitive advisory assessments; it does not claim those packages are patched.

## 14. Tests pass locally but CI fails

Read the first meaningful failure, not just the final red badge. Compare Python/Node versions, lockfiles, working directory, environment variables, filesystem assumptions and network access. Reproduce the failing command with the same configuration. Do not rerun repeatedly without a reason. Preserve the error and fix in the build journal. Local SQLite tests cannot replace PostgreSQL/Docker checks.

## 15. The interviewer asks what you personally built

Say that an AI assistant implemented the initial project under your direction. Explain the code paths you have studied, tests you personally reproduced and modifications you actually made. If you cannot explain a subsystem, say so and identify your next concrete learning step. Demonstrate one small change or test you can make independently instead of claiming professional experience you do not have.

## Practice scoring

Give yourself 0–2 points for each: identifies the boundary, requests relevant evidence, proposes a proportionate action, explains verification, and states uncertainty/ownership honestly. A 10-point answer does not require jargon. It requires a coherent, defensible decision. Ask a friend to challenge your assumptions: “What would change your answer?” and “How would you prove the fix worked?”
