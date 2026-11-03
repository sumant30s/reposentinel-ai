# Security policy

RepoSentinel AI is a single-owner educational/portfolio application. Do not expose unrestricted scans to anonymous or mutually untrusted users. Report a suspected issue privately to the repository owner through GitHub's private vulnerability reporting if available; otherwise request a private contact channel without publishing credentials, source archives or exploit-sensitive information in an issue.

Include affected commit, prerequisites, minimal non-sensitive reproduction, impact and suggested mitigation. Use invented credentials only. Do not test against systems you are not authorized to assess.

Before deploying, read `docs/SECURITY_DESIGN.md`, `docs/PROJECT_LIMITATIONS.md` and `security/advisory-exceptions.json`. Five known Semgrep transitive dependency advisories have exact, expiring exposure assessments; they are not patched or hidden. New advisories and expired exceptions fail CI.

Rotate any real exposed credential immediately; deleting its source line is not sufficient. This tool's secret detection is incomplete and a clean report does not prove a repository contains no secrets.
