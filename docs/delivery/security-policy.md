# CI security policy

The PR workflow checks source, workflow definitions and the wrapper's locked development/test dependencies before its native ARM64 build. These checks are release prerequisites; they do not establish staging or production readiness.

## Tools and privileges

The installer pins Linux AMD64 publisher archives by version and SHA-256:

| Tool | Version | Purpose |
|---|---|---|
| Gitleaks | 8.30.1 | Complete tested Git ancestry and current files |
| zizmor | 1.30.1 | Offline workflow security analysis |
| actionlint | 1.7.12 | Workflow syntax and expression validation |
| Trivy | 0.75.0 | Composer lockfile vulnerability inventory |

Download, checksum, extraction or scanner failures stop the job. Updates require a reviewed change to the version and checksum together.
The workflow uses `contents: read`, credential-free Git checkout, finite timeouts and GitHub-hosted runners. It grants no registry write, OIDC or deployment permission. Superseded disposable CI runs can be cancelled; this policy does not authorize cancelling deployments or migrations.

## Secrets

Gitleaks extends its upstream rules with a project rule for assignments to `DB_PASSWORD`, `DB_ROOT_PASSWORD`, `POSTGRES_PASSWORD` and `RESEND_API_KEY`, without an entropy threshold.
Only the three exact existing placeholder lines in the root `.env.example` are allowed. Copies elsewhere, altered values, added comments and new credential assignments are rejected.
Both the tested history and working files are scanned with the explicit configuration and inline `gitleaks:allow` comments disabled. Logs are redacted; reports containing detected values must never be published.
Historical findings require removal/rotation through a separately authorized process. There is no blanket baseline or global suppression in this candidate.
One rule-specific false-positive exception identifies the exact old credential-check expression by immutable commit, workflow path and complete source line. It does not exempt other lines, other commits or other rules.

## Dependencies

Trivy includes development dependencies and emits all inventoried packages. The validator requires exactly the Composer target, expected report schema/type, and an exact set of package names and versions matching both `packages` and `packages-dev` in the lockfile.
An empty result, missing package, substituted version, unknown target, malformed/missing report or scanner error blocks the gate. A successful scanner exit code alone is insufficient.

The vulnerability DB must have schema version 2, an update timestamp no older than 48 hours and a download timestamp no older than 24 hours. Missing/invalid timestamps or timestamps more than five minutes ahead fail closed. Each hosted job uses a fresh temporary cache and must obtain the DB successfully.

| Finding | Gate behavior |
|---|---|
| Secret or workflow finding at the scanner's failure threshold | Block |
| CRITICAL/HIGH, with or without an available fix | Block pending remediation or explicit risk decision |
| LOW/MEDIUM dependency finding | Does not block this initial gate; retain inventory for triage |
| Unknown/unclassified severity, stale DB or incomplete coverage | HOLD; the job fails |

This candidate implements no vulnerability waiver mechanism and no `ignore-unfixed` fallback. A future exception must name the finding, justification, owner and expiry, and be reviewed before its exact allowlist mechanism is introduced.

The wrapper lockfile contains development/test packages. Upstream LimeSurvey PHP dependencies and OS packages are outside this scan; the release phase must scan the final image by digest and prove its inventory before promotion. A clean wrapper lockfile is not a clean runtime image verdict.

## Required check

Configure `MVP required gate`, emitted by GitHub Actions, as the required `main` check after a hosted canary proves its behavior. Its three dependencies must all report `success`; failure, skipped or cancelled jobs cannot produce an accepted result.
Keep PR integration mandatory and direct pushes, force pushes and deletion blocked. Repository settings are external state and must be verified by read-back; committing this workflow does not enforce these rules.
Negative source/security canaries and the hosted native ARM64 build remain required before Checkpoint A closes.

References: [Gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration), [zizmor usage](https://docs.zizmor.sh/usage/), [Trivy PHP coverage](https://trivy.dev/docs/latest/coverage/language/php/), [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
