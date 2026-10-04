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

## Release artifact route

`Release artifact` is a separate manual workflow, restricted to this repository's `main` ref. It verifies protected current main and the newest completed successful push run of `release-gate.yml` for the exact source SHA, both before building and immediately before publication. A PR event, arbitrary branch, stale source or unsuccessful CI cannot publish through this route. A manual dispatch is an operator action, not production approval.

The native ARM64 job builds once with Buildx and tests the resulting local image using disposable Compose smoke. The Dockerfile separates checksum-verified upstream source preparation from runtime construction; upstream version/base digest and PHP modules remain pinned. The OCI revision is the wrapper commit; `io.omnestack.limesurvey.upstream-revision` retains the upstream commit. Source built during PR validation is distinct from a release candidate. Promotion must reuse the resulting registry digest.

Runtime construction uses the digest-pinned PHP8.3.35/Alpine3.24 base, applies available same-branch APK updates and builds extensions in a removable `.build-deps` package group. Runtime ELF dependencies are retained from PHP CLI/FPM and extensions before compilation tools and headers are removed. Full ICU data and GNU iconv preserve the required Romanian text/number/date behavior. Disposable smoke checks each forbidden APK development package individually, plus compilation commands and IMAP SSL support. APK repository contents can change between builds despite the pinned base; installed inventory and final image digest identify the actual tested packages. Promotion reuses that image. Cleanup/package updates alone do not establish CVE eligibility.

Only this trusted release job receives `packages: write`, plus `contents: read` and `actions: read` for its preflight. Registry login uses its ephemeral `GITHUB_TOKEN` in a temporary Docker configuration created after build/smoke; logout and deletion run on exit. No production/staging secret, persistent PAT, OIDC, credential creation or deployment operation is included. GHCR destination: `ghcr.io/cahangeorge/limesurvey`; tag `sha-<wrapper SHA>-run-<run ID>-<attempt>`. No `latest` tag. New GHCR packages default to private; package visibility and deployment read access are separate operator gates.

Publishing stores a candidate, including one that later fails scanning. Publication alone never grants eligibility. The workflow obtains its final manifest digest, inspects raw registry bytes, pulls by that digest, and requires the config ID to equal the tested local image. The validator checks the manifest hash/config, `linux/arm64`, wrapper/upstream labels and identical scan/SBOM identities. Multi-platform indexes are rejected in this single-platform pilot.

### Inventory and vulnerability acceptance

Trivy 0.75.0 ARM64 archive SHA-256: `a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3`. The final registry digest is scanned using only the remote source, explicit vulnerability scanner, all packages, no implicit configuration/ignorefile, a fresh temporary DB/cache and finite timeout. JSON retains findings at every severity. The same report is converted to CycloneDX 1.7, with the vulnerability scanner explicitly enabled during conversion.

Pinned upstream runtime uses Composer `installed.php` metadata; the vendor analyzer reads `installed.json`. Source preparation adds scanner JSON for concrete packages from every installed PHP inventory. It excludes the application root and declared virtual provided/replaced entries, validates physical package directories, and does not install/resolve/change library versions. Independently, the CI helper extracts package names/versions again from the built image's `installed.php`, plus the installed OS package inventory selected from the image's own OS identity. The validator requires exact OS inventory and exact root/TwoFactor (and any other discovered Composer) inventory targets and versions in the final scan. Missing root libraries cannot be concealed by a nonempty plugin or OS report.

The inventory helper also supports Alpine 3.24 explicitly. It reads `ID` and `VERSION_ID` from `/etc/os-release` inside the tested config image, as data rather than shell code. Debian 12 uses `dpkg-query`; Alpine 3.24 reads all `P:`/`V:` records from `/lib/apk/db/installed`, including virtual dependency packages. Missing, malformed or duplicate APK identities and failed reads stop extraction; there is no package-manager or host-OS fallback. Both identity fields are required in release evidence. The final scan must match the independently extracted OS and have exactly one OS result of that family. Alpine patch versions match exactly; Debian's major version remains 12 because its os-release and scanner can report different point-release detail. APK versions include their exact `-rN` revision without Debian epoch/release reconstruction. Existing coverage, DB, severity, source, platform and digest requirements still apply. Other releases, including Alpine edge/3.23 and Debian 13, are outside this explicit allowlist. See [Alpine APK database format](https://wiki.alpinelinux.org/wiki/Apk_spec).

The selected MVP runtime is Alpine3.24/PHP8.3 with Resend, per [ADR0001](adr-0001-php-alpine-base.md). IMAP SSL remains available; Kerberos/GSSAPI is not a requirement of this MVP and is not claimed to be supported. A future Kerberos integration needs an explicit compatible base/build decision and an authentication test. Native ARM64 execution and final registry-digest validation are required; local AMD64 evidence does not satisfy them.

Existing DB freshness and severity policy applies to every image result, including HIGH/CRITICAL without fixes and unknown severity. Unsupported/EOL OS, malformed evidence, missing packages/targets, tool errors or SBOM package omission produce HOLD and a failed run. There is no waiver/`ignore-unfixed` path. Raw vulnerability evidence may still be retained for triage when the gate fails; `release.json` is created only after successful validation.

### Manifest and later gates

The manifest binds source/config commit, image/digest/config ID/platform, upstream version/commit, verified source CI run/attempt, release run/attempt and SHA-256 hashes of the raw registry manifest, Docker inspect, installed inventory, scan, DB metadata and SBOM. Evidence is uploaded with a pinned `actions/upload-artifact` v4 commit for 30 days; longer operational retention must be established before relying on these reports for rollback/audit.

`ARTIFACT_VERIFIED` means the image passed this inventory/CVE contract. Staging stays `PENDING`, production `HOLD`, configuration schema/migrations `REVIEW_REQUIRED` and previous promoted digest unset until those separate gates supply verified evidence. The manifest cannot authorize deployment. Coolify's existing source branch/autodeploy configuration is untouched.

Coverage limits: OS/Composer inventory does not establish CVE coverage of the PHP interpreter compiled from source, LimeSurvey application code, or bundled non-Composer assets. Those require upstream release/security review in the upgrade/release gates; these gaps are recorded in the manifest. The PHP-FPM image is only the application artifact; pinned Nginx and MariaDB deployment services require their own scan/upgrade review before a full staging/production release.

References: [GitHub Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry), [pinned Trivy vendor analyzer](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/fanal/analyzer/language/php/composer/vendor.go), [Trivy report conversion](https://trivy.dev/docs/latest/references/configuration/cli/trivy_convert/), [Docker Buildx inspection](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/).
