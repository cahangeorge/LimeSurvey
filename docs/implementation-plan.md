# Implementation Plan: Replace Formbricks with LimeSurvey on Coolify

## Status
Approved by the user on 2026-09-17. Implementation proceeds checkpoint by checkpoint; destructive production operations remain separately gated.

## Overview
Build a pinned, ARM64-compatible LimeSurvey Community Edition deployment in a public `cahangeorge/LimeSurvey` deployment repository, add Resend delivery over HTTPS, deploy it beside Formbricks in Coolify, verify survey, email, and persistence behavior, then migrate the required survey flows. Formbricks remains available until cutover succeeds. Its data and resources are retained for a seven-day rollback window, after which permanent deletion requires a new explicit approval.

The implementation is intentionally split into bounded phases. The first implementation session targets only repository foundation and local verification. Production backup, deployment, cutover, and eventual deletion remain separate gates.

## Architecture decisions

1. **Parallel replacement, not in-place mutation.** LimeSurvey receives a separate Coolify application, database, volumes, and `survey.omnestack.com` hostname. Formbricks remains untouched until acceptance checks pass.
2. **Immutable upstream source.** The runtime is pinned to LimeSurvey tag `7.1.1+260914` and commit `6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9`; moving branches and `latest` image tags are forbidden.
3. **Deployment wrapper repository.** `cahangeorge/LimeSurvey` owns only deployment files, the Resend plugin, tests, and runbooks. It does not rewrite vendored upstream application code unless a verified blocker makes a minimal patch unavoidable.
4. **Three-service runtime.** Nginx serves/proxies the application, PHP 8.3 FPM runs LimeSurvey, and MariaDB 11.4 LTS stores application data. Persistent named volumes cover database data and LimeSurvey writable/custom paths.
5. **HTTPS email transport.** A focused LimeSurvey email plugin handles `beforeEmailDispatch`, sends through Resend's HTTPS API, uses finite timeouts, and never logs credentials or authorization headers.
6. **Database-aware backup.** Formbricks PostgreSQL is backed up with `pg_dump`; persistent file data is archived separately. Merely retaining a Docker volume is not accepted as a backup. A restore test and an off-server copy are mandatory before cutover.
7. **Manual semantic migration.** Formbricks exports are archival/reference material. Active surveys are recreated and verified in LimeSurvey because the products do not share a compatible survey schema.
8. **Compatibility cutover.** `survey.omnestack.com` is canonical. `feedback.omnestack.com` is redirected or retained as a compatibility route only after dependent integrations are updated and verified.

## Dependency graph

```text
Approved spec and plan
    |
    +-- Formbricks inventory --> secure backup --> restore proof --------+
    |                                                                   |
    +-- wrapper repository --> runtime image/Compose --> local checks    |
                                 |                                      |
                                 +--> Resend plugin/tests                |
                                            |                           |
                                            +--> Coolify parallel deploy+
                                                        |
                                                        +--> runtime acceptance
                                                                    |
                         exports + active survey selection ----------+
                                                                    |
                                        Daycare integration update --+
                                                                    |
                                                             cutover
                                                                    |
                                              seven-day rollback window
                                                                    |
                                            separate deletion approval
```

## Execution boundaries

- One writer operates in the repository/worktree at a time.
- Secrets are read only from local secret files or Coolify secret variables and are never echoed, committed, or placed in task output.
- Database dumps and survey response contents must not appear in Coolify task logs.
- Temporary Coolify tasks must auto-delete; the remaining task count must return to zero.
- DNS/domain, production deployment, credentials, database operations, stopping Formbricks, and deletion are executed only in their named gates.
- A failed checkpoint stops the sequence. Later phases do not compensate for an unverified earlier gate.

## Task list

### Phase 1: Safety inventory and backup design

#### Task 1: Record a privacy-safe Formbricks inventory

**Description:** Run a temporary, read-only command against the Formbricks PostgreSQL service to identify relevant tables and aggregate counts only. Record organizations, projects/environments, surveys, responses, and users without selecting response payloads, email addresses, names, tokens, or other personal data.

**Acceptance criteria:**
- [x] Aggregate counts and active survey identifiers/titles needed for migration planning are recorded in a local, non-secret inventory note.
- [x] No response body, credential, email address, or other personal record is printed or stored in logs.
- [x] The temporary Coolify task auto-deletes and the application has zero leftover scheduled tasks.

**Verification:**
- [x] Inspect redacted task output and exit status.
- [x] Query Coolify task inventory and confirm count `0`.

**Dependencies:** Approved implementation plan.

**Files likely touched:**
- `docs/formbricks-inventory.md`

**Estimated scope:** Small, 1 file plus read-only production inspection.

#### Task 2: Prove a secure Formbricks backup path

**Description:** Determine whether this Coolify Compose application exposes eligible database/storage backup controls. Prefer a database-aware `pg_dump` written outside application logs, archive relevant persistent files and non-secret configuration, copy the artifacts off the service host, and restore the dump into a disposable PostgreSQL instance for verification. If Coolify cannot securely export the artifacts, stop at the gate and request an approved S3-compatible destination or explicit server-access method.

**Acceptance criteria:**
- [x] PostgreSQL dump and required file archive exist, are non-empty, and have recorded SHA-256 checksums.
- [x] At least one encrypted or access-controlled copy exists outside the service host.
- [x] A disposable restore succeeds and its schema/table/aggregate counts match the inventory.
- [x] Backup location and seven-day retention are documented without secrets.

**Verification:**
- [x] Run `sha256sum` on each artifact at source and destination and compare results.
- [x] Restore into a disposable database and run schema/table/count-only checks.
- [x] Destroy only the disposable restore environment after evidence is recorded.

**Dependencies:** Task 1.

**Files likely touched:**
- `docs/runbook.md`
- `docs/formbricks-backup-evidence.md`

**Estimated scope:** Medium, 2 files plus operational artifacts stored outside Git.

### Checkpoint A: Formbricks safety gate

- [x] Inventory contains no sensitive response data.
- [x] Backup checksums match and restore proof passes.
- [x] An off-server copy is confirmed.
- [x] Formbricks remains running and unchanged.
- [x] If any item fails, production cutover remains blocked.

### Phase 2: Deployment repository foundation

#### Task 3: Create the public deployment repository baseline

**Description:** Create/push `cahangeorge/LimeSurvey` as a public deployment wrapper, carry forward the approved spec and plan, and document the immutable upstream version, supported architecture, boundaries, and exact local commands. Repository creation is allowed by the approved spec but occurs only after this plan is approved.

**Acceptance criteria:**
- [x] Public repository exists with default branch protection-compatible history and no secrets.
- [x] README identifies the pinned upstream tag and commit and explains that this is a deployment wrapper.
- [x] Repository-local `AGENTS.md` contains commands, architecture, and production safety rules.

**Verification:**
- [x] `git status --short --branch` is clean after the authorized commit/push.
- [x] `git log -1 --oneline` and GitHub default branch point to the same commit.
- [x] Secret scan finds no credential-like values.

**Dependencies:** Approved implementation plan.

**Files likely touched:**
- `README.md`
- `AGENTS.md`
- `docs/spec.md`
- `docs/implementation-plan.md`
- `.gitignore`

**Estimated scope:** Medium, 5 files.

#### Task 4: Build the pinned PHP-FPM application image

**Description:** Add an ARM64-compatible PHP 8.3 FPM image that fetches/verifies the immutable LimeSurvey source, installs required extensions, uses a non-root runtime where feasible, and exposes a deterministic health surface. Keep initialization logic separate and fail-fast.

**Acceptance criteria:**
- [x] Image build is pinned to the approved upstream release and verifies the expected source revision/checksum.
- [x] Required LimeSurvey PHP extensions are present on ARM64.
- [x] Entrypoint is idempotent, checks required variables, and does not print secrets.

**Verification:**
- [x] Native `aarch64` build in GitHub Actions release gate.
- [x] `docker run --rm <image> php -m` contains the required modules.
- [x] `sh -n docker/entrypoint.sh` and PHP syntax checks pass.

**Current evidence:** GitHub Actions run
[35342067109](https://github.com/cahangeorge/LimeSurvey/actions/runs/35342067109)
passed on commit `2fb6bdb` using a native `aarch64` runner. It completed the
pinned image build, required PHP module checks, 10 tests/56 assertions, the
Compose smoke test, and the secret scan.

**Dependencies:** Task 3.

**Files likely touched:**
- `docker/php/Dockerfile`
- `docker/entrypoint.sh`
- `docker/php/php.ini`
- `.dockerignore`

**Estimated scope:** Medium, 4 files.

#### Task 5: Define the persistent Compose runtime

**Description:** Add Nginx, PHP-FPM, and MariaDB 11.4 services with pinned images, health checks, private service networking, explicit persistent named volumes, secret-safe environment variables, and dependency conditions. Do not publish the database port.

**Acceptance criteria:**
- [x] `compose.yaml` renders without warnings and contains no literal credentials.
- [x] Database is private, health-gated, and persists across container replacement.
- [x] Nginx serves public assets and routes PHP requests without exposing internal files.

**Verification:**
- [x] `docker compose config --quiet`.
- [x] `docker compose up -d && docker compose ps` shows all services healthy.
- [x] A local HTTP request reaches the LimeSurvey installer/application entry point.

**Dependencies:** Task 4.

**Files likely touched:**
- `compose.yaml`
- `docker/nginx/default.conf`
- `.env.example`
- `tests/smoke.sh`

**Estimated scope:** Medium, 4 files.

### Checkpoint B: Local runtime foundation

- [x] ARM64 build passes.
- [x] Compose renders and all services become healthy.
- [x] Required PHP modules are present.
- [x] Restarting containers preserves a locally initialized database marker.
- [x] `git diff --check` and secret scan pass.

### Phase 3: Resend email integration

#### Task 6: Specify the plugin contract with no-network tests

**Description:** Add focused PHPUnit tests around the LimeSurvey email plugin adapter before implementation. Cover text/HTML payload mapping, sender/recipient/reply-to handling, missing API key, finite timeouts, non-2xx responses, transport exceptions, success signalling, and secret non-disclosure. Explicitly decide attachment behavior: either implement supported attachments or fail closed with a clear administrator error.

**Acceptance criteria:**
- [x] Tests fail for the expected missing implementation rather than test setup errors.
- [x] Tests never perform a real network request or contain a real API key.
- [x] Error assertions prove that authorization values are absent from exceptions/log messages.

**Verification:**
- [x] `composer install --no-interaction --no-progress`.
- [x] `vendor/bin/phpunit tests/ResendEmailPluginTest.php` produces the expected red result before Task 7.

**Current evidence:** The no-network suite first produced nine expected failures for the missing
client/plugin implementation, with no bootstrap or fixture errors.

**Dependencies:** Task 5.

**Files likely touched:**
- `composer.json`
- `phpunit.xml`
- `tests/ResendEmailPluginTest.php`
- `tests/Fakes/FakeHttpClient.php`

**Estimated scope:** Medium, 4 files.

#### Task 7: Implement and package the Resend email plugin

**Description:** Implement the smallest plugin that satisfies Task 6, subscribes to LimeSurvey's supported email dispatch event, sends through `https://api.resend.com/emails`, and reports delivery acceptance/failure back to LimeSurvey without leaking credentials.

**Acceptance criteria:**
- [x] All Task 6 tests pass, including timeout/non-2xx and secret non-disclosure cases.
- [x] Plugin declares compatible LimeSurvey metadata and reads configuration from runtime environment.
- [x] Compose installs/enables the plugin without modifying upstream vendor source.

**Verification:**
- [x] `vendor/bin/phpunit tests/ResendEmailPluginTest.php`.
- [x] `find plugins tests -name '*.php' -print0 | xargs -0 -n1 php -l`.
- [x] Local LimeSurvey plugin list shows `ResendEmail` available.

**Current evidence:** GitHub Actions run 35342067109 passed the no-network suite
with 10 tests and 56 assertions. A disposable initialized LimeSurvey stack discovered
`ResendEmail` through the upstream plugin manager, installed it, set it active, and loaded it
successfully. Production activation remains an explicit post-install runbook step.

**Dependencies:** Task 6.

**Files likely touched:**
- `plugins/ResendEmail/ResendEmail.php`
- `plugins/ResendEmail/config.xml`
- `plugins/ResendEmail/ResendClient.php`
- `compose.yaml`

**Estimated scope:** Medium, 4 files.

#### Task 8: Document deploy, restore, upgrade, and rollback procedures

**Description:** Complete the operator runbook with secret setup, first initialization, backup/restore, Resend validation, pinned upgrade procedure, rollback decision points, and commands that avoid logging sensitive data.

**Acceptance criteria:**
- [x] A new operator can deploy and validate without inspecting chat history.
- [x] Restore and rollback procedures name prerequisites and irreversible boundaries.
- [x] No secret value, private response data, or unsafe dump-through-logs command is present.

**Verification:**
- [x] Execute all safe local commands from the runbook against the local stack.
- [x] Review every production command for output and rollback behavior.

**Dependencies:** Tasks 2 and 7.

**Files likely touched:**
- `docs/runbook.md`
- `README.md`

**Estimated scope:** Small, 2 files.

### Checkpoint C: Repository release candidate

**Status: HOLD.** Independent review found direct Nginx exposure of runtime and
respondent-upload files plus a secret-scan exclusion. Local remediation is pending
a successful CI re-run and independent re-review. No immutable wrapper release tag
exists yet.

- [ ] Compose, PHP syntax, plugin unit tests, build, and local smoke checks pass after remediation.
- [x] No secrets are tracked or exposed in logs.
- [x] Runbook is executable and rollback-safe.
- [ ] Independent code review finds no unresolved high/critical issue.
- [ ] A real immutable wrapper release tag exists.
- [ ] Only then proceed to Coolify.

### Phase 4: Parallel Coolify deployment and acceptance

#### Task 9: Create the separate LimeSurvey Coolify application

**Description:** Create a new Compose application in `tools/production` from the pinned repository revision, generate/store database and administrator secrets only in Coolify, reuse the existing Resend API key as a secret variable, assign `survey.omnestack.com`, and deploy without modifying Formbricks or `feedback.omnestack.com`.

**Acceptance criteria:**
- [ ] New application uses the pinned commit and its own database/volumes.
- [ ] Required variables are configured as secrets and are absent from command output.
- [ ] Deployment finishes successfully and HTTPS serves the new LimeSurvey endpoint.

**Verification:**
- [ ] Inspect Coolify deployment status and service health.
- [ ] Check `https://survey.omnestack.com` certificate, HTTP status, and visible page.
- [ ] Confirm `https://feedback.omnestack.com` still serves Formbricks unchanged.

**Dependencies:** Checkpoint C.

**Files likely touched:**
- `docs/deployment-evidence.md`

**Estimated scope:** Small, 1 evidence file plus approved production configuration.

#### Task 10: Verify admin, public survey, and persistence flows

**Description:** Complete initialization through a secret-safe admin flow, create a disposable survey, submit one non-personal test response in a browser, restart/redeploy the application, and prove the survey and response remain available.

**Acceptance criteria:**
- [ ] Authenticated administrator login works over HTTPS.
- [ ] A disposable public survey accepts a clearly synthetic response.
- [ ] The survey and response persist across restart/redeploy.

**Verification:**
- [ ] Record browser-visible evidence for login and survey completion without credentials.
- [ ] Compare pre/post-restart survey and response counts.
- [ ] Confirm all services return healthy after restart.

**Dependencies:** Task 9.

**Files likely touched:**
- `docs/deployment-evidence.md`

**Estimated scope:** Small, 1 file plus browser/production verification.

#### Task 11: Prove Resend delivery from LimeSurvey

**Description:** Send a test message through the LimeSurvey plugin to Resend's safe test recipient, capture only the non-secret message identifier, and query Resend for the final delivered event.

**Acceptance criteria:**
- [ ] LimeSurvey reports successful dispatch through the plugin.
- [ ] Resend reports final state `delivered` for the test message.
- [ ] Application/deployment logs contain no API key or authorization header.

**Verification:**
- [ ] Check Resend message status using the local secret file without echoing it.
- [ ] Search bounded application logs for accidental credential exposure using redacted output.
- [ ] Confirm temporary tasks count returns to zero.

**Dependencies:** Task 10.

**Files likely touched:**
- `docs/deployment-evidence.md`

**Estimated scope:** Small, 1 file plus production verification.

### Checkpoint D: LimeSurvey production acceptance

- [ ] Admin, public survey, persistence, HTTPS, and delivered-email checks pass.
- [ ] Formbricks remains online and its data is unchanged.
- [ ] Backup safety gate remains valid.
- [ ] No temporary Coolify tasks remain.

### Phase 5: Content migration and dependent integration

#### Task 12: Export Formbricks data and select active surveys

**Description:** Export all surveys/responses needed for archival through supported Formbricks export/API paths, checksum the artifacts, and use the privacy-safe inventory to identify which active surveys must be recreated. Do not put exports in Git.

**Acceptance criteria:**
- [ ] Required exports exist in access-controlled off-server storage with checksums.
- [ ] Active survey list and target owners are approved before recreation.
- [ ] Archive and database backup retention dates are recorded.

**Verification:**
- [ ] Open representative exports locally and validate format/counts without copying personal data into evidence.
- [ ] Compare aggregate counts with Task 1.

**Dependencies:** Checkpoints A and D.

**Files likely touched:**
- `docs/formbricks-inventory.md`
- `docs/migration-map.md`

**Estimated scope:** Small, 2 files plus protected export artifacts.

#### Task 13: Recreate and validate required surveys in LimeSurvey

**Description:** Recreate only the approved active surveys, including question logic, consent wording, notifications, theme settings, and ownership. Map each source survey to its LimeSurvey identifier and validate equivalent behavior with synthetic data.

**Acceptance criteria:**
- [ ] Every approved active source survey has a documented LimeSurvey target.
- [ ] Questions, validation, branching, consent text, notifications, and completion behavior match the approved migration map.
- [ ] Synthetic submissions and notification delivery pass for every migrated survey.

**Verification:**
- [ ] Run a browser checklist for each survey and record pass/fail evidence.
- [ ] Compare mapped fields and aggregate synthetic response counts.

**Dependencies:** Task 12.

**Files likely touched:**
- `docs/migration-map.md`
- `docs/migration-evidence.md`

**Estimated scope:** Small, 2 files plus LimeSurvey content configuration.

#### Task 14: Replace the Georgiana Daycare Formbricks integration

**Description:** Inspect the Daycare repository's current integration and applicable `AGENTS.md`, then replace only the Formbricks-specific survey embed/link/configuration with the approved LimeSurvey endpoint. Keep consent, accessibility, privacy, and analytics behavior intact.

**Acceptance criteria:**
- [ ] No active Daycare UI path loads or links Formbricks.
- [ ] The LimeSurvey flow works in a browser across supported viewport sizes.
- [ ] Consent/privacy behavior and unrelated analytics remain unchanged.

**Verification:**
- [ ] Run the Daycare repository's targeted tests/build from its `AGENTS.md`.
- [ ] Use browser validation for the full site-to-survey-to-completion path.
- [ ] Search the built output for obsolete Formbricks host references.

**Dependencies:** Task 13.

**Files likely touched:**
- Exact files are discovered in the Daycare repository before implementation; scope is capped at 5 files for this task.

**Estimated scope:** Medium, no more than 5 files in a separate repository.

### Checkpoint E: Migration readiness

- [ ] Required surveys pass behavior checks.
- [ ] Daycare uses LimeSurvey successfully.
- [ ] Protected exports and restorable backup remain available.
- [ ] A rollback to the unchanged Formbricks service is still possible.

### Phase 6: Domain cutover and rollback window

#### Task 15: Cut over compatibility routing

**Description:** Make `survey.omnestack.com` canonical, update remaining approved platform references, and configure `feedback.omnestack.com` as a tested redirect or compatibility route. Stop—but do not delete—Formbricks only after public/browser checks pass and rollback instructions are current.

**Acceptance criteria:**
- [ ] Canonical LimeSurvey URL works publicly over HTTPS.
- [ ] Old hostname behaves according to the approved redirect/compatibility decision.
- [ ] No known active platform points directly to the retired Formbricks runtime.
- [ ] Stopped Formbricks containers and volumes remain intact for rollback.

**Verification:**
- [ ] Check HTTP status/redirect chain and TLS for both hostnames.
- [ ] Run browser smoke tests from each dependent platform.
- [ ] Perform a rollback-readiness review before stopping Formbricks.

**Dependencies:** Checkpoint E.

**Files likely touched:**
- `docs/cutover-evidence.md`
- `docs/runbook.md`

**Estimated scope:** Small, 2 files plus approved routing/runtime configuration.

#### Task 16: Observe the seven-day rollback window

**Description:** Keep Formbricks resources and verified backups intact for seven full days after cutover. Monitor LimeSurvey health, survey completion, email failures, storage growth, and dependent-site behavior. Roll back if acceptance criteria materially regress.

**Acceptance criteria:**
- [ ] Seven full days pass with no unresolved migration-blocking incident.
- [ ] LimeSurvey and Resend evidence remains healthy.
- [ ] Backup retention has not expired before the deletion decision.

**Verification:**
- [ ] Complete the daily checklist in the cutover evidence document.
- [ ] Re-run public endpoint, survey submission, persistence, and email checks at the end of the window.

**Dependencies:** Task 15 and elapsed external time.

**Files likely touched:**
- `docs/cutover-evidence.md`

**Estimated scope:** Small, 1 file over an external time gate.

### Checkpoint F: Separate deletion decision

- [ ] Present the seven-day evidence, backup expiry date, and current Formbricks resource inventory to the user.
- [ ] Request explicit approval specifically for permanent deletion.
- [ ] Without that new approval, leave Formbricks stopped and retained; do not delete containers, volumes, backups, DNS, or secrets.

#### Task 17: Permanently remove Formbricks after explicit approval

**Description:** Only after Checkpoint F approval, remove the Formbricks Coolify application and obsolete routing/secrets, verify no orphaned resources remain, and retain the protected archive according to the approved retention decision.

**Acceptance criteria:**
- [ ] Explicit final deletion approval is recorded immediately before execution.
- [ ] Formbricks application, obsolete routes, and unneeded runtime secrets are removed without touching LimeSurvey.
- [ ] Required export/backup archive is retained or destroyed only according to the separately approved retention decision.

**Verification:**
- [ ] Coolify no longer lists Formbricks resources or temporary tasks.
- [ ] Public hosts and dependent platforms still pass their smoke checks.
- [ ] Final resource inventory finds no unintended orphaned volumes/routes.

**Dependencies:** Checkpoint F with explicit approval.

**Files likely touched:**
- `docs/cutover-evidence.md`
- `docs/runbook.md`

**Estimated scope:** Small, 2 files plus explicitly approved destructive production operations.

## Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Coolify does not expose Compose application backups through API/UI | High | Stop at Task 2; use an approved S3-compatible target or explicit server-access method. Never stream dumps through logs. |
| Backup exists but cannot restore | High | Make disposable restore and count comparison a hard pre-cutover gate. |
| ARM64 image/extension incompatibility | High | Build for `linux/arm64` locally/CI before Coolify; pin source and base images. |
| LimeSurvey plugin hook semantics differ from assumptions | High | Test against the pinned source, use supported email events, and fail before deployment if the plugin cannot signal errors correctly. |
| Resend accepts but does not deliver | Medium | Verify the final Resend event, not only HTTP 200/202 from the send request. |
| Attachments are silently lost | High | Add explicit attachment tests; support them or fail closed with an administrator-visible error. |
| Manual survey recreation changes logic/consent | High | Use a per-survey migration map and browser checklist with synthetic submissions. |
| Existing platforms still reference Formbricks | High | Search each approved repository and public output before stopping Formbricks; preserve old hostname compatibility. |
| Secrets leak into Git or task output | High | Secret variables only, bounded redacted logs, automated secret scan, and no dumps in logs. |
| Destructive cleanup occurs too early | High | Seven-day hold plus a separate final approval gate; stopped resources remain intact meanwhile. |
| Stalwart work distracts from migration | Low | Keep Stalwart explicitly queued until LimeSurvey reaches the production acceptance checkpoint. |

## Parallelization and sequencing

- Production inventory/backup and repository foundation are logically independent, but this project uses one active writer/operator and explicit checkpoints rather than concurrent production work.
- Tasks 4 and 5 are sequential because Compose depends on the runtime contract.
- Tasks 6 and 7 are strict red/green TDD steps.
- Coolify deployment starts only after the repository release checkpoint.
- Content migration starts only after both backup and LimeSurvey production acceptance pass.
- Cutover, rollback-window observation, and deletion are strictly sequential and cannot be compressed into one session.

## Plan verification checklist

- [x] Every task has explicit acceptance criteria.
- [x] Every task has verification steps.
- [x] Dependencies are named and ordered.
- [x] No repository task intentionally touches more than five files.
- [x] Checkpoints separate safety, build, deployment, migration, and deletion gates.
- [x] High-risk backup, ARM64, email, privacy, and destructive-operation issues fail early.
- [x] User has reviewed and approved this implementation plan.

## Open decisions at execution time

1. Select the secure off-server backup destination only if existing Coolify backup controls cannot safely export the Compose data.
2. After Task 1, approve the exact list of active Formbricks surveys that must be recreated.
3. At Checkpoint F, decide separately whether to permanently delete Formbricks and how long protected archives must remain.
