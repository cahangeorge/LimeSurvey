# Spec: Replace Formbricks with LimeSurvey on Coolify

## Status
Approved by the user on 2026-09-17. No Formbricks data, container, volume, domain, or DNS record may be deleted until the pre-cutover backup is verified. Permanent deletion still requires a separate, explicit final approval after the rollback window.

## Objective
Replace the shared Formbricks survey service with a self-hosted LimeSurvey Community Edition service in Coolify `tools/production`, suitable for Georgiana Daycare and future platforms.

The replacement must:
- keep the current Formbricks service online during build and validation;
- preserve existing Formbricks data in an export plus restorable database/volume backup before cutover;
- provide a reusable LimeSurvey admin/editor and public survey runtime;
- send transactional/invitation email through Resend over HTTPS because outbound SMTP ports 465 and 587 are blocked on the server;
- cut over public routing only after a browser-visible smoke test and a persistence/restart test;
- retain a rollback path before permanent Formbricks deletion.

## Assumptions for approval
1. Deploy LimeSurvey as a separate Compose application alongside Formbricks first, not as an in-place replacement.
2. Pin the official LimeSurvey Git tag `7.1.1+260914` (commit `6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9`) rather than following `master`.
3. Maintain a small deployment fork/wrapper repository named `cahangeorge/LimeSurvey` containing the Compose/Docker deployment and a Resend HTTPS email plugin; upstream LimeSurvey has no production Dockerfile or Compose definition.
4. Use `survey.omnestack.com` as the canonical LimeSurvey hostname, then redirect or preserve `feedback.omnestack.com` for compatibility after cutover.
5. Archive Formbricks surveys/responses and keep a restorable backup for 7 days after cutover. Do not claim automatic survey migration: Formbricks and LimeSurvey use different survey schemas, so survey recreation/import mapping is a separate verified step.
6. LimeSurvey takes priority now; Stalwart remains queued for a later phase and is not a dependency of this deployment.

## Tech stack
- LimeSurvey Community Edition `7.1.1+260914`, pinned by immutable Git commit.
- PHP 8.3 FPM with required/recommended extensions.
- Nginx reverse proxy.
- MariaDB 11.4 LTS, pinned to an explicit image tag.
- Docker Compose deployed by Coolify on the existing ARM64 server.
- Persistent named volumes for database, LimeSurvey upload files, plugins, themes/customizations, and writable runtime configuration.
- Custom LimeSurvey email plugin using the Resend `POST /emails` HTTPS API and `RESEND_API_KEY` from runtime environment; no secret stored in Git or logged.

## Commands
Preflight and configuration:
```bash
docker compose config --quiet
docker compose build --pull
```

Static verification:
```bash
find docker plugins -name '*.php' -print0 | xargs -0 -n1 php -l
git diff --check
```

Targeted plugin tests:
```bash
composer install --no-interaction --no-progress
vendor/bin/phpunit tests/ResendEmailPluginTest.php
```

Runtime verification:
```bash
docker compose up -d
docker compose ps
docker compose exec app php -m
```

Production verification is performed through Coolify deployment status, HTTPS endpoint checks, an authenticated admin smoke test, one disposable survey/response, a restart persistence check, and a Resend test delivery.

## Project structure
```text
docs/
  spec.md                  requirements and approval source of truth
  implementation-plan.md   ordered migration and rollback tasks
  runbook.md               deploy, backup, restore, upgrade, rollback
compose.yaml                pinned production services and volumes
docker/
  php/Dockerfile            PHP runtime and required extensions
  nginx/default.conf        proxy/static-file configuration
  entrypoint.sh             idempotent initialization and permissions
plugins/
  ResendEmail/              LimeSurvey email plugin for HTTPS delivery
tests/
  ResendEmailPluginTest.php focused no-network plugin tests
```

## Code style
Deployment scripts must be fail-fast and secret-safe:
```sh
#!/bin/sh
set -eu

: "${DB_PASSWORD:?DB_PASSWORD is required}"
exec php-fpm
```

PHP plugin code follows PSR-12, validates external API responses, uses finite connect/total timeouts, and never logs authorization headers or API keys.

## Testing strategy
1. **Static:** Compose render, shell syntax, PHP syntax, no committed secrets.
2. **Unit:** Resend payload, success, timeout/non-2xx failure, missing key, and secret non-disclosure.
3. **Build:** Native ARM64 production image build using the pinned LimeSurvey tag.
4. **Integration:** installer/database initialization, admin login, public survey submission, uploads, and email delivery.
5. **Persistence:** restart/redeploy and prove the created survey/response remains.
6. **Migration:** inventory Formbricks survey/response counts; export data; verify backup can be listed/restored before cutover.
7. **Cutover:** HTTPS/DNS/browser checks on the new domain, then redirect/compatibility check for the old domain.

## Boundaries
### Always
- Inventory and back up Formbricks before any stop/delete operation.
- Keep secrets in Coolify secret variables only.
- Pin images, upstream tag/commit, and database major version.
- Keep Formbricks available until LimeSurvey acceptance criteria pass.
- Verify rollback artifacts and remove temporary diagnostic tasks.

### Ask first
- Creating/pushing the GitHub fork or wrapper repository.
- Creating/changing public DNS and Coolify domains.
- Choosing or generating the initial LimeSurvey administrator credentials.
- Manual migration/recreation of specific surveys.
- Permanently deleting Formbricks resources or backups.

### Never
- Commit API keys, passwords, cookies, database URLs, or generated admin credentials.
- Delete Formbricks before backup verification and explicit final deletion approval.
- Deploy from moving `master`, `latest`, or an unpinned database major tag.
- Run LimeSurvey's destructive upstream test suite against production.

## Success criteria
- LimeSurvey runs on the ARM64 Coolify server from the pinned tag/commit.
- Admin login and public survey completion work over HTTPS.
- A test survey and response persist through application restart/redeploy.
- Resend test email reaches `delivered` through HTTPS port 443 without secret leakage.
- Existing Formbricks data is inventoried and archived; required surveys are recreated/migrated and verified.
- Cutover has a documented rollback procedure.
- Formbricks is stopped only after successful cutover, and permanently removed only after explicit final approval.
- No temporary tasks remain and all public endpoints have final evidence.

## Open questions
- Which existing Formbricks surveys are still active and must be recreated in LimeSurvey? The inventory phase will produce the candidate list without printing response contents.
- Which secure off-server backup destination should be used if the existing Coolify installation cannot export Compose application backups through its API/UI? This is a hard gate before cutover, not before repository work.
