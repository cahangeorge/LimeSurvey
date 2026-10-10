# LimeSurvey Coolify Runbook

This runbook operates the pinned deployment wrapper in this repository. It deliberately keeps Formbricks independent and online until the migration and cutover checkpoints in the implementation plan pass.

## Safety rules

- Never paste secrets into Git, chat, issue trackers, command arguments, or Coolify deployment logs.
- Store credentials only as Coolify secret variables. Use distinct, randomly generated database and administrator passwords.
- Do not send a database dump or a volume archive to standard output. Treat `application/config`, uploads, exports, and backups as sensitive.
- Do not reuse the Formbricks database, volumes, application, or hostname.
- Do not stop or delete Formbricks during this deployment. Permanent deletion has a separate approval and a seven-day rollback gate.
- Stop at the first failed checkpoint. A green Coolify deployment status alone is not acceptance evidence.

## 1. Local release checks

Run these commands from the repository root:

```bash
composer install --no-interaction --no-progress
vendor/bin/phpunit tests/ResendEmailPluginTest.php
find docker plugins tests -name '*.php' -print0 | xargs -0 -n1 php -l
sh -n docker/entrypoint.sh
sh -n tests/smoke.sh
docker compose --env-file .env.example config --quiet
COMPOSE_PROJECT_NAME=limesurvey-release-smoke ./tests/smoke.sh
git diff --check
```

The unit test must use the fake HTTP client and must not contact Resend. The smoke test uses example-only local values, retains named volumes for inspection, and removes its containers and networks unless `KEEP_SMOKE_STACK=1` is set.

Before production deployment, build on an ARM64 runner and inspect the required PHP modules:

```bash
docker buildx build --load --platform linux/arm64 -f docker/php/Dockerfile -t limesurvey-app:release .
docker run --rm --platform linux/arm64 --entrypoint php limesurvey-app:release -m
```

The module list must contain `bcmath`, `curl`, `exif`, `gd`, `gettext`, `imap`, `intl`, `ldap`, `mbstring`, `mysqli`, `pdo_mysql`, `soap`, `zip`, and `Zend OPcache`.

## 2. Create the parallel Coolify application

Create a new Docker Compose application from this repository. Do not alter the existing Formbricks resource.

Use:

- repository: `cahangeorge/LimeSurvey`
- revision: exact integrated source commit from the accepted release manifest
- images: accepted PHP, Nginx and MariaDB `repository@sha256:...` identities
- Compose file: reviewed digest-only operational adapter recorded in the staging
  receipt; its path is pending, so deployment remains on HOLD
- public service: `nginx`
- container port: `80`
- production hostname: `survey.omnestack.com`

Create these Coolify variables and mark every credential as secret:

| Variable | Required | Purpose |
| --- | --- | --- |
| `DB_NAME` | yes | Dedicated LimeSurvey database name |
| `DB_USER` | yes | Dedicated application database user |
| `DB_PASSWORD` | yes, secret | Application database password |
| `DB_ROOT_PASSWORD` | yes, secret | MariaDB administrative password |
| `RESEND_API_KEY` | yes, secret | Resend HTTPS API credential |
| `RESEND_FROM_EMAIL` | yes | Sender on a Resend-verified domain |
| `RESEND_FROM_NAME` | optional | Human-readable sender name |

Use the reviewed digest-only deployment adapter with all three accepted image
references and no build definitions. Root `compose.yaml` remains a development
build recipe; its DB/Nginx defaults are not a production release bundle. Keep
deployment on HOLD until the adapter and selected triple pass staging. The
database has no published host port by design.

Deploy beside Formbricks using the already-tested native ARM64 image digests.
Do not rebuild during promotion. Confirm all three services become healthy and
complete application smoke before adding migration traffic.

Before deployment, verify image signatures/provenance and that source, digests,
configuration and staging receipts match the accepted release manifest. Do not configure Coolify to follow mutable `main` or enable automatic deployment
from later pushes.

## 3. Initialize LimeSurvey

1. Open the HTTPS production hostname in a browser and complete the LimeSurvey installer.
2. For the database screen, use host `db`, port `3306`, and the values already stored in the matching Coolify variables. Do not copy them into notes or screenshots.
3. Create a unique administrator credential in the password manager.
4. Sign in and confirm the administration page loads over HTTPS.
5. Restart/redeploy the application once and confirm the administrator login and configuration still exist.

The wrapper does not silently create the administrator or rewrite LimeSurvey's generated `application/config/config.php`.

## 4. Install and activate ResendEmail

The image stages the managed plugin and the entrypoint refreshes only `/var/www/html/plugins/ResendEmail` on every application start. Other plugin directories are preserved.

After LimeSurvey initialization:

1. Open **Configuration → Plugins**.
2. Scan the filesystem for plugins.
3. Install `ResendEmail`, then activate it.
4. Open **Configuration → Global settings → Email settings**.
5. Select **Resend HTTPS API** as the email method and save.
6. If LimeSurvey reports that `RESEND_API_KEY` is missing, correct the Coolify secret variable and redeploy the application; never paste the key into a survey setting.

Attachments intentionally fail closed. This plugin must not be selected for a flow that requires email attachments until attachment support has tests and an approved implementation.

## 5. Validate production behavior

Record timestamps and pass/fail results, but not recipient addresses, message bodies, tokens, or response data.

1. `https://survey.omnestack.com/` returns a valid TLS response and the browser shows the expected LimeSurvey page.
2. Coolify shows `db`, `app`, and `nginx` healthy.
3. The MariaDB port is not published publicly.
4. Create a disposable internal survey and submit one non-sensitive test response.
5. Restart the application and database services; confirm the survey and test response persist.
6. Send one LimeSurvey test/verification email to an approved test mailbox.
7. Confirm LimeSurvey reports acceptance, Resend records the request, and the message reaches the mailbox. These are three separate checks.
8. Confirm no API key, authorization header, database password, or email content appears in application or deployment logs.
9. Confirm no temporary Coolify tasks remain.

If delivery fails, inspect only the safe status/error text first. Verify the selected email method, plugin activation, sender-domain verification, and Coolify variable presence. Rotate the Resend key immediately if it was ever printed or pasted into an unsafe location.

## 6. Paired backup and isolated recovery

The installed predecessor has schema 712 and MyISAM tables. Quiesce every
writer, including app/nginx ingress and any background job, before dumping.
Use `--lock-all-tables --quick --routines --events --triggers`; transaction-only
dumps cannot establish MyISAM consistency. Keep the database alive, stop app
and nginx, and retain the original volumes throughout recovery.

Use the finite `operate.py rehearse` / `promote` protocol documented in
[staging delivery](delivery/staging.md). Its stable application UUID lock covers
backup, off-host acknowledgement, restore, migration, proof and publication.
Disable automatic Coolify deployment and prove no active/queued jobs before
starting. Provider stop-before-hook behavior means `custom_start` cannot own
this complete critical section; use controlled Compose with the existing UUID.

The helper writes a private SQL dump and full application archive, including
code, config/security, uploads, plugins, themes and runtime. It records table
engines/counts, real configured prefix, permission semantics, original image
IDs and regular-file hashes. Store the pair on a different access-controlled
host and recompute both hashes there. An explicit acknowledgement binds that
pair to the current transaction/state; a missing or mismatched acknowledgement
keeps writers stopped. Do not stream dumps, config or logs into terminals.

## 7. Restore, migration and rescue

Prepare fresh owned isolated volumes from the exact admitted PHP image before
starting the restore stack. Verify the actual DB image, volume and network
identities before any SQL import or reset. Never attach candidate MariaDB to
original database storage. Copy only installed `config.php`, byte-exact
`security.php`, optional `allowed_hosts.php`, explicitly reviewed operator
configuration/custom plugins/themes, and uploads onto the new defaults.
Retain the complete old archive; do not overlay old core/defaults/cache/runtime
onto the candidate. Selected symlinks or special files require separate review
and block automatic restoration.

Require exactly schema 712 before the one-off `updatedb` execution as www-data.
Keep `YII_CONSOLE_COMMANDS` absent, capture DSN/SQL-bearing output in a 0600 log,
and stop the recorded owned updater on timeout. Reject schema 717 no-op and
newer/unknown versions as proof of migration. Verify schema 717 plus plugin
backfill, permission tuple maxima/unique index, quota columns on all existing
active `responses_<sid>` tables, savequotaexit defaults/inheritance, session
column, default theme options and browser behavior. Localization/permission
counts can change legitimately; preserve survey/user/response aggregates.

The rehearsal injects an invalid configuration only in the isolated copy,
proves that it fails, restores the matched schema-712 DB/files pair, migrates
that restored copy, and requires fresh admin/public/persistence proof. Original
traffic can resume after the consistent backup and off-host verification while
this isolated rehearsal continues. Promotion requires the completed hash-bound
rehearsal and a new fresh paired backup under the same stable UUID lock.

Promotion preserves the selected application's private routes/environment and
uses all three accepted immutable images without building. A generated private
Nginx header fence returns 503 to ordinary requests, while exact `/healthz`
remains a static anonymous health check. Only the controller's protected header
allows HTTPS/admin/public/persistence validation. After acceptance, restore the
canonical Nginx configuration and recreate only nginx; require another actual
HTTPS health proof before unlocking. Ordinary request 503 must be independently
verified before publication. Tokens never enter argv, logs or screenshots.

A failed attempt stops candidate app/nginx and preserves data, receipts and
logs. Verify `fence_stop_verified`; a false value requires immediate controlled
writer fencing. Before publication, `legacy-rescue` can reattach the retained
original images/volumes only after proving their matching schema-712 inventory
and original file hashes. It requires functional acceptance and explicitly
reports `LEGACY_INELIGIBLE`, since the old image is not security-admitted.
After `public_unfenced=true`, legacy rescue is blocked: new writes may exist,
so restoring an older pair needs a separately reviewed data-preservation plan.
Never run the predecessor app against schema 717. No failed state or retained
volume is deleted automatically. Record measured elapsed recovery/write windows;
do not invent RPO/RTO guarantees. Mail remains UNKNOWN until approved recipient,
provider acceptance and actual mailbox delivery are independently recorded.

## 8. Upgrade

1. Review the LimeSurvey release notes and database migration requirements.
2. Update the upstream tag, commit, archive SHA-256, base-image versions/digests, and the versioned code/config/plugins/themes/runtime volume names in one reviewed change.
3. Run the full local gate, dependency/secret review, and native ARM64 build.
4. Produce and restore-test a fresh production backup.
5. Deploy in a maintenance window, verify database migrations, browser behavior, plugin availability, persistence, and a Resend test delivery.
6. Retain the previous Git revision, image, database dump, and application-volume archive until the rollback window closes.

For the current `7.5.0+261001` candidate, the source archive checksum is
`88a5501ecd61c3710a8902ce8eb0894d38b64e80c0caaffae496038ab226a493` and the
required schema is 717. Fresh `app-code-v7-5-0`, `app-config-v7-5-0`,
`app-plugins-v7-5-0`, `app-themes-v7-5-0` and `app-runtime-v7-5-0` volumes are
necessary: populated mounts hide new application files, including upstream
plugins/themes, `version.php`, configuration defaults and compiled runtime caches.
Operational volumes containing upstream files must identify the accepted app
digest and be seeded from that exact image. Database and upload volume names stay
unchanged. Previous volumes are retained; never run `down --volumes` on an upgrade.

Before starting an upgraded application against an existing database, stop public
traffic and application writers, complete the paired DB/files backup and isolated
restore proof, then seed fresh volumes with the new image. Restore the reviewed private
`application/config/config.php` settings and the original private
`application/config/security.php` into the fresh config volume before any app or
CLI execution. Preserve `security.php` byte-for-byte: it contains encryption keys
and nonces required to read existing encrypted database records. Missing original
keys for encrypted data block the upgrade; never generate replacements. Reconcile
private settings with new defaults, verify connection settings and existing-data
decryption privately, and never log keys or decrypted records. Inventory other
operator-owned configuration additions and preserve/reconcile each reviewed file,
including `application/config/allowed_hosts.php` when present; absence must not
silently relax an existing host allowlist. Verify the accepted hosts before
restoring traffic. Never overlay the old full config directory or old
`version.php`/`config-defaults.php`. Missing private configuration is an upgrade
blocker, not permission to expose or run the installer against an existing DB.

Inventory old plugin/theme volumes and migrate only reviewed custom additions
into their matching fresh volumes. Do not restore old upstream plugin/theme
folders over new defaults; check custom plugin compatibility and custom theme
inheritance against 7.5. Keep the new runtime/cache volume fresh. Verify the
selected image's version, schema metadata, upstream plugin/theme files and private
config placement before the serialized migration. A full old application-volume
archive is for paired recovery with the old image/database, not for overlaying the
new release. The development Compose file alone is not a production upgrade
procedure; use the reviewed private operational adapter and migration helper.

The supported schema 712 → 717 command is `updatedb` in the pinned console
entrypoint. It has no dry-run, writes DSN/SQL-bearing output, and does not
activate hard maintenance automatically for this range. Execute only through
the reviewed private operational helper after write quiescence, off-host backup
and isolated restore proof. One deployment lock must cover backup, migration,
health and rollback; its built-in runtime-file lock alone does not coordinate
separate containers or manual deployment. Reject a newer installed schema before
execution; return code zero and `DBVersion=717` alone do not prove all columns,
indexes, theme defaults and semantic data updates succeeded. Verify them explicitly.
An initial empty installation has no upgrade migration; record it as not applicable.
The source-maintenance phase does not run this command against existing data.

Never change a pinned value to `latest`, `master`, or another moving reference.

## 9. Rollback and cutover boundaries

Before a database migration, decide whether the old application can read the migrated schema. If compatibility is not explicitly documented, rollback means restoring both the previous application volumes and the matching database backup into an isolated replacement stack.

For an application-only failure before any schema/data change:

1. Remove traffic from the failed LimeSurvey route.
2. Redeploy the previous accepted image digests and matching code/configuration.
3. Verify health, login, persistence, and email behavior before restoring traffic.

For a schema, data, or volume failure:

1. Keep the failed stack stopped and preserve it for diagnosis.
2. Create fresh volumes with the previous verified revision.
3. Restore the matching database and application archives.
4. Verify checksums and acceptance behavior, then switch the route.

Formbricks remains the service-level rollback path until LimeSurvey acceptance, survey recreation, dependent-site updates, and cutover all pass. Keep all Formbricks resources and backups for at least seven days after cutover. Permanent deletion requires a new explicit approval.
