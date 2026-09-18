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
- revision: immutable release tag `v7.1.1-260914-omnestack.1`
- Compose file: `/compose.yaml`
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

Do not set `APP_IMAGE` unless deploying a separately built immutable image. The Compose database has no published host port by design.

Deploy beside Formbricks. Confirm the native ARM64 build completes and all three services become healthy before adding migration traffic.

Before deployment, verify that the release tag resolves to the reviewed commit recorded in the
release evidence. Do not configure Coolify to follow mutable `main` or enable automatic deployment
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

## 6. Backup

Back up both MariaDB and the persistent application paths before upgrades, migrations, and cutover. Store an access-controlled copy outside the Coolify host and record SHA-256 checksums in the private operational evidence.

Run the following only from a trusted shell inside the correct Compose project directory. The dump is created inside the database container and copied as a file so its contents do not pass through task logs:

```bash
set -eu
umask 077
backup_root="${HOME}/limesurvey-backups/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$backup_root"

db_container="$(docker compose ps -q db)"
app_container="$(docker compose ps -q app)"
test -n "$db_container"
test -n "$app_container"

docker exec "$db_container" sh -eu -c '
  umask 077
  export MYSQL_PWD="$MARIADB_PASSWORD"
  mariadb-dump --single-transaction --quick --skip-lock-tables \
    --user="$MARIADB_USER" "$MARIADB_DATABASE" \
    > /tmp/limesurvey-database.sql
'
docker cp "$db_container:/tmp/limesurvey-database.sql" "$backup_root/database.sql"
docker exec "$db_container" rm -f /tmp/limesurvey-database.sql

docker exec "$app_container" sh -eu -c '
  umask 077
  tar -C /var/www/html -czf /tmp/limesurvey-application-volumes.tar.gz \
    application/config upload plugins themes
'
docker cp "$app_container:/tmp/limesurvey-application-volumes.tar.gz" \
  "$backup_root/application-volumes.tar.gz"
docker exec "$app_container" rm -f /tmp/limesurvey-application-volumes.tar.gz

chmod 600 "$backup_root/database.sql" "$backup_root/application-volumes.tar.gz"
sha256sum "$backup_root/database.sql" "$backup_root/application-volumes.tar.gz" \
  > "$backup_root/SHA256SUMS"
chmod 600 "$backup_root/SHA256SUMS"
```

Copy the complete directory to approved encrypted or access-controlled off-host storage, recompute checksums at the destination, and compare them. A backup is not accepted until a disposable restore succeeds.

## 7. Restore test and disaster restore

Prefer a new isolated Compose project and empty volumes for a restore test. Never overwrite the only working production database to prove a backup.

1. Verify `sha256sum -c SHA256SUMS` in the backup directory.
2. Deploy the same Git commit and pinned images into an isolated project with fresh volumes.
3. Start only `db`, wait for it to become healthy, then copy the dump into the container.
4. Import from the file inside the container; do not stream SQL through the terminal or task log.
5. Restore application volumes before starting `app` and `nginx`.
6. Validate schema presence, aggregate counts, login, survey rendering, and one non-sensitive record.
7. Destroy only the disposable restore project after recording the result.

Database import pattern for the isolated project:

```bash
set -eu
docker compose up -d db
db_container="$(docker compose ps -q db)"
test -n "$db_container"
docker cp ./database.sql "$db_container:/tmp/limesurvey-database.sql"
docker exec "$db_container" sh -eu -c '
  export MYSQL_PWD="$MARIADB_ROOT_PASSWORD"
  mariadb --user=root "$MARIADB_DATABASE" < /tmp/limesurvey-database.sql
  rm -f /tmp/limesurvey-database.sql
'
```

Restore the application archive only into fresh or deliberately selected volumes. Stop for explicit approval before replacing any production volume.

## 8. Upgrade

1. Review the LimeSurvey release notes and database migration requirements.
2. Update the upstream tag, commit, archive SHA-256, base-image versions/digests, and the versioned `app-code-*` volume name in one reviewed change.
3. Run the full local gate, dependency/secret review, and native ARM64 build.
4. Produce and restore-test a fresh production backup.
5. Deploy in a maintenance window, verify database migrations, browser behavior, plugin availability, persistence, and a Resend test delivery.
6. Retain the previous Git revision, image, database dump, and application-volume archive until the rollback window closes.

Never change a pinned value to `latest`, `master`, or another moving reference.

## 9. Rollback and cutover boundaries

Before a database migration, decide whether the old application can read the migrated schema. If compatibility is not explicitly documented, rollback means restoring both the previous application volumes and the matching database backup into an isolated replacement stack.

For an application-only failure before any schema/data change:

1. Remove traffic from the failed LimeSurvey route.
2. Redeploy the last verified Git revision and immutable image.
3. Verify health, login, persistence, and email behavior before restoring traffic.

For a schema, data, or volume failure:

1. Keep the failed stack stopped and preserve it for diagnosis.
2. Create fresh volumes with the previous verified revision.
3. Restore the matching database and application archives.
4. Verify checksums and acceptance behavior, then switch the route.

Formbricks remains the service-level rollback path until LimeSurvey acceptance, survey recreation, dependent-site updates, and cutover all pass. Keep all Formbricks resources and backups for at least seven days after cutover. Permanent deletion requires a new explicit approval.
