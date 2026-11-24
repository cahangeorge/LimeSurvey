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
2. Update the upstream distribution version/source type, archive SHA-256, base-image versions/digests, and the versioned code/config/plugins/themes/runtime volume names in one reviewed change.
3. Run the full local gate, dependency/secret review, and native ARM64 build.
4. Produce and restore-test a fresh production backup.
5. Deploy in a maintenance window, verify database migrations, browser behavior, plugin availability, persistence, and a Resend test delivery.
6. Retain the previous Git revision, image, database dump, and application-volume archive until the rollback window closes.

For the current `7.7.0+261020` candidate, the official ZIP checksum is
`925dd275e301b3a12fd18e14994bd21cbee34a08202bc618278c3c1cfc16988d`. The admitted ZIP declares schema 717,
as did the previous 7.5.0 deployment. Rehearse against a restored copy before
production; the existing historical controller only supports the 712-to-717
path and must not be used to migrate an existing schema-717 source to OCI. Fresh `app-code-v7-7-0`, `app-config-v7-7-0`,
`app-plugins-v7-7-0`, `app-themes-v7-7-0` and `app-runtime-v7-7-0` volumes are
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

## OCI cross-host schema 717 transfer (2026-10-22)

`scripts/delivery/crosshost.py` is a local Docker-host adapter. It does not use
SSH, start services, run `updatedb`, publish routes, resume source writers, or
remove source data. The historical `operate.py` 712-to-717 recovery command must
not be used for this transfer. There is no automatic reset or retry after a
partial restore: preserve the failed target and provision a new isolated target
with a new reviewed plan.

The reviewed target Compose source is `deploy/staging.compose.yaml`, using its
admitted immutable PHP/Nginx/MariaDB triple and `DELIVERY_*` external volume and
network selections. Render with `docker compose --project-directory <checkout>
--project-name <unique-oci-project> -f deploy/staging.compose.yaml config --quiet`
using an operator-owned private environment. Keep `RESEND_API_KEY` empty for the
rehearsal. Database and PHP publish no host ports; Nginx binds only
`127.0.0.1:$DELIVERY_PORT:80`. Use new OCI volume/network names disjoint from the
source. Target bridge networks must contain only the three exact target
containers, with no Coolify/proxy containers or public routing labels. The
adapter verifies those constraints before import. A live rendered configuration,
volume image-seeding check, admitted artifact identity and host isolation proof
remain gates; a static Compose render does not prove them.

Prepare target DB initialization only, with empty application tables, and seed
application volumes from the admitted image. Keep target app and nginx stopped
before restore; DB stays running. Do not run the installer. Supply the existing
DB connection identity through the approved secret path so the preserved
`config.php` remains usable; the adapter never reads/prints database passwords.
Both source encryption keys in `security.php` and the complete `config.php` are
restored byte-identically. Custom plugin/theme directories must be explicitly
allowlisted; the old application code and bundled defaults are not overlaid.

Before writer fencing, disable autodeploy on both source and target and verify
there is no queued deployment, scheduled restart or external supervisor action
that could restart app/nginx. Both Compose runtimes use `restart: unless-stopped`;
the Docker stop fence alone does not exclude an operator or deployment controller
starting them again. Retain that deployment freeze through publication. Re-inspect
the exact stopped source app/nginx IDs and private DB topology immediately before
cutover; if the fence has drifted, capture a fresh matched backup and repeat the
private restore proof before publication.

Before writer fencing, review a private JSON plan (mode `0600`) on each host.
Its absolute `directory` must have mode `0700`, belong to the invoking operator,
and resolve without symbolic links. Use the same absolute directory and plan
bytes on both hosts; the plan contains no secrets. Required shape:

```text
version: 1; schema: 717; transaction: unique lowercase alphanumeric (16–48 chars)
prefix: verified SQL table prefix
directory: absolute protected directory
hosts: {source: sha256(/etc/machine-id bytes), target: distinct host hash}
custom_plugins: explicit directory names; custom_themes: explicit directory names
source and target, each:
  nginx_config: {path: absolute local bind file, sha256: exact file hash}
  volumes: {db, code, config, upload, plugins, themes, runtime: exact Docker names}
  containers: {app, nginx, db}, each:
    id: exact 64-character container ID
    image: exact repository@sha256:digest
    image_id: exact sha256 image configuration ID
    networks: exact Docker bridge network names
```

The plan is reviewed and SHA-256 pinned externally before execution; the CLI
requires that exact hash. `validate-plan` checks only the plan structure and
protected paths; `validate` performs a real read-only runtime preflight on the
matching source/target host. Source preflight requires the running source
app/nginx, its reviewed private DB network, table prefix and schema 717; target
preflight requires stopped app/nginx and an empty DB. A different host fails
before Docker access. Inspect operations and backup receipts contain private
aggregate inventories and must stay outside Git. Run these local commands in
sequence, substituting only the reviewed plan path/hash:

```bash
python3 scripts/delivery/crosshost.py validate --plan /private/plan.json --plan-sha256 <reviewed-sha256>
# On OmneStack: verifies source schema/identity, stops exact nginx and app,
# rechecks writer fence, and uses mariadb-dump --lock-all-tables for MyISAM.
python3 scripts/delivery/crosshost.py backup --plan /private/plan.json --plan-sha256 <reviewed-sha256>
# Copy the matched database.sql, files.tar.gz, backup.json and identical plan
# through the approved encrypted transfer path into OCI's protected directory.
# Also retain an independently protected off-server copy and verify its hashes.
python3 scripts/delivery/crosshost.py verify-pair --plan /private/plan.json --plan-sha256 <reviewed-sha256>
# On OCI, with app/nginx stopped and only its empty DB running:
python3 scripts/delivery/crosshost.py restore --plan /private/plan.json --plan-sha256 <reviewed-sha256>
```

`backup.json` binds the plan, transaction, source host, SQL/archive hashes,
selected file hashes and schema/table/row/permission inventory in one receipt.
Receipt creation follows the fenced capture; transfer corruption and mixed
pairs fail before target import. Success leaves source stopped and target
app/nginx stopped. Repeating completed backup rechecks the fence/pair; repeating
completed restore rechecks the DB inventory and every restored file hash without
reimporting. A partial operation fails closed and retains diagnostic state.

`PRIVATE_RESTORE_VERIFIED` proves a stopped target restore, not application or
publication readiness. Next verify private HTTP/admin login, existing surveys,
synthetic response/export, restart persistence, PHP 8.3.36, schema 717, encryption
and Resend delivery with the approved sender. Recheck source fence and backup
retention before controlled canonical publication. Record the publication time
and first possible OCI write: after OCI accepts writes, restarting the stale
OmneStack DB is forbidden as a rollback. Recovery requires a fresh OCI paired
backup and a separately reviewed data-preserving plan. Remove OmneStack resources
only after successful live acceptance and the user's retention/deletion decision.

Offline adapter evidence (2026-10-22):
- `python3 -m unittest discover -s tests -p test_crosshost_delivery_gate.py`:
  13 tests PASS, including successful paired capture and repeat restore without
  reimport, plus schema/identity/path/permission/mixed-pair/port/network fences.
- `python3 -m unittest discover -s tests -p 'test_*gate.py'`: 194 tests PASS
  (181 existing gate tests plus 13 cross-host tests).
- `python3 -m py_compile scripts/delivery/crosshost.py tests/test_crosshost_delivery_gate.py`
  and `git diff --check`: PASS.
- Local `docker compose ... config --quiet` is unavailable: this workstation's
  Docker command invokes Podman Compose 1.6.0, which rejects `--project-directory`.
  Exact Docker Compose rendering on OCI remains an independent live gate.
No production capture, transfer, import, deployment or publication was performed
by this source implementation slice.

Independent review repairs (2026-10-22): source DB publication/internal bridge
membership are now verified before and after fencing/capture; `validate` invokes
runtime/schema preflight and `validate-plan` names the structural-only operation.
Focused tests reject new source ports, runtime port-map drift, publish-all,
non-internal DB networking, extra clients before/after fence, wrong hosts,
wrong schemas and runtime drift. No production operations were executed.
