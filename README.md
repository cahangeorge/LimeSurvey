# LimeSurvey for Coolify

Deployment wrapper for running [LimeSurvey Community Edition](https://github.com/LimeSurvey/LimeSurvey) on ARM64 OCI infrastructure. The current OmneStack deployment is the migration source; OCI restore rehearsal and cutover remain pending.

## Status

The functional and signed-artifact pipeline passed on integrated source
`34d187f542e013ecfad5fca3023c62423898ad7d`:
[PHP publisher](https://github.com/cahangeorge/LimeSurvey/actions/runs/38087140326)
and [Nginx publisher](https://github.com/cahangeorge/LimeSurvey/actions/runs/38087586359).
Exact native CI, public Chrome survey/export/restart proof, digest scans,
CycloneDX SBOM, keyless signatures and independent provenance verification
passed for those prior artifacts.

The current candidate updates LimeSurvey to the hash-pinned 7.7 CE distribution below and
adds a strict MariaDB/gosu derivative. Its native runtime, fresh security scans
and signed artifacts require new exact-source acceptance; previous success is
not proof for this candidate. Production remains blocked until those checks,
real three-image staging, backup/restore, serialized migration and rollback pass.
See [`docs/implementation-plan.md`](docs/implementation-plan.md). Formbricks
remains independent; operational evidence and secrets stay outside this public repo.

## Pinned upstream

- Official CE ZIP version: `7.7.0+261020`
- Archive SHA-256: `925dd275e301b3a12fd18e14994bd21cbee34a08202bc618278c3c1cfc16988d`
- PHP: `8.3.36-fpm-alpine3.24` (immutable multi-architecture base)
- License: GPL-2.0-or-later

The official ZIP is verified before extraction; no upstream Git commit is asserted for this release. The download directory name `latest-master` is only a transport path: the complete filename and SHA-256 identify the admitted bytes.

This repository contains deployment configuration, tests, runbooks, and a Resend HTTPS email plugin. It does not track LimeSurvey's moving `master` branch and should not carry a modified vendor tree.

## Intended architecture

```text
Internet
   |
   v
Coolify proxy / TLS
   |
   v
Nginx  -->  PHP 8.3 FPM / LimeSurvey  -->  MariaDB 11.4 LTS
                    |
                    +--> Resend HTTPS API
```

The final service will use `survey.omnestack.com`. The existing Formbricks service at `feedback.omnestack.com` remains independent until backup, deployment, migration, and cutover checkpoints pass.

## Local verification

The repository includes a no-network plugin unit test and a disposable Compose smoke test:

```bash
composer install --no-interaction --no-progress
vendor/bin/phpunit tests/ResendEmailPluginTest.php
docker compose --env-file .env.example config --quiet
./tests/smoke.sh
git diff --check
```

The smoke test builds the pinned image, verifies service health and database persistence, confirms that the database port is private, checks Nginx deny rules, and confirms the packaged `ResendEmail` plugin metadata. It does not send email or use a real Resend key.

Never place `.env`, database dumps, API keys, administrator credentials, exports, or survey responses in this repository.

## Documentation

- [`docs/spec.md`](docs/spec.md) — approved requirements and boundaries
- [`docs/implementation-plan.md`](docs/implementation-plan.md) — ordered tasks and checkpoints
- [`docs/runbook.md`](docs/runbook.md) — deployment, initialization, backup, restore, email validation, upgrade, and rollback

Production resource identifiers, survey inventories, database evidence, and backup locations are intentionally not published.

## Upstream notice

LimeSurvey is maintained by the LimeSurvey project. This wrapper is not an official LimeSurvey image or distribution channel.
