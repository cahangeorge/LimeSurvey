# LimeSurvey for Coolify

Deployment wrapper for running [LimeSurvey Community Edition](https://github.com/LimeSurvey/LimeSurvey) on the ARM64 Coolify environment used by OmneStack platforms.

## Status

The pinned local runtime and Resend plugin are implemented. GitHub Actions run
[35342067109](https://github.com/cahangeorge/LimeSurvey/actions/runs/35342067109)
passed on commit `2fb6bdb` with a native `aarch64` build, required PHP module
checks, 10 tests/56 assertions, the Compose smoke test, and the secret scan.
Independent review then found Nginx direct-access and secret-scan blockers; their
local remediation still needs CI re-run and independent re-review. Checkpoint C
remains on hold, no immutable wrapper release tag exists yet, and Formbricks
remains online. See [`docs/implementation-plan.md`](docs/implementation-plan.md)
for the gated rollout. Operational inventories and backup evidence are kept
outside this public repository.

## Pinned upstream

- Release tag: `7.1.1+260914`
- Commit: `6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9`
- License: GPL-2.0-or-later

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
