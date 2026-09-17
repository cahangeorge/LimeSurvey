# LimeSurvey for Coolify

Deployment wrapper for running [LimeSurvey Community Edition](https://github.com/LimeSurvey/LimeSurvey) on the ARM64 Coolify environment used by OmneStack platforms.

## Status

Repository foundation only. The production service has not been deployed and Formbricks remains online. See [`docs/implementation-plan.md`](docs/implementation-plan.md) for the gated rollout. Operational inventories and backup evidence are kept outside this public repository.

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

## Planned local verification

The following commands become executable as their referenced files are added in Tasks 4-7:

```bash
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps

find docker plugins tests -name '*.php' -print0 | xargs -0 -n1 php -l
composer install --no-interaction --no-progress
vendor/bin/phpunit tests/ResendEmailPluginTest.php
git diff --check
```

Never place `.env`, database dumps, API keys, administrator credentials, exports, or survey responses in this repository.

## Documentation

- [`docs/spec.md`](docs/spec.md) — approved requirements and boundaries
- [`docs/implementation-plan.md`](docs/implementation-plan.md) — ordered tasks and checkpoints

Production resource identifiers, survey inventories, database evidence, and backup locations are intentionally not published.

## Upstream notice

LimeSurvey is maintained by the LimeSurvey project. This wrapper is not an official LimeSurvey image or distribution channel.
