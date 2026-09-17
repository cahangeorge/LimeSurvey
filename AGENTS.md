# Repository operating contract

## Source of truth

- Requirements: `docs/spec.md`
- Ordered work and gates: `docs/implementation-plan.md`

Operational inventories and backup evidence are private local artifacts and must not be added to this public repository.

Read these files and run `git status --short --branch` before making changes.

## Architecture and versions

- Upstream LimeSurvey tag: `7.1.1+260914`
- Upstream commit: `6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9`
- Runtime: Nginx, PHP 8.3 FPM, MariaDB 11.4 LTS
- Target platform: Docker Compose on ARM64 Coolify
- Email: Resend HTTPS API through a LimeSurvey plugin; do not depend on SMTP ports 465/587

Do not replace pinned revisions with `master`, `latest`, or another moving reference.

## Commands

Run the smallest relevant check after each slice:

```bash
git diff --check
docker compose config --quiet
docker compose build --pull
docker compose up -d
docker compose ps
find docker plugins tests -name '*.php' -print0 | xargs -0 -n1 php -l
composer install --no-interaction --no-progress
vendor/bin/phpunit tests/ResendEmailPluginTest.php
```

Commands referring to files not yet implemented are release targets, not permission to skip verification.

## Safety

- Preserve unrelated user work and keep each task within the approved plan.
- Keep all credentials in local secret files or Coolify secret variables.
- Never print or commit `.env` values, database URLs, API keys, administrator credentials, survey exports, response payloads, or backup archives.
- Do not pipe database dumps through task/deployment logs.
- Keep Formbricks online until LimeSurvey production acceptance and migration checkpoints pass.
- The off-server backup gate must pass before cutover.
- Do not stop Formbricks until the cutover task authorizes it.
- Do not delete Formbricks containers, volumes, routes, secrets, or backups without a separate final user approval after the seven-day rollback window.

## Implementation discipline

- Use one writer per worktree.
- Follow test-driven development for plugin behavior: failing test, minimal implementation, refactor.
- Keep task changes to five files or fewer unless the plan is updated and reviewed first.
- Pin base images by explicit version and, at release, by immutable digest where available.
- Compose must keep the database private and define health checks and persistent volumes.
- Shell scripts use `set -eu`, finite timeouts, and secret-safe errors.
- The Resend plugin must fail closed for unsupported attachments rather than silently dropping them.

## Release evidence

Before claiming a checkpoint complete, record the exact commands and results in the corresponding evidence/runbook document. A Coolify status alone is insufficient: verify HTTPS, browser-visible behavior, persistence after restart, final Resend delivery, and zero leftover temporary tasks.
