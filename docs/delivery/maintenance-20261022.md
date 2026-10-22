# CE 7.7.0 and PHP 8.3.36 maintenance evidence

This is source/local verification for the 2026-10-22 candidate. Native ARM64
runtime, current CVE scans, signed release admission and OCI migration remain
separate gates. No production mutation, commit or publication was performed.

## Exact inputs

- Official distribution: `https://download.limesurvey.org/latest-master/limesurvey7.7.0%2B261020.zip`.
- Official SHA-256: `925dd275e301b3a12fd18e14994bd21cbee34a08202bc618278c3c1cfc16988d`.
- Download/checksum authority: [official CE downloads](https://community.limesurvey.org/downloads/) and [official checksum](https://download.limesurvey.org/latest-master/limesurvey7.7.0%2B261020-sha256-checksum.txt).
- Base image: `php:8.3.36-fpm-alpine3.24@sha256:81cb692948e6de4275f7e107c50a34e963a440660f2c5b8502d11071f7d30338`.
- [Official image metadata](https://github.com/docker-library/repo-info/blob/master/repos/php/remote/8.3.36-fpm-alpine3.24.md) identifies a multi-architecture index including AMD64 and ARM64.

The actual 120,913,268-byte ZIP was downloaded and SHA-256 verified. Its
`application/config/version.php` declares version 7.7.0, build 261020, schema
717. All 24,771 paths have the expected `limesurvey/` root, no absolute paths
or parent traversals; both root and TwoFactorAdminLogin Composer inventories
are present. Dockerfile SHA-256 and fail-closed member-list verification precede extraction.
The actual extracted awk guard passed the official archive and rejected empty,
absolute, parent traversal, nested traversal, wrong-root and mixed-root lists. Release admission
binds archive type/hash and requires the exact PHP security release.

## Commands and results

- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*gate.py'`: PASS, 181 tests. Includes distribution-label substitution and old/missing PHP version rejection in both Debian and Alpine fixtures.
- `PYTHONDONTWRITEBYTECODE=1 python3 tests/functional-smoke.py self-test`: PASS, 11 tests.
- `docker compose --env-file .env.example config --quiet`: PASS using the installed Podman Compose provider.
- `sh -n docker/entrypoint.sh tests/smoke.sh tests/nginx-security-smoke.sh scripts/ci/install-security-tools.sh`: PASS.
- Pinned Composer 2.8.12 disposable image: `composer validate --strict --no-check-publish` and locked `composer install --no-interaction --no-progress --prefer-dist`: PASS. PHP lint of docker/plugins/tests: PASS. `vendor/bin/phpunit tests/ResendEmailPluginTest.php`: PASS, 10 tests / 56 assertions (test tool PHP 8.4.14).
- `git diff --check`: PASS.
- `docker build --pull --platform linux/arm64 --file docker/php/Dockerfile ...`: blocked locally by `Exec format error` executing ARM64 `/bin/sh`; this AMD64 host has no ARM64 emulation. The expected ARM64 parent config was pulled, but this does not establish an ARM64 application build.
- Final local AMD64 build: `docker build --pull --layers --format docker --platform linux/amd64 --file docker/php/Dockerfile --tag localhost/limesurvey-maintenance:7.7.0-php8.3.36 .`: PASS. Config ID `sha256:a26f169992ec21469df19281e8ba8f50878da289ff0395d428b0658acd9c7bd6` (local config identity, no registry publication/digest). The completed build includes the archive-path guard.
- Final image `docker run --rm --network none --entrypoint php ...` probe: PASS, exact PHP `8.3.36`, all 14 required modules, CE `7.7.0`, build `261020`, schema `717`. `docker run --rm --network none --entrypoint php-fpm ... -t`: PASS. Image inspection confirms `amd64` and the configured HEALTHCHECK, 30s interval/start period, 5s timeout, 3 retries. Docker format is explicit because the installed Podman default OCI format omits HEALTHCHECK.
- Native ARM64 build, installer/public browser/export/restart acceptance, fresh CVE scans and signed three-component publication were not executed in this local source slice. The AMD64 image is diagnostic acceptance, not a production release.

## Migration gate

The existing operational controller's restore/migration path requires schema
712 and verifies 712-to-717 changes. The live source and this release both use
717; migration to OCI needs a reviewed schema-717 adapter and restore rehearsal
before backup/cutover execution. New code/config/plugin/theme/runtime volume
names prevent old upstream files masking the new image. Operator configuration,
security identity and uploads must be restored deliberately from paired backup.

No prior 7.5 Git-source receipt can admit this candidate. Fresh exact-source
native ARM64 CI/build, browser/installer/export/restart checks, security scans,
three-component signing and paired backup/restore remain required before release.
