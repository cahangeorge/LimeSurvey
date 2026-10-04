# ADR0001: PHP8.3 on Alpine3.24 for the Resend MVP

Date: 2026-10-04. Decision accepted by the user through the explicit instruction to execute this recommendation. Release/deployment acceptance is separate.

## Context

The LimeSurvey wrapper needs PHP8.3/FPM, the existing14modules, Romanian UTF-8/locale behavior and email through the Resend HTTPS plugin. The prior Debian12 diagnostic image retained blocking package findings after available updates and build-tool cleanup. A private Alpine3.24/PHP8.3.35 canary passed local application/module/locale tests and had zero reported package CVEs at its recorded database timestamp. This is evaluation evidence, not a guarantee of vulnerability absence.

Alpine c-client provides IMAP SSL but lacks Kerberos/GSSAPI authentication. The user selected the recommended MVP scope without Kerberos as a requirement; Resend remains the outgoing email transport. No change to application source, database major version or production configuration is part of this decision.

## Decision

- Use official `php:8.3.35-fpm-alpine3.24@sha256:454b11c8907e32878ce92e87b13c14e1bbe6e1b10f4f96d4a19c9b62ec675d41` for both source preparation and runtime stages.
- Preserve LimeSurvey7.1.1+260914 commit `6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9` and the exact verified source archive checksum.
- Retain all14modules, IMAP SSL, GNU iconv and full ICU data. Do not advertise Kerberos or keep a misleading configure flag for an absent feature.
- Install build dependencies in a removable APK group; retain ELF runtime dependencies for PHP/FPM/modules and reject compiler/header packages in smoke.
- Independently inventory every installed APK and Composer package; apply the existing strict image/digest/ARM64/DB/SBOM/HIGH/CRITICAL/UNKNOWN contract without waivers.

## Consequences and remaining gates

Kerberos/GSSAPI is outside this MVP. If a concrete future requirement appears, review a compatible base or c-client build and test against an isolated authentication fixture before promising support. IMAP over TLS with username/password remains available; an actual mail-server connection is a separate integration test.

UID/GID for www-data changes33→82; local fixtures and smoke test Unix permissions, but production-volume ownership and served-code identity require staging evidence. The existing app-code volume can mask a new image's code. No production data or volumes are changed by this source decision.

Alpine community support ends at the next stable release; base maintenance must follow that support window, not only the main repository's longer EOL. APK updates are not bit-identical rebuild guarantees. Publish and promote one tested digest; preserve the previous digest for rollback and keep DB migration/recovery gates separate.

Native ARM64 build/test, final registry-digest scan, isolated staging and recovery remain required before production. Source-built PHP, application code and non-Composer assets need separate upstream/security review. Local adoption does not authorize commit/push/publication/deployment or credential changes.

## References

[PHP8.3.35 security release](https://www.php.net/releases/8_3_35.php), [Alpine support branches](https://alpinelinux.org/releases/), [official PHP image source](https://github.com/docker-library/php/tree/master/8.3/alpine3.24), [Alpine IMAP build recipe](https://gitlab.alpinelinux.org/alpine/aports/-/blob/3.24-stable/main/imap/APKBUILD). Operational reports and inventories remain private outside this public repository.
