# Active Plan: adopt PHP Alpine base for the MVP

## Project and phase
LimeSurvey CI/CD MVP, bounded local base adoption, 2026-10-04. Root Codex sole writer; independent native review read-only.
User explicitly requested execution of the recommendation: Alpine3.24/PHP8.3 with Resend; Kerberos/GSSAPI is outside this MVP requirement. Prior canary and APK adapter are checkpointed privately. Main base a904e62; preserve original dirty checkout.

## Scope and ordered work
This phase edits five files: active-plan.md, docker/php/Dockerfile, tests/smoke.sh, docs/delivery/security-policy.md, and a new material-decision ADR docs/delivery/adr-0001-php-alpine-base.md. Prior release helper/tests stay byte-for-byte unchanged. Accumulated candidate diff is seven files, including those two prior implementation files; scope accounted for explicitly.
1. Record the user-authorized base/feature decision and exact immutable official PHP8.3.35/Alpine3.24 base; preserve pinned application source/archive and all14required modules.
2. Adopt the reviewed canary package/build cleanup recipe. Remove the misleading --with-kerberos flag and unused krb5-dev dependency; retain SSL IMAP, GNU iconv/full ICU and runtime ELF dependencies for PHP/FPM/modules.
3. Adapt smoke to APK, checking each development/header package individually from a successfully read inventory. Prove single-package rejection and inspection-error failure; retain all existing no-build integration/persistence/protection checks.
4. Build the exact new repository Dockerfile locally; record diagnostic development-label config and source hashes. Test required modules/FPM, Romanian probes, actual PHP Resend unit tests, full no-build disposable smoke and50Python gates.
5. Restore pinned ephemeral scanner tools and download a fresh vulnerability DB; scan exact image, independently extract APK/allComposer packages with the current helper, convert same report to CycloneDX and verify complete package/config/PURL coverage. Independent native review, cleanup and durable handoff complete the phase.

## Acceptance and verification
No silent application version change or relaxed HIGH/CRITICAL/UNKNOWN thresholds; unknown/incomplete evidence remains HOLD. Dockerfile build dependencies/header tools absent; each individual forbidden-package fixture must fail.
Use actual local AMD64 execution only. Native ARM64 and final registry digest require later live verification. Avoid rebuilding/rescanning unchanged intermediate states after PASS; one corrected rebuild only if a real defect requires it.
Tests: sh -n tests/smoke.sh; git diff --check; current helper inventory; PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*gate.py'; actual image PHP tests; ENV_FILE=.env.example APP_IMAGE=<tested image> SMOKE_NO_BUILD=1 COMPOSE_PROJECT_NAME=limesurvey-adopt-smoke-20261004 sh tests/smoke.sh. Remove only this synthetic smoke's volumes/resources afterward. Operational evidence stays private.

## Authority and stop
Local base adoption/build/scan/test is authorized by the explicit request. No commit/push/PR/GHCR publication/workflow dispatch, native ARM claim, remote provisioning, production/staging deployment, migrations, credential changes or mutation of existing Coolify/Formbricks resources. Synthetic local smoke DB writes only. Stop with reviewed local result and one concrete next external gate.

## Completed checkpoint — 2026-10-04
LOCAL ADOPTION PASS; release HOLD. Adopted official pinned PHP8.3.35/Alpine3.24, retained exact upstream source, all14modules, GNU iconv/full ICU and IMAP SSL. Kerberos excluded by the accepted MVP decision; ADR0001 records compatibility and volume caveats.

Exact repository build and disposable no-build smoke PASS on Linux/AMD64. PHP10tests/56assertions,50Python gate tests, PHP lint, Romanian probes and seven APK guard regressions PASS. Native read-only review resolved one inventory-error masking defect with a smoke-only correction; no remaining introduced blockers. LSP diagnostics unavailable.

Fresh October4Trivy0.75.0 scan reports zero package vulnerabilities:55APK+46Composer,101PURLs matched exactly to CycloneDX1.7 and independent image inventory. This does not cover every source-built component or establish ARM64/release readiness. Evidence is bound to a local diagnostic config with development revision, not a published release digest.

Release helper/tests unchanged from phase start; original14dirty-file hashes preserved. Own smoke containers/networks/volumes and scan archive removed; image/reports retained privately. Seven accumulated candidate files remain uncommitted. Canonical operational evidence: /home/gion/.local/state/cicd-mvp/20261002-limesurvey/current-status.md and adopt.local-acceptance.json.

Next gate: review and integrate this seven-file candidate through a GitHub PR under explicit publication authority; native ARM64 and final registry-digest verification follow separately. Staging/production remain HOLD.

## Integration phase — 2026-10-04
The subsequent user instruction to execute the recommendation authorizes committing/publishing this reviewed seven-file candidate to cahangeorge/LimeSurvey and integrating it through a protected-main pull request after mandatory CI passes. Root Codex remains the sole writer. Preserve all unrelated original work and every source pin/security gate.

Acceptance: exact reviewed code hashes; seven-file staged scope including ADR; no committed secrets/private operational evidence; remote branch and PR head match local commit; native hosted ARM64/runtime and all mandatory PR checks PASS; protected main integration and exact-source push CI verified. No bypass/force push or production action. A new defect permits only a bounded documented fix/review/check pass. Release-artifact dispatch/GHCR publication, staging/deployment/migrations/credentials remain separate authority gates.
