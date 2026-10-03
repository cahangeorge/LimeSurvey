# Active Plan: ARM64 release artifact

## Project and phase

Public LimeSurvey wrapper, `cahangeorge/LimeSurvey`; bounded Lot3 candidate, 2026-10-03.
Base: integrated main `f25836960b2086e8fdeff38cf48d9fb11bac1ae4`.
Codex leader is sole writer; native architectural/source review is read-only.
Existing source requirements and deployment gates remain in `docs/spec.md` and `docs/implementation-plan.md`.

## Scope and order

1. Artifact slice, four files: new `.github/workflows/release.yml`, `scripts/ci/release-artifact.py`, `tests/test_release_gate.py` and existing `docker/php/Dockerfile`.
2. Verification integration slice, two files: `tests/smoke.sh` adds explicit use of a previously built image without rebuild, and `.github/workflows/release-gate.yml` runs the new behavioral probes in required CI. Inspection found existing smoke unconditionally rebuilt, so this adapter is necessary to test the exact artifact.
3. Documentation slice: this plan and `docs/delivery/security-policy.md`.

Build a single native ARM64 candidate from verified main using multi-stage source preparation and pinned runtime inputs. Run disposable runtime smoke on that built image. A manual main-only workflow verifies successful required CI for its exact source SHA before registry access. GHCR uses only job-scoped `GITHUB_TOKEN`; no production secrets or OIDC permission. Use unique run tags and verify final digest/config/platform/source identity, scan that exact digest, convert the same complete report into CycloneDX, and create a manifest only after validation succeeds. Registry storage alone never grants staging or production eligibility.

## Acceptance

- Branch/commit/CI mismatch or missing evidence fails closed before publication. PR events and non-main refs cannot run publication.
- Final registry manifest hash/config matches the tested local image. Platform is linux/arm64. OCI revision records wrapper SHA; upstream source identity is recorded separately.
- Trivy inventories Debian OS packages and every independently extracted installed upstream Composer package/version; missing targets/packages, malformed reports, stale DB, unsupported scan identity, unknown severity, HIGH/CRITICAL with or without fix block eligibility. No blanket waiver.
- SBOM derives from that exact scan and proves package coverage; manifest hashes bind scan/SBOM/config/inventory to image and exact CI run. Staging, migrations, previous promoted digest and production remain explicit pending gates.
- Behavioral negative probes, all required workflow linters, secret scans and independent review pass locally. Native hosted build, digest scan and GHCR publication remain external acceptance evidence until actually executed.

## Verification and stop

Use pinned security tools already verified in the foundation; verify ARM64 Trivy publisher checksum and artifact-upload action commit from official upstream. Run `python3 -m unittest discover -s tests -p 'test_*gate.py'`, actionlint, offline strict zizmor, Gitleaks history/current files, Compose validation and `git diff --check`. Record actual scan coverage using a read-only export of the existing local baseline; it is diagnostic evidence, never release evidence. Targeted build/runtime verification uses disposable isolated resources only.

Local implementation/review is authorized. Stop at the concrete reviewed commit/push/PR and GHCR publication gate if its new scoped authority is missing. No production/staging changes, credential configuration, database migration, private-data transfer or Coolify branch changes. Preserve all other worktrees and private operational evidence. Final local status must distinguish PASS, FAIL, UNKNOWN and HOLD.
