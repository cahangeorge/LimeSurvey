# Active Plan: CI/security foundation

## Project and phase

- Project: public LimeSurvey deployment wrapper, `cahangeorge/LimeSurvey`.
- Phase: local CI/security candidate; publication and hosted canaries are the next gate.
- Base: `main`, commit `ae0f999936bbccfa88c220072eb40af2e90bdbed`.
- Writer: Codex leader; independent native Codex review is read-only.
- Date: 2026-10-02.
- Existing requirements and deployment gates remain in `docs/spec.md` and `docs/implementation-plan.md`.

## Scope

Implementation slice (five files):

1. `.github/workflows/release-gate.yml`
2. `.gitleaks.toml`
3. `scripts/ci/install-security-tools.sh`
4. `scripts/ci/check-dependencies.py`
5. `tests/test_dependency_gate.py`

Documentation slice (two files): this plan and `docs/delivery/security-policy.md`.
Operational evidence and GitHub setting proposals stay outside this public repository.
The candidate starts from committed code and preserves unrelated changes in other worktrees.

## Acceptance criteria

- Hosted quality/security checks precede the existing native ARM64 build and Compose smoke job. The aggregate `MVP required gate` succeeds only when all three jobs succeed.
- Secret/workflow scanners reject synthetic defects. Dependency scanning proves complete locked package/version coverage, including development dependencies, and blocks unsafe or incomplete reports according to the security policy.
- Static checks, unit tests and independent review pass locally. Hosted positive/negative canaries and actual `main` enforcement are separate acceptance requirements; local validation cannot close them.

## Verification

Install the pinned Linux AMD64 tools into a disposable directory:

```sh
sh scripts/ci/install-security-tools.sh /tmp/limesurvey-ci-tools
git diff --check
sh -n docker/entrypoint.sh
sh -n tests/smoke.sh
sh -n scripts/ci/install-security-tools.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_dependency_gate.py'
/tmp/limesurvey-ci-tools/actionlint .github/workflows/*.yml
/tmp/limesurvey-ci-tools/zizmor --offline --strict-collection .github/workflows/*.yml
/tmp/limesurvey-ci-tools/gitleaks git --config .gitleaks.toml --ignore-gitleaks-allow --redact --no-banner --log-level error .
/tmp/limesurvey-ci-tools/gitleaks dir --config .gitleaks.toml --ignore-gitleaks-allow --redact --no-banner --log-level error .
```

The exact Composer, PHP, Compose, Trivy and ARM64 commands are in `release-gate.yml`.
Trivy reads only `composer.lock` in this phase; it does not inventory the upstream runtime downloaded by the Dockerfile.
The dependency validator's CLI takes the Trivy JSON report, `composer.lock`, and the downloaded DB's `db/metadata.json` in that order.

Verify secret rules using disposable synthetic files: each protected variable with a non-placeholder value, quoted/export/comment variants, exact root examples, altered examples and examples at other paths. Only exact root examples may pass. Redact scanner output and remove only the test fixture directory.
Verify the aggregate shell with success, failure, cancellation and skipped results; only all-success may pass.
Keep commands, exit codes and reports in private operational evidence.

## Stop condition

The local candidate can be reviewed and published after independent acceptance.
Commit/push/PR publication and GitHub protection changes require their explicit authority.
Checkpoint A remains HOLD until hosted positive/negative probes and real required-check enforcement pass.
Release artifact publication, staging, migrations, production and rollback proof remain later gates.
This phase adds no release/deployment credentials or production authority to CI.
