# Signed release artifacts

## Contract

The PHP and Nginx publishers must sign the exact GHCR digest only after their
existing native build, smoke, vulnerability, inventory and SBOM gates pass.
Use Cosign keyless with GitHub Actions OIDC; do not retain a private signing key.
Attach SLSA v1 provenance and the CycloneDX SBOM to that same image digest.
Before reporting signing success, cryptographically verify the image signature
and both attestations using the exact publisher workflow identity, GitHub OIDC
issuer and source commit. Check the verified payloads against the expected image,
source commit, release run and local evidence hashes. A missing signature,
wrong identity, substituted digest, altered SBOM or failed verifier is HOLD.

This is a local implementation phase. Commit, push, merge, workflow dispatch,
registry writes and deployment require their corresponding existing authority.
The previous unsigned images are not retroactively signed by this change.
Signing proves origin and integrity; it does not establish application acceptance,
erase vulnerabilities or authorize deployment. No SLSA assurance level is claimed.

## Scope and tasks

One Codex writer, isolated worktree based on `94cdd41f797bb24fc056b905c88004ab1f56dc60`.
Only five source files: both publisher workflows, `scripts/ci/sign-release.py`,
`tests/test_signing_gate.py` and this document. The staging refresh PR is preserved.

1. Add tests for evidence/predicate binding and rejection paths; prove the missing
   implementation fails before writing the helper.
2. Generate provenance from verified release evidence; implement exact-identity
   Cosign signing and verification with bounded subprocesses and fail-closed output.
3. Wire both main-only publishers after manifest creation, with pinned Cosign and
   job-scoped OIDC permission. PR workflows retain read-only permissions.
4. Run the signing tests, the complete Python gate suite, actionlint, zizmor,
   secret scan and diff checks; obtain independent native read-only review.

## Verification

```bash
python3 -m unittest discover -s tests -p 'test_signing_gate.py'
python3 -m unittest discover -s tests -p 'test_*gate.py'
git diff --check
```

The existing PR quality job discovers `test_*gate.py`, including the new tests.
Tests use synthetic evidence and stub the external registry/OIDC boundary; they
do not claim a live keyless signature. Live acceptance additionally requires an
authorized publisher run on integrated main, read-back of the same digest and
verification of its signature and both attestations. Until that probe passes,
hosted signing and production remain unverified.
