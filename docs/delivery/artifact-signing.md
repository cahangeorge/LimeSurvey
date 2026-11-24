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

One Codex writer, isolated worktree based on `2b7abac451afb0ce74aae735fe8b62d5ce171b41`.
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

## Publisher and consumer commands

The main-only `release.yml` (PHP) and `nginx-release.yml` (Nginx) install
`sigstore/cosign-installer@ba7bc0a3fef59531c69a25acd34668d6d3fe6f22` (v4.1.0),
with explicit Cosign v3.1.3. Only those publisher jobs have `id-token: write`.
They run the following after successful release manifest creation, using their
existing temporary GHCR login; no production credential is required:

```bash
python3 scripts/ci/sign-release.py sign "$EVIDENCE" php "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
# The Nginx publisher passes nginx instead of php.
```

A consumer must obtain the release evidence and select the expected commit/run
from the approved candidate, independently of the registry response. With the
same pinned Cosign on PATH, verify without publishing anything:

```bash
python3 scripts/ci/sign-release.py verify RELEASE_EVIDENCE_DIRECTORY php EXPECTED_COMMIT EXPECTED_RUN_ID EXPECTED_ATTEMPT
```

`release.json` alone is insufficient for signed-release acceptance. This command
cryptographically verifies the image signature and both attestations, checks their
payloads and unchanged local evidence, and creates `signing.json` with status
`SIGNATURES_VERIFIED` only when all checks succeed. It removes an earlier receipt
before verification so a failed attempt cannot retain apparent success.
The receipt records hashes of the verified outputs and release manifest; reuse
requires fresh verification. Staging vulnerability/freshness and runtime gates
remain independent. The existing staging adapter is not changed by this slice.

No live signing is performed on PRs. Initial image publication can succeed before
a later scan/signature step fails; that image must remain an unapproved candidate.
Partial signature/attestation writes are possible if a service fails mid-run.
A failed publisher is not a release, and no automatic retry or promotion occurs.
Keyless signing publishes the public artifact identity to Sigstore transparency
infrastructure; private operational inventories are not included.

## Build definition v1

The predicate's build type is the URI of this section. Each publisher builds once
with Docker Buildx on native ARM64 using its pinned Dockerfile/source and current
protected-main CI gate. The final registry manifest must identify the exact image
that passed the existing publisher smoke and inventory/security gates.
`externalParameters` records source commit/ref and the component. The builder ID
is the exact main workflow certificate identity; the invocation includes the run
and attempt. `resolvedDependencies` binds source and all release evidence hashes,
including registry manifest, scan, inventory, SBOM, CI and release manifest.
Those records describe this custom build definition, not a complete reproducibility
claim or a GitHub-generated attestation.

Cosign v3.1.3 uses the SLSA v1 predicate inside an in-toto Statement/v0.1 envelope.
The built-in `slsaprovenance1` and `cyclonedx` types and their real output shapes
are used; container `attest --statement` does not work in this pinned release.
Verification pins the issuer to `https://token.actions.githubusercontent.com`,
the exact `release.yml` or `nginx-release.yml` main identity, the certificate's
GitHub workflow source SHA, the image digest and the expected predicate bytes as
JSON values. The helper consumes verifier output only after Cosign succeeds.
This does not assert a SLSA assurance level.

## Cosign v3 registry envelope correction

The first live publisher on integrated source `b504af2` wrote a valid image
signature and both attestations, but the helper rejected the verifier's actual
v3 output. Its `critical.identity.docker-reference` contains the complete
`repository@sha256:digest`, rather than a bare repository. The bounded correction
touches only this document, the signing helper and its tests. Verification now
requires the exact digest-qualified reference and
`critical.type == https://sigstore.dev/cosign/sign/v1`. Cosign may also return
verified provenance/SBOM claims from OCI referrers; those alone cannot substitute
for the required image signature. Repository-only, other-digest, unknown-type
and attestation-only claims remain rejected. Exact certificate identity, issuer,
source commit, transparency, attestation subjects and evidence binding remain
mandatory. No insecure verification option or security-policy waiver is added.

Regression tests reproduce the original failure with the real v3 claim shape.
Acceptance also requires read-only cryptographic verification of the existing
digest and a corrected hosted publisher; the first failed run remains a failed
run and cannot be promoted.

References: [Sigstore CI](https://docs.sigstore.dev/quickstart/quickstart-ci/),
[pinned installer](https://github.com/sigstore/cosign-installer/blob/ba7bc0a3fef59531c69a25acd34668d6d3fe6f22/action.yml),
[Cosign attestation implementation](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/pkg/cosign/attestation/attestation.go),
[Cosign verification](https://github.com/sigstore/cosign/blob/11926fa5bbbbde47e88fc006b625a17769b743b2/pkg/cosign/verify.go).
