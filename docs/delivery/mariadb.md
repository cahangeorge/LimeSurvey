# MariaDB derivative artifact contract

This source phase replaces only `/usr/local/bin/gosu` in official native ARM64
MariaDB 11.4.13 Noble. Production and staging remain HOLD/PENDING respectively.
The reviewed plan in `docs/implementation-plan.md` owns the eighteen-file scope.
No deployment, existing database migration, host credential use or retirement is
part of this artifact gate.

The immutable parent is
`docker.io/library/mariadb@sha256:0130d92c05fbf2d82adc2b86de742eaede65b2596c65d91786f8e03cd19e6a39`.
The builder is Go 1.27.2 Alpine 3.24, index digest
`sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d`.
Unchanged gosu 1.19 source is `6456aaa0f3c854d199d0f037f068eb97515b7513`;
its archive SHA-256 is `33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b`.
The Dockerfile pins module versions/checksums, uses local toolchain, static ARM64,
`-trimpath`, `-ldflags '-d -w'`, `-buildvcs=false` and `-mod=readonly`.
Go omits linker flags from build metadata when `-trimpath` is set; the ELF
symbol table must remain present to reject `-s`, while the reviewed Dockerfile
binds the exact linker flags. The main module is `(devel)` because the source comes from an archive.
Compiler, exact dependency identities, binary hash, source pin and gosu version
remain mandatory. The Go 1.26 module directive compiled by Go 1.27.2 also
requires the exact build setting
`DefaultGODEBUG=tracebacklabels=0,x509sslcertoverrideplatform=0`; omitted, changed
or arbitrary compatibility defaults fail. Stripping with `-s` is forbidden.

The independent installed inventory uses dpkg and `go version -m` on the actual
final binary. It checks ELF64 ARM64 with no dynamic interpreter. Parent config,
non-wrapper labels, rootfs layer prefix and entrypoint hash remain unchanged;
only source/revision/version/component wrapper labels may replace parent labels. Only the final
gosu copy adds a layer. `buildinfo.json` binds the binary/compiler/modules.

Native `ubuntu-24.04-arm` CI verifies mysql/numeric identities, supplementary
groups, HOME, PID-preserving exec and failure statuses. The official entrypoint
initializes a fresh owned volume as root; readiness requires the final PID1
`/usr/sbin/mariadbd` with mysql UID plus SQL/official healthcheck, excluding the
entrypoint initialization shell and its temporary SQL server. A subsequent mysql-user container must
retain the synthetic row and table columns. Random synthetic passwords live only
in private mode-0600 temporary environment/client files. All process output is
captured, errors are generic, and no database output or stderr enters evidence.
Owned containers/volume are removed and absence verified before a PASS receipt.
A missing, failed, skipped or cancelled database job blocks the aggregate gate.

Trivy 0.75.0 is checksum pinned. Raw all-package candidate scan plus fresh database
metadata must pass before registry authentication. Exactly one Ubuntu 24.04 and
one gosu binary scan cover installed OS packages and Go compiler/dependencies.
Pinned Trivy 0.75.0 reports exactly four Go records: the archive-built root
`github.com/tianon/gosu` has no `Version` field and the exact versionless PURL
`pkg:golang/github.com/tianon/gosu`; stdlib and both dependencies retain exact
versions. This single root must have its exact ID/name, `Relationship=root`, and
three exact `DependsOn` IDs. The binary `(devel)` module, actual gosu 1.19,
source/archive pins, compiler/dependency metadata and binary hash bind its
identity. No synthetic version is inserted and no dependency may omit a version.
CycloneDX likewise preserves the versionless root library, exact PURL/bom-ref,
Trivy package ID/type properties and the three exact dependency PURL links.
Missing, duplicate or substituted roots/dependency links fail. The release
summary reports all four validated Go packages.
Package version/PURL coverage must agree; HIGH, CRITICAL, UNKNOWN, absent severity,
missing coverage and malformed evidence block. No ignore, VEX or ignore-unfixed
exception is allowed. The final digest is scanned independently, its installed
inventory compared, and full CycloneDX coverage checked.

`mariadb-release.yml` is a manual main-only publisher: protected exact main CI
preflight, one build/load, native regression, candidate scan, main recheck,
registry push, exact digest scan/SBOM, manifest and keyless signing/verification.
PR CI never publishes. Schema-1 `DATABASE_ARTIFACT_VERIFIED` manifests include
parent, build and regression identities and hashes for every evidence file.
The common seven evidence files remain mandatory; parent/build/regression and
candidate evidence are additional provenance dependencies.

The independent consumer is:

```sh
python3 scripts/ci/sign-release.py verify EVIDENCE mariadb SOURCE_SHA RUN_ID ATTEMPT
```

It requires `ghcr.io/cahangeorge/limesurvey-mariadb@sha256:…`, the exact
`mariadb-release.yml@refs/heads/main` certificate identity, GitHub OIDC issuer,
source SHA, publisher run, image signature, provenance and SBOM. Artifact success
does not prove the newly selected PHP/Nginx/MariaDB triple or operational staging.

Local acceptance commands (no container/network execution):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_mariadb_release_gate.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_signing_gate.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*gate.py'
git diff --check
```

Native builds, gosu/database regression and fresh scans remain UNKNOWN until
protected GitHub CI runs against the reviewed source.
