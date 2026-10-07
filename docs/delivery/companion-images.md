# Nginx companion validation

The PHP application release and the Nginx/MariaDB services are separate artifacts.
The verified application is promoted by digest; adding a companion recipe does
not rebuild or promote that release automatically.

`docker/nginx/Dockerfile` retains the immutable official Nginx1.30.5 Alpine3.24
base and its entrypoint/modules. It upgrades exactly libexpat2.8.5-r0,
libpng1.6.59-r0 and pcre2 10.49-r0 to address the corresponding reported package
findings. Repository updates can change dependency resolution despite the base
pin; installed inventory and the resulting image identity must be validated.
Do not substitute another Alpine branch, disable signature verification or
silently accept unavailable package versions.

Local recipe and proxy canary:

```sh
docker build --pull -f docker/nginx/Dockerfile -t limesurvey-nginx:canary docker/nginx
export NGINX_IMAGE=$(docker image inspect limesurvey-nginx:canary --format '{{.Id}}')
export FPM_IMAGE=$(docker image inspect <existing-tested-FPM-image> --format '{{.Id}}')
./tests/nginx-security-smoke.sh
```

The test requires full local image IDs, uses `--pull=never`, synthetic files,
an internal network, read-only containers and no host ports. It proves health,
static serving, FastCGI PATH_INFO/HTTPS/proxy behavior, seven protected paths and
unexpected PHP denial. Cleanup must succeed before PASS. It neither starts a
database nor proves LimeSurvey application acceptance.

The existing mandatory native ARM64 CI job additionally builds this Nginx
candidate, inventories its APK database, scans the exact exported image with
checksum-pinned Trivy0.75.0 and requires complete package/version coverage,
matching image/OS/platform, fresh DB and zero HIGH/CRITICAL/UNKNOWN. LOW/MEDIUM
findings remain visible. The proxy test uses the FPM image already built by that
job. Native evidence is preserved for30days; no registry-write/deployment
permission is introduced. AMD64 canary results do not satisfy this ARM64 gate.

The separate manual `.github/workflows/nginx-release.yml` route targets
`ghcr.io/cahangeorge/limesurvey-nginx`. Only a trusted repository/main dispatch
on native ARM64 can run it. It checks protected main and the newest successful
exact-source `release-gate.yml` push CI before building and immediately before
publication. Nginx is built once from `docker/nginx/Dockerfile`; source, revision,
component and version labels are added by the build command. The existing PHP
release workflow remains PHP-only.

The proxy smoke pulls only the approved FPM reference
`ghcr.io/cahangeorge/limesurvey@sha256:4193d1c9bef626c675381fe2bad07b400bcf5cce56e373c221babae2ce9d3510`.
Its raw manifest hash, config
`sha256:ecad9df832a2f9e20585922ece061d2527f117a9436c8271ca27efe33c1fb4da`,
ARM64 platform and source `58de3e047274976775a726fe4b21d879ba7a7844`
are validated before smoke. That artifact was accepted by release run
37186347292/attempt1; this route does not rebuild or republish PHP.

`scripts/ci/nginx-release.py` reuses the existing pure CI preflight, APK parsing
and DB freshness helpers, with separate Nginx-specific identity validation. The
candidate's independent installed APK inventory must match its complete exported
image scan, including the three exact patched versions. Trivy0.75.0 is pinned by
its ARM64 archive checksum. DBv2 must be updated within48hours and downloaded
within24hours, with at most5minutes of future clock skew. Alpine3.24.2 and no EOL
flag are required. HIGH, CRITICAL, UNKNOWN and malformed severities block
publication; LOW/MEDIUM remain in retained findings. No ignore/config file,
ignore-unfixed or severity suppression is used.

Only after the candidate scan passes does the workflow authenticate in an owned
ephemeral Docker configuration and push. It retains that authentication for
private-package verification and removes it on exit. It re-pulls the registry
digest and checks exact tested config parity, raw manifest hash/config,
platform/provenance and complete package/version coverage in the final scan.
CycloneDX1.7 is converted from that same final JSON and must bind the same image
and cover every scanned APK with a unique library component whose name, full
version, PURL and bom-ref agree. APK PURLs require matching decoded package
identity and exactly arch=aarch64/distro=3.24.2 qualifiers. The scan target must
match its artifact reference followed by `(alpine 3.24.2)`. Evidence is uploaded for30days even on
failure; tokens, auth configuration and exported image archives are excluded.

The final `release.json` binds source/run/attempt, both tested local config IDs,
FPM reference, source CI, smoke, inventory, raw manifest, scans, DB and SBOM
checksums. Registry manifest digest and image config digest are separate fields.
For a syntactically valid `manifest` invocation, the validator removes a
previous final manifest before validating a reused directory. Argument-parser
errors do not enter evidence validation; the workflow uses a clean owned directory. It creates `COMPANION_ARTIFACT_VERIFIED` only after every check passes,
with staging `PENDING` and production `HOLD`.

Local offline verification:

```sh
python3 -m unittest discover -s tests -p 'test_*gate.py'
python3 scripts/ci/nginx-release.py --help
```

Publication execution and a native registry artifact remain unverified until
separately authorized source integration and the first manual dispatch. Compose
still does not consume this companion. Staging needs a separately reviewed
configuration using exact PHP/Nginx digests, MariaDB resolution, and deployment
approval. The proxy smoke does not initialize a database or prove LimeSurvey,
backup/recovery, migrations or production acceptance.

MariaDB/gosu findings require exact binary, toolchain, platform and CVE database
coverage for reachability analysis. Keep raw scanner results and distinguish
module matches from affected functions. The current CI policy has no waiver
mechanism; analysis alone does not bypass the severity gate. Any proposed
exception needs its exact scope, owner, expiry and reviewed implementation.
See [gosu security policy](https://github.com/tianon/gosu/blob/6456aaa0f3c854d199d0f037f068eb97515b7513/SECURITY.md)
and [Go vulnerability analysis](https://go.dev/doc/security/vuln/).
