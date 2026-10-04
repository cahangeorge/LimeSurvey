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

Neither Compose nor the release publication route consumes this new companion
yet. Integration/publication must bind a tested native image to its final
registry digest before staging can use it. Existing production stays at its
current configuration until separately authorized.

MariaDB/gosu findings require exact binary, toolchain, platform and CVE database
coverage for reachability analysis. Keep raw scanner results and distinguish
module matches from affected functions. The current CI policy has no waiver
mechanism; analysis alone does not bypass the severity gate. Any proposed
exception needs its exact scope, owner, expiry and reviewed implementation.
See [gosu security policy](https://github.com/tianon/gosu/blob/6456aaa0f3c854d199d0f037f068eb97515b7513/SECURITY.md)
and [Go vulnerability analysis](https://go.dev/doc/security/vuln/).
