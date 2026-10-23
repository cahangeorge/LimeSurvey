# Existing OCI Nginx maintenance preflight

This adapter admits one signed Nginx component for an existing fresh-OCI
installation. It never creates a container, edits an environment file, recreates
a service or authorizes a completed production release. The original
`staging-release.py` three-component gate and `fresh.py` empty-target gate retain
their contracts.

The operator must separately review the current installation, the signed Nginx
release and rollback reference. A private SHA-256-pinned manifest is the trust
anchor for those reviewed observations. Never commit this manifest, environment
files, Docker inspect output, proxy configuration or release evidence. Inspect
and rendered Compose include secrets; hash them in memory and keep private files
mode 0600. Hashes are not a substitute for reviewing the original observation.

## Trusted gate execution

Gate source and image build source are separate identities. Independently review
and accept a clean gate commit containing this adapter and its transitive
validators. Supply that commit separately as `--gate-commit`; the private manifest
must bind the same `gate_commit`. Never derive the gate commit from candidate
image evidence. The CLI checks the clean source checkout and compares all six
local gate/validator files with that Git commit **before** importing any local
validator. This internal check alone cannot make an altered entrypoint trusted.

The required external bootstrap below first checks the reviewed checkout, then
executes only its Git archive in a new owned directory. The initial checks run
before any repository Python executes. Python isolated mode excludes inherited
module paths and the current directory; bytecode writing is disabled. The
archive contains no untracked or ignored checkout files. The operator owns the
shell command and fills the reviewed values independently; executing the CLI
directly from a mutable checkout is unsupported.

```bash
set -euo pipefail
gate_repo=/absolute/clean/reviewed/checkout
gate_commit=REVIEWED_40_CHARACTER_GATE_COMMIT
maintenance_manifest=/absolute/private/maintenance.json
maintenance_sha256=REVIEWED_MANIFEST_HASH
[[ "$gate_commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$(git -C "$gate_repo" rev-parse HEAD)" == "$gate_commit" ]]
[[ -z "$(git -C "$gate_repo" status --porcelain --untracked-files=all)" ]]
gate_archive=$(mktemp -d)
trap 'rm -rf -- "$gate_archive"' EXIT
git -C "$gate_repo" archive --format=tar "$gate_commit" | tar -xf - -C "$gate_archive"
env -u PYTHONPATH -u PYTHONHOME python3 -I -B \
  "$gate_archive/scripts/delivery/nginx-maintenance.py" \
  --gate-repository "$gate_repo" --gate-commit "$gate_commit" \
  --expected "$maintenance_manifest" --expected-sha256 "$maintenance_sha256"
```

## Ordered preparation

1. Independently verify the candidate publisher's successful main-only workflow,
   exact source commit, immutable image, release/signing receipts and raw evidence
   hashes. Retain the evidence directory outside Git. The preflight invokes the
   existing `staging-release.component` validator including current strict scans,
   coverage, provenance/SBOM and online Cosign verification. It does not accept a
   release because a local receipt merely claims PASS.
2. Under the existing operation lock, capture the exact production project,
   rendered Compose, app/DB/Nginx IDs, start times, restart counts, configuration,
   networks, volumes and actual proxy container/configuration. Preserve the
   currently running immutable Nginx digest as rollback. Prepare a second private
   environment file changing only `OCI_NGINX_IMAGE`; the final rendered Compose
   must differ only at `services.nginx.image`. The host checkout/adapter and
   mounted configuration are separate identities from the candidate build source.
   Compose's freshly calculated `config --hash '*'` values for all three services
   must equal the live `com.docker.compose.config-hash` labels. This prevents a
   reviewed hash of a hypothetical old Compose file from admitting live drift.
   The adapter also maps the Nginx rendered mounts, networks, loopback port,
   root filesystem, tmpfs, limits and restart policy directly to Docker inspect;
   unsupported rendered service keys fail closed. Docker resource controls omitted
   by Compose must also retain defaults: PID/swappiness overrides, additional CPU,
   block I/O, device, cgroup, ulimit and OOM adjustments are rejected on production
   and canary containers. Null command/entrypoint values
   resolve against the pinned local image defaults.
3. An explicitly authorized operator creates a disposable, separately owned
   canary from the admitted digest. Give it exactly the production Nginx mounts,
   the production application network, no proxy network, no host port, no DNS or
   host override and only `traefik.enable=false` routing labels. Its entrypoint
   and command must equal production. Keep root, code and bind mounts read-only;
   allow only the existing Nginx cache/run tmpfs. Do not attach Compose project
   labels that make it part of the live three-service project. The canary can
   issue normal unauthenticated GETs to the live app; never submit a survey,
   initialize an installer or run a migration. Creation/cleanup are not performed
   by this CLI. Retain a private cleanup record for this owned resource. PID/IPC
   namespaces must be private, network mode must be the actual application
   network, and unconfined security options are rejected. Set the same reviewed
   CPU/memory/swap limits and tmpfs as production; unlimited resources fail.
4. Capture and review the manifest below after canary creation. Network hashes
   include its endpoint, so creating/removing it invalidates a prior snapshot.
   Run preflight within 15 minutes. Docker and Git command probes have 120-second
   timeouts; the existing Cosign transport allows 180 seconds. The preflight
   rejects a total check exceeding five minutes. If signatures/scans expire,
   obtain new legitimate evidence rather than editing timestamps. Re-capture
   observations after any runtime/configuration change.

## Private manifest contract

All `sha256` fields are lowercase SHA-256 hex without a prefix. Container IDs are
full 64-character IDs. `source_commit` is the candidate's 40-character build
commit; it need not equal the unchanged app/DB build commits. No credentials are
included in the manifest itself. Its trusted outer hash must be supplied through
an independently reviewed command, not read from the same untrusted file.

```text
schema_version: 1
observed_at: current UTC ISO-8601 timestamp
project: reviewed existing ls-oci project
source_commit: reviewed candidate build commit
gate_commit: independently reviewed gate/validator source commit
adapter: absolute existing OCI Compose path
current_env: absolute mode-0600 current environment file
candidate_env: absolute mode-0600 proposed environment file
compose_sha256: fingerprint(current rendered Compose JSON)
rollback_image: exact current immutable Nginx repository@sha256:digest
files_sha256: {absolute adapter, mounted Nginx config and proxy config paths: byte hash}
proxy_config: absolute dynamic configuration path used by the actual proxy
proxy_container: {id: actual proxy ID, sha256: container_fingerprint(inspect)}
containers:
  app: {id: actual app ID, sha256: container_fingerprint(inspect)}
  db: {id: actual DB ID, sha256: container_fingerprint(inspect)}
  nginx: {id: actual Nginx ID, sha256: container_fingerprint(inspect)}
volumes: {every rendered Compose volume name: fingerprint(docker volume inspect object)}
networks: {every rendered Compose network name: fingerprint(docker network inspect object)}
canary:
  id: actual disposable candidate ID
  sha256: container_fingerprint(inspect)
  nginx_config_sha256: byte hash of successful docker exec CANARY nginx -T stdout
candidate:
  evidence_directory: absolute private candidate evidence directory
  release_sha256: byte hash of release.json
  signing_sha256: byte hash of signing.json
  image: signed immutable Nginx reference
  image_config_digest: signed registry manifest config digest
  release_run: {id: reviewed publisher run, attempt: reviewed attempt}
  evidence_sha256: exact raw evidence map from the reviewed release receipt
```

Use the script's `fingerprint` and `container_fingerprint` functions to compute
canonical hashes. `fingerprint` is SHA-256 over UTF-8 `json.dumps(value,
sort_keys=True, separators=(',', ':'), ensure_ascii=True)`. Docker inspect returns
an array; hash its single object. `container_fingerprint` hashes Id, Name, Image,
Config, HostConfig, Mounts, RestartCount, State.StartedAt and
NetworkSettings.Networks. It excludes changing healthcheck logs but separately
requires healthy live app/DB/Nginx/canary services. The actual proxy must be
running, match its reviewed fingerprint, join the intended proxy network and
mount the pinned proxy configuration's parent or file.

The candidate local image's RepoDigests must contain the signed immutable
reference and its Docker Id must equal the canary's Image. This allows Docker's
config/manifest ID representation to vary while the existing component validator
independently checks the signed registry manifest's config digest. Only the live
app ID may own the `app` alias on the application network. The entire output of
`nginx -T` must equal production, and its hash must match the private manifest.
A private GET through the canary to the LimeSurvey admin login must succeed and
contain the login form. A static health endpoint alone cannot pass. Only the
response hash is emitted; the body and transient CSRF/session values are discarded.

Run the external trusted-source bootstrap above with this manifest and its
independently reviewed hash.

A successful result is `NGINX_MAINTENANCE_PREFLIGHT_PASS` with `production: HOLD`.
It binds a short-lived observation and is not a durable deployment permission.
The script repeats Compose, all production/proxy/configuration/resource
fingerprints and both canary health and fingerprint after probing. It cannot prevent a
concurrent change after exit; the operator must retain the same operation lock
and verify these conditions immediately before replacement.

## Operator replacement, verification and rollback

After independent source review, fresh successful preflight and the existing
production authority, use the exact reviewed adapter and candidate environment
with `docker compose up -d --no-deps --no-build --pull never nginx`. Never invoke
`fresh.py` or recreate app/DB for this maintenance. Keep the service/container
name and application/proxy networks, host probe port, proxy route, volumes,
configuration and app/DB identities unchanged. Retain the rollback image locally
before starting. Do not delete any persistent resource.

Capture the new Nginx immutable image, healthy state and version; recheck the
unchanged app/DB IDs/start times and resource/configuration hashes (allow only the
expected old/new Nginx network endpoint change). Verify private health/FastCGI,
public HTTPS, authenticated admin login and an existing public survey route in
sandboxed Chrome. Inactive real surveys must remain inactive; use an already
approved disposable fixture for any response test. Clean up the owned canary and
check no temporary resources remain. Record the exact receipts and observations
privately. Preflight success alone does not establish these post-change results.

If checks fail, recreate **only Nginx** with the pinned original environment and
rollback digest using the same one-service command. Recheck healthy routing,
HTTPS/admin/public behavior and unchanged app/DB identities. This component
change performs no application/schema migration. Preserve evidence of a failed
candidate and report unresolved rollback checks; never claim rollback from the
command exit status alone.
