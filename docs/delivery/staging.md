# Strict artifact admission before operational staging

`staging-release.py` accepts only a trusted three-component PHP/Nginx/MariaDB
bundle. Its result establishes artifact admission and keeps
`staging_deployable=false`, production `HOLD`. Selected-triple runtime, mounted
configuration, application/DB/Chrome/persistence, backup/restore, migration,
promotion and rollback remain separate operational gates. The historical
MariaDB applicability disposition and frozen old Compose receipt cannot admit
the new bundle. No waiver is renewed and no archived timestamp is rewritten.

The accepted artifact build source is
`d35eafe8861b34b597b1640382854dadd82b39a5`; its upstream security policy pins
`c5a2ac817396220e054efc3fd26b84cafb92b36f` (7.5.0+261001). Publisher runs are
PHP `38091168439`, Nginx `38091739144`, MariaDB `38091169584`, attempt 1.
PHP, Nginx and MariaDB consumer proof is independent of later deployment
configuration source. The Nginx publisher companion smoke used historical FPM;
it does not prove this selected triple works together. Source-built PHP and
LimeSurvey application/bundled assets remain outside OS/Composer CVE coverage.

## Trusted bundle contract

Store this JSON privately outside Git. Supply its reviewed SHA-256 through an
independent trusted channel; computing a hash from an unreviewed candidate does
not establish trust. Schema version 1 requires `source_commit`,
`upstream_commit`, and exactly `components.php`, `components.nginx`,
`components.mariadb`. Each component requires:

- `evidence_directory`: absolute private directory with original publisher evidence.
- `release_sha256` and `signing_sha256`: SHA-256 of the original receipt bytes.
- `image`: exact repository plus `@sha256:` ARM64 leaf manifest identity.
- `image_config_digest`: exact tested image config identity.
- `release_run`: exact integer `id` and `attempt`.
- `evidence_sha256`: the complete original release raw evidence hash map.

The bundle selects identities explicitly, including source, run/attempt, release
receipt, config, raw manifest/inventory/scan/DB/SBOM/CI and candidate proof.
Missing coverage, substituted sources/digests/configs/runs, unsafe evidence
paths, missing signatures or HIGH/CRITICAL/UNKNOWN findings fail closed.
Every final/candidate scan `CreatedAt` and scanner database `UpdatedAt` and
`DownloadedAt` must be at most 24 hours old and at most five minutes in the
future, against the actual current UTC clock. Older proof requires a real new
scan/publisher acceptance path; editing timestamps invalidates signed evidence.

## Invocation and verification

```sh
python3 scripts/ci/staging-release.py \
  --expected-bundle "$EXPECTED_BUNDLE" \
  --expected-bundle-sha256 "$TRUSTED_BUNDLE_SHA256"
python3 -m unittest discover -s tests -p 'test_*gate.py'
git diff --check
```

The verifier requires the existing pinned Cosign executable on `PATH` and
read-only registry/Sigstore connectivity. It runs online `verify` and
`verify-attestation`, checking exact OIDC publisher/source, image digest,
provenance, run and SBOM through the existing signing helper. Only selected
hash-bound inputs are copied into an owned temporary directory; signing
verification can mutate that copy, never original publisher receipts. Temporary
copies are removed on success or failure. The command does not sign, push,
start services, deploy, write configuration, or authorize a production mutation.
An error emits a generic secret-safe `staging_release=HOLD` and exits 1.

Local regression proof uses real pure artifact validators and mocks only the
Cosign transport; this establishes rejection behavior, not fresh registry
verification or operational readiness. Run the CLI with the reviewed private
bundle for actual online admission evidence.

## Selected-triple staging operations

`deploy/staging.compose.yaml` is the single no-build adapter for admitted images.
All seven volumes and both networks are explicit external resources. The
helper rejects production manifests. Coolify application UUID is the exact
Compose project identity; `preserveRepository` stays enabled and the target
repository directory contains the SHA-pinned read-only Nginx bind source. Disable auto-deploy and select Coolify RAW Compose deployment
(`is_raw_compose_deployment_enabled=true`); the native parser adds an application
UUID network and `env_file` entries to every service, which violates these
private DB boundaries. RAW Compose permits only its three documented labels:
`coolify.managed=true`, `coolify.applicationUuid=PROJECT`,
`coolify.type=application`. Any unexpected runtime network fails inspection. App and DB have only the internal backend; Nginx has only the two
internal networks and a loopback-bound HTTP port. Staging Resend is disabled.

The operator owns Coolify API/deployment and SSH tunneling separately. This helper
contains no provider API, deployment command or arbitrary command interface.
Before preparation, preload the three exact admitted ARM64 images on the target.
Use a private 0600 manifest, independently reviewed hash and private evidence
files. Schema 1 adds these fields:

- `environment`: exactly `staging`; `project`: exact lowercase Coolify UUID.
- `configuration_commit`: exact target repository Git HEAD, independent of image build source.
- `adapter_sha256`: independently trusted SHA-256 of the committed
  `deploy/staging.compose.yaml` blob at that commit.
- `repository_root`, `nginx_sha256`, and integer loopback `port` (1024–65535).
- `images` and `config_digests`: exact `php`, `nginx`, `mariadb` identities.
- `volumes`: `db`, `upload`, `code`, `config`, `plugins`, `themes`, `runtime`.
- `networks`: `backend`, `frontend`.
- `state_file`: absolute private JSON path beside the manifest.
- `admission`: private `receipt`, `receipt_sha256`, `bundle`, `bundle_sha256`.

Volume names are `PROJECT-stage-KIND`; code/config/plugins/themes/runtime append
`-FULL_PHP_MANIFEST_HEX_DIGEST`. Network names are `PROJECT-stage-backend` and
`PROJECT-stage-frontend`. These names cannot reuse production resources.
Admission receipt must be at most one hour old, match the trusted bundle,
component identities and accepted upstream policy. Original raw evidence hashes
and scan/database freshness are rechecked on every operation. Use byte-identical target and local probe manifests, and mirror their protected
absolute admission/bundle/evidence paths. The local probe skips access to the
target repository directory and binds its configuration proof to the supplied
snapshot bearing that same manifest hash.

```sh
python3 scripts/delivery/operate.py stage --action prepare \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256"
# Apply returned secret-free adapter_environment through the controlled Coolify
# procedure; inject STAGING_DB_* secrets separately. Deploy through Coolify.
python3 scripts/delivery/operate.py stage --action initialize \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --credentials "$PRIVATE_ADMIN_JSON" --receipt "$BEFORE_SNAPSHOT"
python3 scripts/delivery/operate.py snapshot \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --receipt "$BEFORE_SNAPSHOT"
```

Preparation refuses all existing resource collisions, labels each owned
resource, records network IDs and volume creation identities, and seeds new
volumes from the exact PHP image using one network-disabled, root seed
container. Original image directories remain visible while destinations mount
under `/seed`; code/config/upload/plugins/themes/runtime bytes and ownership
are copied explicitly. The managed Resend plugin is included. The owned seed
container is removed after success. A failed operation preserves its resources
and private state. Never overlay old application defaults/cache onto new source.

Initialization requires three healthy, correctly mounted services, an actually
empty fresh database and absent `config.php`. Protected admin JSON contains
`admin_user` and `admin_password` (at least 24 characters). DB credentials remain
in runtime environment; admin credentials pass installer stdin, never OS argv
or environment. One PHP process decodes stdin, sets PHP-memory `$_SERVER['argv']`
and `$GLOBALS['argv']`, then requires the pinned console bootstrap in process.
No child process receives the private password in its command line. Command
output remains captured and failures emit the existing generic HOLD. The state records IDs before mutation, refuses repeat initialization and
proves schema 717 afterward. Existing production databases are never initialized
or migrated by this slice.

Before preparation, the actual checkout HEAD must equal `configuration_commit`,
and source adapter/Nginx bytes must equal their committed blobs and trusted
hashes. Runtime inspection requires a private owner-controlled 0600 target
`.env`. Set it before deployment and recheck its mode after Coolify writes it.
Coolify may normalize YAML and inject the exact three RAW labels into the source
adapter; therefore deployed adapter bytes need not remain byte-identical.

The helper renders the trusted Git adapter blob through an owned 0600 temporary
file, the working source adapter, and generated root `docker-compose.yaml` with
the same project directory and protected `.env`. Validated manifest adapter
variables override inherited or file-supplied `DELIVERY_*` values. All rendered
JSON fields must match, with only the exact three provider labels tolerated;
added networks, env files, commands or other runtime options fail closed. JSON,
private environment and credentials remain in memory, never emitted. The
snapshot records both configuration commit and adapter hash; local probes
require both to match the trusted manifest.

Snapshot checks literal mounted Nginx bytes plus `nginx -t`, image/config IDs,
exact mounts and read-only flags, network IDs/internal boundaries, disabled mail,
loopback-only ingress, healthy services and schema. Actual container inspection
also enforces `unless-stopped`, DB 1 GiB/1 CPU, app 512 MiB/1 CPU and Nginx
128 MiB/0.25 CPU. Entrypoint, command, user, working directory and stop signal
must retain the admitted image defaults; extra security options/cap drops and
changed healthcheck tests/timing fail closed. Private snapshot output may
be transferred to the local controller; pass its trusted hash to the probe.
Open an owned SSH tunnel to the target loopback port; local URLs must use
`http://127.0.0.1:PORT`. Local probing does not inspect laptop Docker.

```sh
python3 scripts/delivery/operate.py probe --phase before \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --url "$LOCAL_TUNNEL_URL" --credentials "$PRIVATE_ADMIN_JSON" \
  --snapshot "$BEFORE_SNAPSHOT" --snapshot-sha256 "$BEFORE_SNAPSHOT_SHA256" \
  --receipt "$PROBE_RECEIPT"
# On target, restart the three recorded container IDs and preserve a new snapshot.
python3 scripts/delivery/operate.py stage --action restart \
  --manifest "$MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --receipt "$AFTER_SNAPSHOT"
# Locally run the same probe arguments with --phase after and AFTER_SNAPSHOT.
```

The before probe authenticates a real admin browser, creates/imports the pinned
synthetic question via RemoteControl, completes the public survey through one
owned sandboxed Chrome for Testing context, and exports exactly one completed
response. The after probe requires restart proof, unchanged container/mount/
network/resource identities, admin browser acceptance and the same completed
export/response hashes. Private receipts and separate before/after screenshots
are 0600. The helper imports pure fixture/RPC/export/browser helpers only; it
never instantiates the disposable Roundtrip lifecycle or installs a browser on
the server. Locks are finite and refuse concurrent project operations.

`cleanup-stage` is an explicit operator command: it verifies ownership and
recorded IDs before removing owned resources. Unknown containers or ownership
changes preserve the failed state. No implicit cleanup or production teardown
is performed. All local tests use synthetic evidence and mocked Docker/transport;
actual target preparation, runtime/browser/persistence proof remain required.

## PR 13 review remediation evidence

Offline targeted operational tests: 30 PASS, preserving the prior 25 cases and
adding source HEAD/blob/hash tamper rejection, exact RAW-label-only rendered
comparison, rejection before runtime inspection, runtime option/resource
mutation rejection, and stdin-only administrator bootstrap proof. Complete gate
suite: 137 PASS. `git diff --check`: PASS. No target runtime, deployment,
credential, commit or registry mutation was performed for this remediation.
Actual staging proof remains HOLD until the protected branch includes the fix
and the independently reviewed adapter/runtime path is executed.


## Finite paired recovery controller

The additional target-side commands are `rehearse`, `promote`, and
`legacy-rescue`, each requiring `--plan "$PRIVATE_PLAN" --plan-sha256
"$PRIVATE_PLAN_SHA256"`. The protected JSON plan and evidence are owned 0600;
the new transaction directory is 0700. All commands take the same stable
`/var/lock/limesurvey-<application_uuid>.lock`, independent of image/release/state
path. Never run a parallel Coolify deployment or use its stop-before-hook job.
No command sends email or certifies runtime from offline tests.

Plan version 1 contains these fields (paths refer to protected local target
files; do not publish the files):

| Fields | Binding |
| --- | --- |
| `application_uuid` | Existing selected production app, never a new production app |
| `legacy_inspect`, `legacy_inspect_sha256` | Exact original three containers, images, mounts, environments and networks |
| `trusted_proxy` | Exact live proxy metadata: `Id`, actual Docker image-ID `Image`, `Name`, `compose_project`, `compose_service`; only `/coolify-proxy` in project `coolify-proxy`, service `traefik` |
| `legacy_compose`, `legacy_compose_sha256` | Server-only expanded private Compose JSON; preserve routes/environment, remove build |
| `candidate_manifest`, `candidate_manifest_sha256` | Fresh isolated restore resources and current admitted triple; includes reviewed B configuration bindings |
| `accepted_stage_manifest`, `accepted_stage_manifest_sha256`, `accepted_stage_receipt`, `accepted_stage_receipt_sha256` | Same triple/config and completed staging persistence proof |
| `provider_receipt` | Fresh existing-app auto-deploy OFF, no running/queued jobs, background writers absent |
| `directory`, `state_file` | New transaction directory and state, both siblings of plan |
| `ack_timeout` | Bounded controller acknowledgement timeout, 30–1800 seconds per step |
| `custom_plugins`, `custom_themes`, `operator_config_files` | Explicit reviewed basenames, excluding old application defaults |
| `rehearsal_receipt`, `rehearsal_receipt_sha256` | Required for promote: completed rehearsal state, same app/images/config, synthetic recovery PASS |

Provider receipt fields are `application_uuid`, `auto_deploy:false`,
`running_deployments:[]`, `queued_deployments:[]`,
`background_writers_absent:true`, and current `checked_at`. It is checked before
backup and immediately before production replacement. Artifact admission and
scan clocks remain real; never rewrite them to extend readiness.

The helper checkpoints private state and waits for fixed acknowledgement files
in `directory`. Every acknowledgement contains `transaction_id`, SHA-256 of
the current raw `state_file` as `state_sha256`, and UTC `checked_at` (at most ten
minutes old, five minutes future). The controller reads state, completes the
actual operation/browser checks and atomically writes the owned 0600 JSON file:

| File | Required actual proof |
| --- | --- |
| `offhost.json` | `status:OFFHOST_HASH_VERIFIED`, exact `sha256` mapping for database.sql/files.tar.gz, different machine-id SHA-256 `destination_host_id` |
| `restore-proof.json` | `status:RESTORE_FUNCTIONAL_PASS`, admin/public/persistence PASS, exact original `security_sha256`, default_theme_options PASS |
| `recovery-proof.json` | Same actual proof after synthetic bad config, paired 712 restore and migration |
| `production-proof.json` | `status:PRODUCTION_CORE_PASS`, https/admin/public/persistence PASS, ordinary_requests_fenced PASS, exact candidate `images`, original security_sha256; optional explicit mail_delivery PASS or UNKNOWN |
| `production-open-proof.json` | `status:PUBLIC_HEALTH_PASS`, actual https PASS after canonical nginx replacement |
| `legacy-proof.json` | `status:LEGACY_RESCUE_FUNCTIONAL_PASS`, actual admin/public/persistence PASS and original security_sha256 |

During production proof, load the generated `fence-token.private.json` only
into an owned browser request route as `X-LimeSurvey-Delivery-Token` only for
the exact approved HTTPS origin (scheme, hostname and port). Strip this header
from every other origin and reject unexpected top-level redirects. Do not set
a global context header that could leak the token to third-party resources or
redirects. It is absent from command lines. Independently
prove ordinary no-header requests receive 503, then use real HTTPS/admin/public
and restart/export persistence evidence for the controlled browser. The helper
retains the fenced configuration's separate hash. Normal `/healthz` is static
and never authorizes a DB write. Publication replaces the bind with the exact
canonical file and only recreates nginx. `public_unfenced` is recorded before
this operation and permanently excludes legacy rescue for that attempt.

`rehearse` resumes original traffic after the off-host backup proof and runs the
isolated fault/paired recovery. `promote` keeps production writers withdrawn
through the new backup, isolated migration and controlled production proof.
Failures preserve resources/logs and attempt to stop both isolated and
production writers; inspect `fence_stop_verified` before recovery. Failed owned
updater containers remain stopped with protected logs. Legacy rescue is allowed
from the hash-bound original pair even when candidate admission expires; it
never reports security PASS. Actual runtime checks, off-host transfer and browser
acknowledgements are controller evidence, not results of these offline tests.

The legacy backup topology may include the existing provider proxy on the
original networks. The plan pins its complete container/image ID and exact
name/project/service; the helper independently verifies that live identity.
Only the three recorded legacy services plus that exact proxy may be network
members. An additional container or substituted proxy blocks backup. This
exception authorizes no proxy or global-network mutation.

Promoted MariaDB joins only the recorded owned internal candidate backend,
without published ports or foreign members. Production Compose declares this
external owned network as `delivery-private`; app joins it in addition to its
original route/egress networks. Nginx retains its original networks and route
labels. Runtime inspection requires these exact sets and the recorded private
network ID. The legacy shared-provider DB topology is never copied to the new
production DB.
