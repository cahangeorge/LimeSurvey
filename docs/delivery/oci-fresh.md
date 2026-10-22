# Fresh OCI installation

The user decision on 2026-10-22 discards existing OmneStack **LimeSurvey** data
and authorizes a new empty OCI installation without a LimeSurvey backup or
restore. This overrides the LimeSurvey cross-host recovery prerequisite for
this installation only. Formbricks and unrelated services retain their existing
requirements. `crosshost.py` is not used by this path.

`deploy/compose.oci-fresh.yaml` uses only the three admitted ARM64 release image
digests. It has no build, restore, import or migration command. Docker initializes
seven dedicated new named volumes; the installer then creates the new database.
The gate refuses any existing target project container, target volume or private
network, even an empty one. Use a new `ls-oci-…` project name; never point this
adapter at old data. The gate is for first installation, not subsequent restarts.

Only Nginx joins the existing external proxy network. Nginx and PHP share one
internal application network; PHP and MariaDB share a separate internal database
network. MariaDB has no published port and cannot be reached directly by the
proxy network. PHP also joins a normal outbound bridge for Resend HTTPS access;
this enables egress and does not implement a destination/port firewall. The
sole host port is a required unprivileged loopback probe port on Nginx. All
application data mounts in Nginx are read-only.

Keep these variables in an operator-owned, non-symlink file with mode `0600`:

- `OCI_PROJECT`, `OCI_PROXY_NETWORK`, `OCI_PROBE_PORT`;
- `OCI_APP_IMAGE`, `OCI_NGINX_IMAGE`, `OCI_DB_IMAGE`, each copied exactly from the
  expected admitted bundle as `ghcr.io/cahangeorge/…@sha256:…`;
- `OCI_DB_NAME`, `OCI_DB_USER`, `OCI_DB_PASSWORD`, `OCI_DB_ROOT_PASSWORD`;
- `OCI_RESEND_API_KEY`, `OCI_RESEND_FROM_EMAIL`, optional `OCI_RESEND_FROM_NAME`.

Generate new credentials through the approved secret workflow. No old survey,
response, user, upload or encryption configuration is copied. Keep the selected
expected bundle and its externally trusted SHA-256 in protected local storage.
The preflight invokes the existing `staging-release.py` evaluator directly,
including current scan coverage, exact-source provenance and online Cosign
verification for each image. A digest string or an archived receipt alone cannot
pass. Existing signed artifact evidence is required; this adapter does not
publish artifacts or weaken protected-main release requirements.
The checkout HEAD must equal the admitted source commit and tracked files must
be clean. The Nginx configuration, fresh Compose file and preflight script must
match their committed bytes.

Run on the intended OCI Docker host from the reviewed repository checkout:

```sh
python3 scripts/delivery/fresh.py \
  --env-file /protected/oci-fresh.env \
  --expected-bundle /protected/expected-bundle.json \
  --expected-bundle-sha256 "$TRUSTED_BUNDLE_SHA256"
```

Success prints only `fresh_install_preflight=PASS; public routing and runtime
acceptance pending`. Failure suppresses Compose, signature-tool and Docker
output because rendered configuration contains secrets. This is a read-only
check; it creates no Docker resources and is not runtime acceptance. Fix a HOLD
before deployment. Re-run immediately before initial creation, with no concurrent
operator or changes to inputs. Use the same protected file and adapter without
overrides; inherited `OCI_*` variables must be absent for the deployment command
as they are explicitly removed by the preflight renderer. Do not print or save
unprotected rendered Compose JSON.

The operator may then start the selected images using `docker compose` with this
adapter, the same protected env file, `--no-build` and `--pull never` after pulling
and verifying the admitted images. The adapter deliberately sets
`traefik.enable=false`; it must not expose an unauthenticated installer. Complete
initialization and private admin login through the loopback probe endpoint or a
secure tunnel. Verify the managed Resend plugin, synthetic survey submission and
export, restart persistence and final delivered Resend event. Only then add the
reviewed proxy file route to Nginx port 80 and verify public DNS, HTTPS and the
full browser flow. The Nginx `/healthz` check alone does not prove PHP/database
or survey acceptance.

The fresh path does not delete the old service. After target acceptance, the
operator must disable the old LimeSurvey Coolify application/deployment records,
then remove only the reverified LimeSurvey containers, volumes, networks and
dedicated paths authorized by the user. Preserve shared proxy containers,
certificates and unrelated services. No rollback of discarded source data is
promised.

Local verification for this adapter:

```sh
python3 -m unittest discover -s tests -p test_fresh_delivery_gate.py -v
git diff --check
```

The unit suite uses synthetic normalized Compose data and mocked read-only
Docker inventory. CI also renders the actual fresh Compose with synthetic
values. A real Docker Compose render on OCI and live application,
egress, TLS and persistence acceptance remain operator checks.
