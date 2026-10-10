# Local synthetic staging candidate

This recipe joins the existing verified ARM64 PHP and Nginx releases with the
exact reviewed MariaDB 11.4.13 Noble artifact. It performs no build, publication,
provisioning or database operation. A successful local gate returns
`LOCAL_STAGING_CANDIDATE_WITH_ACCEPTED_DISPOSITION` and
`staging_deployable: false`. Production remains `HOLD`.

## Fixed components and evidence

| Component | Source / run | Immutable registry identity |
| --- | --- | --- |
| PHP | `58de3e047274976775a726fe4b21d879ba7a7844`, run `37186347292/1` | `ghcr.io/cahangeorge/limesurvey@sha256:4193d1c9bef626c675381fe2bad07b400bcf5cce56e373c221babae2ce9d3510` |
| Nginx | `2b7abac451afb0ce74aae735fe8b62d5ce171b41`, run `38053603034/1` | `ghcr.io/cahangeorge/limesurvey-nginx@sha256:a8eeb20f935ef074537bdafe1151dae2892ce381f97305edc448af1647a061f4` |
| MariaDB | official 11.4.13 Noble, upstream `bdfe641466a5312bb97d06a1a4e1fb411c49e6b6` | `docker.io/library/mariadb@sha256:0130d92c05fbf2d82adc2b86de742eaede65b2596c65d91786f8e03cd19e6a39` |

The helper pins the independently accepted release manifest hashes and verifies
all referenced evidence bytes. Original PHP provenance/inventory/SBOM are checked
against its fresh exact-digest scan; Nginx uses the current replacement release
scan/SBOM and native proxy test evidence. These checks use the current clock and
hold when scans or DB metadata age out. Neither artifact is rebuilt here.

Private evidence root layout (never commit operational records):

```text
release-evidence-37186347292-1/       # original PHP release bundle
nginx-tiff-publication-20261010/release-evidence/ # replacement Nginx release bundle
published-readiness-20261010/
  mariadb-30-disposition.proposed.json # immutable reviewed proposal, retained as draft
  app-scan.json / app-scan-db.json
  db-scan.json / db-scan-db.json
  db-live-manifest.json / db-live-index.json
  go-record-refresh.json
  go-records/GO-*.json
  applicability/                    # four bounded source/binary result streams
staging-preflight-20261007/noble-installed-inventory.json
```

The proposal lists its exact CVE/package/version/severity/Go-ID tuples and
reviewed evidence hashes. Its SHA-256 is pinned in the helper. The separately
accepted private authority record has `status: ACCEPTED`, `owner: gion`,
`scope: isolated-synthetic-staging`, the same `proposal_sha256`,
`review_at: 2026-10-11T12:00:00Z`, and `expires_at: 2026-10-14T18:00:00Z`.
Keep the actual human acceptance and provenance with that private record.
This is a new, explicitly approved 30-finding disposition; it does not rewrite or
renew the archived 23-finding authority. The pinned proposal SHA-256 is
`9841ff3bccd351a02202fb809eb902908267f87c827ae443c8c905cf85b7ea02`.

The **operator-provided, previously trusted authority hash is the trust root**.
This is a tamper-evident local check, not a signature or an independent identity
service. Do not derive the trusted hash from an unreviewed replacement JSON file.
Changing a JSON status field alone does not grant authority. The preserved draft
proposal is not rewritten to simulate an approval.

## Bounded MariaDB disposition

The raw Trivy result remains **FAIL: 30 blocking findings in
`usr/local/bin/gosu`**, 1 CRITICAL, 24 HIGH and 5 UNKNOWN. Four bounded
source/binary analyses
with govulncheck 1.8.0 and 1.1.4 found no affected functions for these exact
records; both versions belong to the same scanner family. Thirty-four official
Go records remain visible, with only the 30 current blocking tuples accepted;
this does not establish zero risk. Only those exact tuples on the fixed
leaf/config/gosu hash are accepted for isolated staging with synthetic data and
blocked external egress. OS findings and all unlisted findings retain strict
gates. There is no global ignore, VEX masking, `ignore-unfixed`, or production
exception.

Missing acceptance, review due, expiry, changed artifact/Go record, missing or
duplicate package/CVE coverage, stale scan/DB/Go refresh, or altered Compose
configuration returns HOLD. Review due on October 11 at 12:00 UTC also holds
even though the hard expiry is October 14; neither date is automatically extended. DB updates
must be at most 48 hours old, downloads/scans/Go refresh at most 24 hours old,
with at most five minutes of future clock skew.

This local recipe pins the reviewed October 10 scans, original installed DB
inventory, current DB metadata, and refreshed Go records. When evidence ages
out, a fresh review and bounded recipe update are required. Do not edit timestamps to make old evidence
appear fresh. The local report is not a reusable deploy authorization.

## Configuration-only commands

Use the actual target Docker Compose provider for parsing, or its separately
validated identical version. The last verified target parser is Compose 5.4.0.
The separately checksum-verified local official 5.4.0 parser reproduces its
archived baseline output; the candidate
changes only the Nginx digest. Recheck the actual provider before runtime use.
Local Podman Compose output is not equivalent evidence. The following command only
parses YAML with fictive inputs. It starts no services, writes no remote files,
and uses no deployment credentials:

```bash
env STAGING_DB_NAME=cicd_synthetic STAGING_DB_USER=cicd_synthetic \
  STAGING_DB_PASSWORD=synthetic_parse_only \
  STAGING_DB_ROOT_PASSWORD=synthetic_parse_only_root \
  STAGING_RESEND_API_KEY=synthetic_disabled \
  STAGING_RESEND_FROM_EMAIL=staging@example.invalid STAGING_RESEND_FROM_NAME=Staging \
  docker compose --env-file /dev/null --project-directory /tmp \
  --project-name limesurvey-ci-staging --file - config --format json \
  < deploy/staging.compose.yaml > "$STAGING_PRIVATE/rendered.json"

PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/staging-release.py \
  --evidence-root "$STAGING_EVIDENCE_ROOT" \
  --authority "$STAGING_PRIVATE/authority.json" \
  --authority-sha256 "$STAGING_TRUSTED_AUTHORITY_SHA256" \
  --compose deploy/staging.compose.yaml \
  --rendered "$STAGING_PRIVATE/rendered.json" \
  --nginx-config docker/nginx/default.conf

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*gate.py'
git diff --check
```

Set the three `STAGING_*` path/hash variables from the private accepted handoff.
Use a new private capture for each invocation and check exit status; the helper
prints a candidate JSON only on success and never writes an eligible manifest.
It has no configurable clock override or command to start containers. Old output
files, `x-readiness`, and a successful Compose parse grant no execution authority.
The fixed rendered JSON hash binds all synthetic input values and all provider
configuration keys. `x-readiness` is an informational extension ignored by
Compose and excluded from that semantic hash; source YAML bytes are pinned too.

## Runtime gates still pending

The recipe declares both networks internal, no host ports/builds/bind mounts,
seven project-scoped volumes, and resource ceilings: DB 1 GiB/1 CPU, PHP
512 MiB/1 CPU, Nginx 128 MiB/0.25 CPU. These are static boundaries, not proven
runtime isolation or load capacity. PHP-FPM syntax/process health and Nginx
`/healthz` are not complete LimeSurvey/database acceptance.

Before separately authorized staging execution:

1. Refresh exact-digest scans, Go records and host headroom. Re-evaluate any new
   finding and the disposition; preserve raw reports. Confirm memory reserve,
   disk/inodes and existing-service identities on the selected Coolify server.
2. Review the Coolify Compose adapter, separate staging environment/application,
   private ingress/route, synthetic secrets and clean volume namespace. Verify
   that no existing/production volume, network, domain or Formbricks service is
   reused. The image-specific code volume must be fresh and prove PHP code identity.
3. Obtain explicit provisioning and synthetic DB/admin initialization authority
   against the concrete runtime plan. Credentials stay in protected runtime
   variables. Never reuse parse-only passwords or production data/credentials.
4. Prove actual network egress denial, mounted Nginx byte hash and `nginx -t`.
   The image does not carry the app-specific default.conf. The target parser
   retains `$$` in `configs.content`; source normalization matches, but literal
   mounted bytes are UNKNOWN. Resolve this adapter behavior before serving traffic.
5. Verify database/app health, installation/login, create/publish/respond to a
   synthetic survey, and restart persistence with Chrome for Testing/Playwright.
   Keep mail egress disabled. Actual external email delivery belongs to a later
   separately scoped gate.

Production approval, backup/restore, serialized compatible migrations, digest
promotion, post-deploy checks and rollback remain separate. This local slice adds
no hosted workflow gate and does not complete the end-to-end MVP.
