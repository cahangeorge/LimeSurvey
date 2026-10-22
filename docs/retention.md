# Anonymous site-survey response retention

This source-only job covers exactly two configured surveys, with a maximum target
of 365 days. It preserves `anonymized=Y` and `datestamp=N`. It never exports answers,
submission timestamps, tokens or IP addresses. It calls RemoteControl
`export_responses(key, sid, 'csv', language, 'all', 'code', 'short', null, null,
['id'])` and accepts only a base64 CSV containing the exact single header `id`
and unique positive numeric IDs. It permits at most one terminal empty CSV
record emitted by the installed exporter. Internal blanks, multiple terminal
blanks, quoted empty fields and any additional column abort before deletion.
Deletion uses `delete_response(key, sid, responseId)`, which runs LimeSurvey's
response deletion path. No direct SQL writes occur.

## Age bounds and limitations

The private ledger contains only survey IDs, language, response IDs, scan-start
epoch seconds and a conservative creation lower bound per response. On first
observation, that bound is the previous successful scan's start. A response
created during that interval cannot be older than this bound. It becomes due at
`lower_bound + 365 days - 1 hour`. Consequently deletion can occur about one hour
plus one scan interval before the actual response reaches 365 days. This is a
maximum retention policy, not a promise to keep every response for exactly 365
days. Dry runs do not change ledger bounds or delete responses.

The timer runs every five minutes. The one-hour margin allows scan scheduling,
RPC and deletion time. A scan more than 55 minutes after the preceding successful
scan, a backward clock, an invalid/missing ledger or a changed privacy setting
aborts with a nonzero exit. Failed scans do not advance the successful bound.
The ledger is saved atomically with file/directory fsync; discoveries are saved
before deletion and each successful deletion is checkpointed. A crash after
remote deletion is reconciled by the next ID export. The exact success object
`{"responseId":"deleted"}` (with the requested numeric ID as a JSON string key)
and exactly `{"status":"Response Id not found","error_code":"ERR_NOT_FOUND"}`
are accepted. Arrays, wrong IDs, additional keys and other RPC results abort.

An outage, failed timer, disabled host, exhausted RPC budget or unavailable API
can defeat a 365-day maximum. `Persistent=true` attempts a missed run when the
host returns; it does not undo expired retention. Alert immediately on a failed
unit and on no successful run for 10 minutes using the existing external
monitoring system. Monitoring is an operational prerequisite, not implemented by
these unit files. After a gap above 55 minutes, stop public collection and have
an operator review the preserved ledger and delete due cohorts through the same
supported API before deliberately recovering the scan checkpoint. Never reset,
reinitialize or fabricate age bounds to conceal a gap. This tool has no automatic
recovery override. No absolute retention guarantee is claimed during outages.

Each run permits at most 1,000 RPC calls and 180 seconds overall, with 15 seconds
per HTTP request, a 2 MiB response/file limit and 5,000 IDs per survey. These are
hard failure bounds, not a capacity promise. Load-test the expected largest daily
expiry cohort; reduce cohort volume or implement a separately reviewed scalable
strategy before approaching the budget. A partial failure preserves pending IDs
for retry without advancing the last successful scan.

## Private configuration and bootstrap

Install the reviewed source at `/opt/limesurvey`, provision an unprivileged
`limesurvey-retention` system user and dedicated least-privilege LimeSurvey RPC
account with access only to the two intended surveys. Provision the local RPC
forwarder/origin separately; no public endpoint, hostname, proxy or redirect is
accepted. The endpoint must use HTTP with a numeric loopback IP. The only allowed
query string is exactly `r=admin/remotecontrol`, required by the installed OCI
front controller; a query-free path remains supported for a separately verified
forwarder. Additional parameters, encoded variants and fragments are rejected. The trusted local
host/forwarder supplies the transport boundary; do not expose it externally.
The job ignores environment proxy settings and systemd allows loopback only.

Create `/etc/limesurvey-retention` and `/var/lib/limesurvey-retention` as directories
owned by this user with mode `0700`. Create
`/etc/limesurvey-retention/config.json`, owned by this user with mode `0600`:

```json
{
  "endpoint": "http://127.0.0.1:18080/index.php?r=admin/remotecontrol",
  "username": "REPLACE_LOCALLY",
  "password": "REPLACE_LOCALLY",
  "state": "/var/lib/limesurvey-retention/ledger.json",
  "surveys": [
    {"id": 111111, "language": "ro"},
    {"id": 222222, "language": "en"}
  ]
}
```

These IDs are examples, not production inventory. Verify the two real IDs and
that no other surveys are accessible to the account. Config changes to the survey
pair or language fail against the initialized ledger. Keep config, ledger, lock
and any backups outside the repository. The process rejects public/private-file
mode mismatches and symlinks for those private files. Its exclusive lock prevents
overlapping runs. Do not invoke the Python `run` function directly in operations;
the CLI supplies config validation, lock and bounded transport.

Before initialization, independently audit both surveys as **fresh, never
previously activated**, inactive and empty, with no archived response tables.
LimeSurvey may report `ERR_NO_DATA` when an inactive survey has no active table;
this cannot distinguish a new draft from a previously deactivated survey with
archived responses. The audit is mandatory. Initialization accepts only numeric
zero or exactly `{"status":"No available data","error_code":"ERR_NO_DATA"}`
from `get_summary(..., 'full_responses')`, with both surveys inactive. Initialization
refuses to overwrite an existing ledger. Export has different pinned contracts:

- Exactly `{"status":"No Data, survey table does not exist.","error_code":"ERR_NO_RESPONSE_TABLE"}`
  is accepted only for an inactive survey with no tracked IDs. A missing table for
  an active survey or a previously populated ledger aborts, preserving evidence
  of possible deactivation/archival.
- Exactly `{"status":"No Data, could not get max id.","error_code":"ERR_NO_DATA"}`
  is accepted only for an active survey. This means its response table exists but
  contains no rows; it also reconciles a crash after the last remote deletion and
  before the corresponding ledger checkpoint. No pending ID is remotely deleted
  based on this result; the ledger is reconciled to the authoritative empty table.
- Wrong status/code combinations, extra fields and all other errors fail before
  mutation. `No available data` belongs to `get_summary`, not export.

These contracts were checked in the official `7.7.0+261020` ZIP with SHA-256
`925dd275e301b3a12fd18e14994bd21cbee34a08202bc618278c3c1cfc16988d`, in
`application/helpers/remotecontrol/remotecontrol_handle.php`, including the
single-response deletion return object. No installed-source Git revision is
inferred from the ZIP version.

Run as the dedicated user, with credentials kept in that private file:

```sh
python3 /opt/limesurvey/scripts/retention.py --config /etc/limesurvey-retention/config.json --initialize
python3 /opt/limesurvey/scripts/retention.py --config /etc/limesurvey-retention/config.json --initialize --apply
python3 /opt/limesurvey/scripts/retention.py --config /etc/limesurvey-retention/config.json
```

Initialize immediately before installing/enabling the timer, while both surveys
remain inactive. Supply/configure the local origin forwarder and verify the
endpoint returns the exact installed RPC contracts before enabling units. Install
both unit files and enable `limesurvey-retention.timer`; verify the next runs,
failed-unit alert delivery and missed-run behavior. The timer's service always
uses `--apply`. Run the entire deletion roundtrip on a separately owned synthetic
pair and private ledger first, including interruption/retry and a due synthetic
cohort; never backdate production state to test deletion. Verify the field-limited
export contains only IDs on that installed version. Only then activate the site
surveys and publish the 365-day wording. Source tests alone do not pass this gate.

## Backups and archived data

The job covers active response tables for the configured pair only. It does not
expire backups, exports, administrator downloads, deactivated/archived response
tables or application/access logs. Establish and verify a separate lifecycle for
those copies before claiming a universal 365-day data policy. Preserve the ledger
with recoverable private backups and reconcile it against active IDs after any
restore. Restoring an older database can reintroduce deleted responses: quarantine
collection and perform retention reconciliation before reopening it. Loss of the
ledger cannot be repaired by assigning current ages to existing responses.

## Local checks

```sh
python3 -m unittest tests/test_retention.py
python3 -m py_compile scripts/retention.py tests/test_retention.py
git diff --check
```

Production installation, monitoring, synthetic integration/deletion acceptance,
backup lifecycle and survey activation remain operational gates. Errors expose
only a fixed diagnostic and success logs contain aggregate counts, never response
IDs, answer content, credentials, upstream error messages or sensitive paths.
