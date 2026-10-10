# Disposable functional roundtrip gate

## Bounded implementation plan

This functional gate contributes five files to the combined nine-file CI/CD
MVP slice: `tests/functional-smoke.py`, `tests/smoke.sh`, both PHP release
workflows and this document. The three signing files and the canonical plan
complete the reviewed scope recorded in
[the implementation plan](../implementation-plan.md#cicd-mvp-extension-functional-gate-and-signed-release-artifacts).
Keep ordinary smoke behavior unless the explicit `FUNCTIONAL_SMOKE=1` flag
selects the isolated functional gate.

1. Implement secret-safe JSON-RPC/CSV validation and adversarial self-tests.
2. Create a unique task-owned Compose project, reject pre-existing resources,
   inspect the rendered configuration, and prove empty database/config before
   installing the administrator through the pinned upstream CLI.
3. Create one synthetic survey/question over authenticated RemoteControl 2,
   submit through sandboxed Chrome for Testing, export exactly one completed
   response, restart app and DB retaining the same volumes, and re-export it.
4. Require this gate in native ARM64 CI and again on the exact publisher image
   before any registry push. Bootstrap pinned browser dependencies in runner
   temporary directories. Preserve bounded synthetic artifacts only.
5. Run helper self-tests, existing gate tests, shell/Compose/workflow checks and
   independent review. Local runtime needs separate leader authorization.

## Acceptance and safety

PASS requires a real public browser submission, visible completion screenshot,
exact marker and completed response identity before/after restart, unchanged
image/volume identities, and successful cleanup. API insertion is insufficient.
Every failure invalidates any old receipt and suppresses raw exception messages,
credentials, session keys, configuration, raw CSV and command output. Evidence
contains only synthetic screenshot, aggregate count, source/image/browser
identities and hashes; no administrator or response payload.
Failure logs contain only a constant phase name and an allowed error category.
Compose may omit an optional service environment map; the validator accepts
that shape while retaining the private-DB and isolated-resource checks.

The helper chooses `ls-functional-<32 hex>` itself. It rejects caller project,
environment-file, retained-stack and Compose override settings. It only reads
this checkout's `compose.yaml`; all generated config/env/port overrides live in
an owned temporary directory. It checks project-labelled containers, volumes and
networks are absent before startup and never attaches existing named volumes.
The nginx route binds an ephemeral port on `127.0.0.1`; DB remains private.
Cleanup removes only the generated project and its volumes, never host settings
or personal browser profiles. No production service, credential or data is used.

The pinned official Chrome for Testing executable runs with
`chromiumSandbox=True` and an ephemeral context; no alternative browser or
sandbox bypass is permitted. CI uses a runner-temporary Python environment;
local runs select the established Chrome for Testing path explicitly.

Commands (static):

```sh
python3 tests/functional-smoke.py self-test
python3 -m unittest discover -s tests -p 'test_*gate.py'
sh -n tests/smoke.sh
git diff --check
```

CI runs `python3 tests/functional-smoke.py bootstrap "$RUNNER_TEMP/functional-tools"`
then selects the returned temporary Python/browser paths through explicit env.
An authorized local runtime run requires prebuilt `APP_IMAGE`, `FUNCTIONAL_PYTHON`,
`FUNCTIONAL_CHROME`, and a task-owned `FUNCTIONAL_EVIDENCE` directory:
`FUNCTIONAL_SMOKE=1 ./tests/smoke.sh`.

This proves the PHP application functional path on disposable ordinary Compose.
It does not imply scanned companion/MariaDB acceptance, email delivery, staging
or production readiness, backups, cutover or authority to deploy.

## Pinned reference behavior

The recipe follows immutable upstream revision
`c5a2ac817396220e054efc3fd26b84cafb92b36f`: RemoteControl
`import_question` returns a positive integer; `set_survey_properties` returns
per-field booleans; activation permits additional success metadata with
`status=OK`. `CsvWriter` defaults to semicolon-delimited UTF-8 with BOM, and
code headings preserve `id`, `submitdate`, `SMOKE`. The default submit template
renders `Your survey responses have been recorded.`. The question fixture is
embedded from that exact upstream commit and checksum-verified before import,
never read from a moving branch or assumed to exist in the runtime archive.

CI downloads Chrome for Testing `155.0.8059.39` for Linux ARM64 and verifies
SHA-256 `b9d44e5d183260ca941a4c4d8d21c8a437d81ef778a489047ef98968b0475dc5`.
Playwright `1.63.0`, greenlet `3.5.6`, pyee `13.0.1`, and typing_extensions
`4.16.0` are installed using exact wheel hashes embedded in the helper.
The ARM64 bootstrap requires CPython 3.12 and a GitHub-hosted runner; system
browser libraries are installed only in that disposable CI environment.
Local browser runs require the established Chrome for Testing path and a
non-root caller. Caller-selected alternative paths/engines are rejected.

## Local static evidence (2026-10-10)

- Helper adversarial self-tests: 9 PASS (API failures, duplicate/incomplete/wrong
  response, browser path/sandbox/root policy, config/resource boundaries,
  failure output redaction and stale receipt invalidation).
- Existing gate tests: 89 PASS.
- Shell syntax and `git diff --check`: PASS.
- Compose rendering: PASS using installed rootless Podman Compose provider;
  sandbox-only attempt was blocked by read-only Podman runtime configuration,
  then the authorized read-only render succeeded outside the sandbox.
- actionlint 1.7.12: PASS; zizmor 1.30.1: PASS with existing two suppressions;
  gitleaks 8.30.1 directory scan: PASS (redacted, no output).
- Runtime/build/browser roundtrip: UNKNOWN pending independent review and an
  exact authorized local run or native ARM64 CI. Static checks do not prove the
  runtime acceptance above. No runtime/deployment/registry mutation performed.

## Independent review remediation

The pinned Yii `CSecurityManager.generateRandomString(32)` session alphabet
includes `_` and `~`; authentication now accepts exactly 32 characters from
`A-Z`, `a-z`, `0-9`, `_`, `~`. A regression test covers both special characters
and rejects incorrect lengths and the unmapped `+`/`/` alphabet.

Rendered Compose validation rejects `network_mode`, requires an internal
backend network, and restricts DB to that network alone. Mutations enabling
host networking, public backend networking or DB egress all fail. These four
regression cases failed before remediation and pass after it.

## Installer and archive contract remediation

The generated synthetic configuration uses upstream `DbConnection`, including
LimeSurvey's `MysqlSchema` mappings for `autoincrement` and `composite_pk`.
The generic Yii `CDbConnection` fails while creating the initial schema. An
isolated local reproduction failed with the generic class and completed CLI
installation, administrator creation and permissions with `DbConnection`.
Both disposable app/database probes completed resource cleanup.

The official source archive omits upstream `tests/`, so the gate embeds the
exact 1,456-byte upstream question fixture from the pinned commit, with SHA-256
`5e8cd08ced46c9a8991d2f98294234bf3b0690e0907798c1ed22fa7c4dd5091d`.
It verifies that checksum before importing the synthetic question. The runtime
image does not need test assets or an additional network download.

These repairs retain the mandatory native ARM64 functional gate. Local Podman
diagnostic probes do not replace its exact-source CI acceptance. This synthetic
installation also does not prove production table engines or backup consistency.

## Pinned 7.5 maintenance candidate

The fixture bytes and used CLI/RemoteControl return contracts were reviewed
against both immutable upstream commits and remain compatible. The current
source pin is 7.5.0+261001; earlier local/runtime evidence above belongs to the
prior implementation checkpoint. New exact-source native 7.5 installer/public
Chrome/export/restart/cleanup proof remains required. An empty installation does
not establish migration of an existing schema 712 database to 717.

## Hosted Chrome sandbox preflight

Browser bootstrap now launches an isolated blank renderer with
`chromium_sandbox=True` before the expensive native CI build. Failures emit
only an allowlisted reason; raw browser diagnostics remain private.

If that launch specifically reports sandbox denial and Ubuntu's AppArmor
user-namespace restriction is enabled, bootstrap loads the documented
`userns,` permission profile for the exact downloaded Chrome executable.
The profile is restricted to the owned, checksum-pinned browser path on an
ephemeral GitHub-hosted ARM64 runner, followed by another mandatory sandboxed
launch. Self-hosted/local callers, alternate paths, root callers and unknown
browser failures cannot trigger it. It does not disable AppArmor or change
global namespace settings, and does not configure the laptop or deployment
server. The profile disappears with the disposable hosted runner.

Reference: [Ubuntu 24.04 namespace sandbox policy](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).
