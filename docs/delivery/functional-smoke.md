# Disposable functional roundtrip gate

## Bounded implementation plan

Scope: exactly `tests/functional-smoke.py`, `tests/smoke.sh`, both PHP release
workflows and this document. Keep ordinary smoke behavior unless the explicit
`FUNCTIONAL_SMOKE=1` flag selects the isolated functional gate.

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
`6c2ae12f8a2245fbc0eb4ea0a677155d1ec9b7d9`: RemoteControl
`import_question` returns a positive integer; `set_survey_properties` returns
per-field booleans; activation permits additional success metadata with
`status=OK`. `CsvWriter` defaults to semicolon-delimited UTF-8 with BOM, and
code headings preserve `id`, `submitdate`, `SMOKE`. The default submit template
renders `Your survey responses have been recorded.`. The question fixture is
read from that same built image, never a moving branch.

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
