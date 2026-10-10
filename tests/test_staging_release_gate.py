"""Synthetic admission with real artifact validators; only Cosign transport is mocked."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


gate = load_module('staging', ROOT / 'scripts/ci/staging-release.py')
php_fixture = load_module('php_fixture', ROOT / 'tests/test_release_gate.py')
nginx_fixture = load_module('nginx_fixture', ROOT / 'tests/test_nginx_release_gate.py')
db_fixture = load_module('db_fixture', ROOT / 'tests/test_mariadb_release_gate.py')
NOW = datetime(2026, 10, 11, 8, tzinfo=timezone.utc)
SHA = 'a' * 40


def write(path, value):
    path.write_text(json.dumps(value))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StagingGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = {'schema_version': 1, 'source_commit': SHA,
                       'upstream_commit': gate.shared.UPSTREAM, 'components': {}}
        self.outputs = {}
        for kind in sorted(gate.COMPONENTS):
            root = self.root / kind
            root.mkdir()
            if kind == 'php':
                f = php_fixture.ReleaseGateTests(); f.setUp()
                ci = {'id': 1, 'run_attempt': 1, 'head_sha': SHA, 'event': 'push',
                      'path': '.github/workflows/release-gate.yml'}
                files = {'image.json': f.inspect, 'scan.json': f.report, 'db.json': f.db,
                         'inventory.json': f.inventory, 'sbom.cdx.json': f.sbom, 'ci.json': ci}
                for name, value in files.items(): write(root / name, value)
                (root / 'registry-manifest.json').write_bytes(f.raw)
            elif kind == 'nginx':
                nginx_fixture.write_evidence(root)
            else:
                db_fixture.MariaDBTests().release_fixture(root)
                for name in ('image.json', 'candidate-image.json'):
                    value = json.loads((root / name).read_text())
                    value[0]['Config']['Labels']['org.opencontainers.image.revision'] = SHA
                    write(root / name, value)
                for name in ('ci.json', 'runs.json', 'branch.json'):
                    value = json.loads((root / name).read_text())
                    if name == 'ci.json': value['head_sha'] = SHA
                    elif name == 'runs.json': value['workflow_runs'][0]['head_sha'] = SHA
                    else: value['commit']['sha'] = SHA
                    write(root / name, value)
            for name in ('scan.json', 'candidate-scan.json', 'db.json', 'candidate-db.json'):
                if not (root / name).exists(): continue
                value = json.loads((root / name).read_text())
                if 'scan' in name: value['CreatedAt'] = NOW.isoformat()
                else: value.update(UpdatedAt=NOW.isoformat(), DownloadedAt=NOW.isoformat())
                write(root / name, value)
            image, workflow, status, key = gate.signing.COMPONENTS[kind]
            image_digest = 'sha256:' + digest(root / 'registry-manifest.json')
            config = json.loads((root / 'image.json').read_text())[0]['Id']
            release = {'schema_version': 1, 'status': status, 'repository': gate.shared.REPOSITORY,
                       'source_commit': SHA, 'config_commit': SHA,
                       'upstream': {'version': gate.shared.VERSION, 'commit': gate.shared.UPSTREAM},
                       'image': image + '@' + image_digest, key: image_digest, 'image_config_digest': config,
                       'platform': 'linux/arm64', 'scan': {'status': 'PASS'},
                       'ci': json.loads((root / 'ci.json').read_text()), 'release_run': {'id': 123, 'attempt': 1},
                       'evidence_sha256': {p.name: digest(p) for p in root.iterdir()}}
            write(root / 'release.json', release)
            self.refresh(kind)
        self.online = patch.object(gate.signing, 'cosign', side_effect=self.cosign)
        self.online.start()
        self.addCleanup(self.online.stop)

    def refresh(self, kind):
        root = self.root / kind
        release = json.loads((root / 'release.json').read_text())
        release['evidence_sha256'] = {name: digest(root / name) for name in release['evidence_sha256']}
        write(root / 'release.json', release)
        ctx = gate.signing.context(root, kind, SHA, 123, 1)
        signature = json.dumps([{'critical': {'image': {'docker-manifest-digest': ctx['digest']},
            'identity': {'docker-reference': ctx['image']}, 'type': 'https://sigstore.dev/cosign/sign/v1'}}])
        def envelope(predicate, predicate_type):
            statement = {'_type': 'https://in-toto.io/Statement/v0.1', 'predicateType': predicate_type,
                         'subject': [{'name': ctx['repository'], 'digest': {'sha256': ctx['digest'][7:]}}],
                         'predicate': predicate}
            return json.dumps({'payloadType': 'application/vnd.in-toto+json',
                               'payload': base64.b64encode(json.dumps(statement).encode()).decode()})
        outputs = {'cosign-signature.json': signature,
                   'cosign-provenance.json': envelope(ctx['provenance'], gate.signing.PROVENANCE_TYPE),
                   'cosign-sbom.json': envelope(ctx['sbom'], gate.signing.SBOM_TYPE)}
        for name, value in outputs.items(): (root / name).write_text(value)
        receipt = {'schema_version': 1, 'status': 'SIGNATURES_VERIFIED', 'image': ctx['image'],
                   'source_commit': SHA, 'identity': ctx['identity'], 'issuer': gate.signing.ISSUER,
                   'release_run': {'id': 123, 'attempt': 1}, 'release_sha256': digest(root / 'release.json'),
                   'verification_sha256': {name: digest(root / name) for name in outputs}}
        write(root / 'signing.json', receipt)
        self.outputs[ctx['image']] = outputs
        self.bundle['components'][kind] = {'evidence_directory': str(root), 'release_sha256': digest(root / 'release.json'),
            'signing_sha256': digest(root / 'signing.json'), 'image': ctx['image'],
            'image_config_digest': release['image_config_digest'], 'release_run': receipt['release_run'],
            'evidence_sha256': release['evidence_sha256']}

    def cosign(self, arguments):
        outputs = self.outputs[arguments[-1]]
        name = 'cosign-signature.json' if arguments[0] == 'verify' else (
            'cosign-provenance.json' if '--type=slsaprovenance1' in arguments else 'cosign-sbom.json')
        return outputs[name]

    def check(self, now=NOW, sha=None):
        path = self.root / 'expected.json'
        write(path, self.bundle)
        return gate.evaluate(path, sha or digest(path), now)

    def test_exact_fresh_triple_admitted_without_readiness_or_original_writes(self):
        before = {str(p): p.read_bytes() for kind in gate.COMPONENTS for p in (self.root / kind).iterdir()}
        result = self.check()
        self.assertEqual(result['status'], 'ARTIFACT_BUNDLE_ADMITTED')
        self.assertEqual(set(result['components']), gate.COMPONENTS)
        self.assertFalse(result['staging_deployable'])
        self.assertEqual(result['production'], 'HOLD')
        self.assertEqual(before, {name: Path(name).read_bytes() for name in before})

    def test_external_hash_and_component_set_required(self):
        with self.assertRaises(ValueError): self.check(sha='0' * 64)
        del self.bundle['components']['mariadb']
        with self.assertRaises(ValueError): self.check()

    def test_expected_identity_substitutions_block(self):
        original = copy.deepcopy(self.bundle)
        for kind in gate.COMPONENTS:
            for field, value in [('image', 'ghcr.io/substitution@sha256:' + '0' * 64),
                                 ('image_config_digest', 'sha256:' + '0' * 64),
                                 ('release_run', {'id': 124, 'attempt': 1}),
                                 ('release_run', {'id': 123, 'attempt': 2}),
                                 ('release_sha256', '0' * 64)]:
                self.bundle = copy.deepcopy(original)
                self.bundle['components'][kind][field] = value
                with self.subTest(kind=kind, field=field), self.assertRaises(ValueError): self.check()
        self.bundle = copy.deepcopy(original); self.bundle['source_commit'] = 'b' * 40
        with self.assertRaises(ValueError): self.check()
        self.bundle = copy.deepcopy(original); self.bundle['upstream_commit'] = 'b' * 40
        with self.assertRaises(ValueError): self.check()

    def test_current_time_rejects_archival_and_future_scans(self):
        for delta in (timedelta(hours=24, seconds=1), -timedelta(minutes=5, seconds=1)):
            with self.subTest(delta=delta), self.assertRaises(ValueError): self.check(now=NOW + delta)

    def test_rehashed_scan_and_db_timestamp_changes_fail_for_each_component(self):
        for kind in gate.COMPONENTS:
            for name, field in [('scan.json', 'CreatedAt'), ('db.json', 'DownloadedAt')]:
                path = self.root / kind / name
                original = path.read_bytes()
                for delta in (-timedelta(hours=24, seconds=1), timedelta(minutes=5, seconds=1)):
                    value = json.loads(original); value[field] = (NOW + delta).isoformat()
                    write(path, value); self.refresh(kind)
                    with self.subTest(kind=kind, field=field, delta=delta), self.assertRaises(ValueError): self.check()
                path.write_bytes(original); self.refresh(kind)

    def test_db_updated_at_is_stricter_than_publisher_48h_policy(self):
        for kind in gate.COMPONENTS:
            path = self.root / kind / 'db.json'
            original = path.read_bytes(); db = json.loads(original)
            db['UpdatedAt'] = (NOW - timedelta(hours=25)).isoformat()
            write(path, db); self.refresh(kind)
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.check()
            path.write_bytes(original); self.refresh(kind)

    def test_rehashed_missing_package_coverage_and_blocking_findings_fail(self):
        for kind in gate.COMPONENTS:
            path = self.root / kind / 'scan.json'
            original = path.read_bytes()
            for mutate in (lambda r: r['Results'][0]['Packages'].clear(),
                           lambda r: r['Results'][0].update(Vulnerabilities=[{'Severity': 'HIGH'}])):
                value = json.loads(original); mutate(value); write(path, value); self.refresh(kind)
                with self.subTest(kind=kind), self.assertRaises(ValueError): self.check()
            path.write_bytes(original); self.refresh(kind)

    def test_changed_raw_evidence_missing_signatures_and_symlinks_fail(self):
        path = self.root / 'php' / 'scan.json'; original = path.read_bytes()
        path.write_text('{}')
        with self.assertRaises(ValueError): self.check()
        path.write_bytes(original)
        signature = self.root / 'php' / 'cosign-signature.json'; raw = signature.read_bytes()
        signature.unlink()
        with self.assertRaises(OSError): self.check()
        external = self.root / 'signature.json'; external.write_bytes(raw); signature.symlink_to(external)
        with self.assertRaises(ValueError): self.check()

    def test_multiple_dsse_envelopes_keep_raw_hashes_and_original_bytes(self):
        for kind in gate.COMPONENTS:
            root = self.root / kind
            image = self.bundle['components'][kind]['image']
            outputs = self.outputs[image]
            for name in ('cosign-provenance.json', 'cosign-sbom.json'):
                outputs[name] = outputs[name] + '\n' + outputs[name] + '\n'
                (root / name).write_text(outputs[name])
            receipt = json.loads((root / 'signing.json').read_text())
            receipt['verification_sha256'] = {name: digest(root / name) for name in outputs}
            write(root / 'signing.json', receipt)
            self.bundle['components'][kind]['signing_sha256'] = digest(root / 'signing.json')
        before = {str(p): p.read_bytes() for kind in gate.COMPONENTS for p in (self.root / kind).iterdir()}
        self.assertEqual(self.check()['status'], 'ARTIFACT_BUNDLE_ADMITTED')
        self.assertEqual(before, {name: Path(name).read_bytes() for name in before})
        (self.root / 'php' / 'cosign-provenance.json').write_text('{}\n{}')
        with self.assertRaises(ValueError): self.check()

    def test_online_signature_failure_blocks(self):
        with patch.object(gate.signing, 'cosign', side_effect=subprocess.CalledProcessError(1, ['cosign'])):
            with self.assertRaises(subprocess.SubprocessError): self.check()

    def test_cli_fail_closed(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/ci/staging-release.py'),
            '--expected-bundle', str(self.root / 'missing.json'), '--expected-bundle-sha256', '0' * 64],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('staging_release=HOLD', result.stderr)


if __name__ == '__main__': unittest.main()
