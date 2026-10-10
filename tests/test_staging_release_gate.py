"""Synthetic gate cases: no services, registry, credentials or database writes."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('staging', ROOT / 'scripts/ci/staging-release.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
NOW = datetime(2026, 10, 10, 19, tzinfo=timezone.utc)


def fixture():
    finding = {'id': 'CVE-SYNTHETIC', 'package': 'stdlib', 'version': 'v1.24.6',
               'severity': 'HIGH', 'go_id': 'GO-SYNTHETIC',
               'applicability': 'NO_REACHABLE_AFFECTED_SYMBOL_FOUND'}
    policy = {'image': 'docker.io/library/mariadb@sha256:0130d92c05fbf2d82adc2b86de742eaede65b2596c65d91786f8e03cd19e6a39',
              'image_config_digest': 'sha256:46d43d3c938ae9c1826af3c4093cea628499394820aab667519d72be306c6f9c',
              'index_digest': 'sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6',
              'gosu_sha256': '3a8ef022d82c0bc4a98bcb144e77da714c25fcfa64dccc57f6aba7ae47ff1a44',
              'platform': 'linux/arm64', 'target': 'usr/local/bin/gosu', 'findings': [finding]}
    inventory = {'image_leaf': policy['image'].split('@')[1], 'gosu_sha256': policy['gosu_sha256'],
                 'installed_packages': [{'name': 'bsdutils', 'version': '1:2.39.3-9ubuntu6.6',
                                         'architecture': 'arm64'}]}
    package = {'Name': 'bsdutils', 'Version': '2.39.3', 'Release': '9ubuntu6.6',
               'Epoch': 1, 'Arch': 'arm64', 'ID': 'bsdutils@1:2.39.3-9ubuntu6.6',
               'Identifier': {'PURL': 'pkg:deb/ubuntu/bsdutils@2.39.3-9ubuntu6.6?arch=arm64&distro=ubuntu-24.04&epoch=1'}}
    go = [{'Name': name, 'Version': version, 'ID': name + '@' + version,
           'Identifier': {'PURL': 'pkg:golang/' + name + '@' + version}}
          for name, version in {'github.com/tianon/gosu': 'v1.19.0',
                                'github.com/moby/sys/user': 'v0.1.0',
                                'golang.org/x/sys': 'v0.1.0', 'stdlib': 'v1.24.6'}.items()]
    report = {'SchemaVersion': 2, 'Trivy': {'Version': '0.75.0'}, 'ArtifactName': policy['image'],
              'ArtifactType': 'container_image', 'CreatedAt': NOW.isoformat(),
              'Metadata': {'ImageID': policy['image_config_digest'], 'RepoDigests': [policy['image']],
                           'ImageConfig': {'architecture': 'arm64', 'os': 'linux'},
                           'OS': {'Family': 'ubuntu', 'Name': '24.04'}},
              'Results': [{'Class': 'os-pkgs', 'Type': 'ubuntu',
                           'Target': policy['image'] + ' (ubuntu 24.04)', 'Packages': [package]},
                          {'Class': 'lang-pkgs', 'Type': 'gobinary', 'Target': 'usr/local/bin/gosu',
                           'Packages': go, 'Vulnerabilities': [
                               {'VulnerabilityID': finding['id'], 'PkgName': finding['package'],
                                'InstalledVersion': finding['version'], 'Severity': finding['severity']}]}]}
    db = {'Version': 2, 'UpdatedAt': NOW.isoformat(), 'DownloadedAt': NOW.isoformat()}
    return policy, inventory, report, db


class StagingGateTests(unittest.TestCase):
    def accepted(self):
        return {'status': 'ACCEPTED', 'owner': 'gion', 'scope': 'isolated-synthetic-staging',
                'proposal_sha256': '9841ff3bccd351a02202fb809eb902908267f87c827ae443c8c905cf85b7ea02',
                'review_at': '2026-10-11T12:00:00Z', 'expires_at': '2026-10-14T18:00:00Z'}

    def test_acceptance_keeps_raw_fail(self):
        p, i, r, d = fixture()
        result = gate.validate_db(r, i, d, p, NOW)
        self.assertEqual(result['raw_scan'], 'FAIL')
        self.assertEqual(result['disposition'], 'ACCEPTED_STAGING_ONLY')
        self.assertEqual(result['blocking_findings'], 1)

    def test_debian_epoch_purl_is_not_version_prefix(self):
        p, i, r, d = fixture()
        gate.validate_db(r, i, d, p, NOW)
        r['Results'][0]['Packages'][0]['Identifier']['PURL'] = 'pkg:deb/ubuntu/bsdutils@1:2.39.3-9ubuntu6.6?arch=arm64&distro=ubuntu-24.04&epoch=1'
        with self.assertRaises(gate.shared.GateError):
            gate.validate_db(r, i, d, p, NOW)

    def test_wrong_image_config_platform_and_gosu_hold(self):
        for section, key, value in [('Metadata', 'ImageID', 'sha256:' + '0' * 64),
                                    (None, 'ArtifactName', 'mariadb:latest')]:
            p, i, r, d = fixture()
            (r[section] if section else r)[key] = value
            with self.subTest(key=key), self.assertRaises(gate.shared.GateError):
                gate.validate_db(r, i, d, p, NOW)
        p, i, r, d = fixture()
        i['gosu_sha256'] = '0' * 64
        with self.assertRaises(gate.shared.GateError):
            gate.validate_db(r, i, d, p, NOW)
        p, i, r, d = fixture()
        r['Metadata']['ImageConfig']['architecture'] = 'amd64'
        with self.assertRaises(gate.shared.GateError):
            gate.validate_db(r, i, d, p, NOW)

    def test_incomplete_duplicate_or_extra_package_hold(self):
        for change in ('missing', 'duplicate', 'extra', 'qualifier'):
            p, i, r, d = fixture()
            packages = r['Results'][0]['Packages']
            if change == 'missing': packages.clear()
            elif change == 'duplicate': packages.append(copy.deepcopy(packages[0]))
            elif change == 'extra': r['Results'][1]['Packages'].pop()
            else: packages[0]['Identifier']['PURL'] += '&arch=arm64'
            with self.subTest(change=change), self.assertRaises(gate.shared.GateError):
                gate.validate_db(r, i, d, p, NOW)

    def test_new_unknown_unlisted_os_or_missing_finding_hold(self):
        for change in ('new', 'unknown', 'os', 'missing', 'duplicate', 'malformed'):
            p, i, r, d = fixture()
            findings = r['Results'][1]['Vulnerabilities']
            if change == 'new': findings[0]['VulnerabilityID'] = 'CVE-NEW'
            elif change == 'unknown': findings[0]['Severity'] = 'UNKNOWN'
            elif change == 'os': r['Results'][0]['Vulnerabilities'] = findings
            elif change == 'missing': findings.clear()
            elif change == 'duplicate': findings.append(copy.deepcopy(findings[0]))
            else: findings[0]['Severity'] = None
            with self.subTest(change=change), self.assertRaises(gate.shared.GateError):
                gate.validate_db(r, i, d, p, NOW)

    def test_stale_scan_or_database_hold(self):
        for field in ('UpdatedAt', 'DownloadedAt', 'CreatedAt'):
            p, i, r, d = fixture()
            (r if field == 'CreatedAt' else d)[field] = (NOW - timedelta(days=3)).isoformat()
            with self.subTest(field=field), self.assertRaises(gate.shared.GateError):
                gate.validate_db(r, i, d, p, NOW)

    def test_accepted_owner_and_exact_dates(self):
        gate.validate_authority(self.accepted(), NOW)
        for key, value in [('status', 'DRAFT_NOT_APPROVED'), ('owner', 'other'),
                           ('scope', 'production'), ('proposal_sha256', '0' * 64),
                           ('expires_at', '2027-01-01T00:00:00Z'),
                           ('review_at', '2026-10-10T18:00:00Z')]:
            record = self.accepted(); record[key] = value
            with self.subTest(key=key), self.assertRaises(gate.shared.GateError):
                gate.validate_authority(record, NOW)
        for at in ('2026-10-11T12:00:00Z', '2026-10-14T18:00:00Z'):
            with self.subTest(at=at), self.assertRaises(gate.shared.GateError):
                gate.validate_authority(self.accepted(), gate.timestamp(at))

    def test_untrusted_authority_file_hash_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'record.json'
            path.write_text(json.dumps(self.accepted()))
            gate.checked(path, hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(gate.shared.GateError):
                gate.checked(path, '0' * 64)

    def test_component_rejects_changed_release_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind, (name, _, image, sha, run) in gate.COMPONENTS.items():
                evidence = root / name; evidence.mkdir(parents=True)
                (evidence / 'release.json').write_text(json.dumps({
                    'image': image, 'source_commit': sha, 'release_run': {'id': run, 'attempt': 1},
                    'platform': 'linux/arm64', 'scan': {'status': 'PASS'}}))
                with self.subTest(kind=kind), self.assertRaises(gate.shared.GateError):
                    gate.component(root, kind, NOW)

    def test_component_provenance_mismatch_even_with_trusted_input(self):
        for kind, (_, _, image, _, run) in gate.COMPONENTS.items():
            release = {'image': image, 'source_commit': '0' * 40,
                       'release_run': {'id': run, 'attempt': 1},
                       'platform': 'linux/arm64', 'scan': {'status': 'PASS'}}
            with self.subTest(kind=kind), patch.object(gate, 'checked', return_value=release), \
                    self.assertRaises(gate.shared.GateError):
                gate.component(ROOT, kind, NOW)

    def test_cli_wrong_trusted_hash_produces_only_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            authority = Path(directory) / 'authority.json'
            authority.write_text(json.dumps(self.accepted()))
            command = [sys.executable, str(ROOT / 'scripts/ci/staging-release.py'),
                       '--evidence-root', directory, '--authority', str(authority),
                       '--authority-sha256', '0' * 64,
                       '--compose', str(ROOT / 'deploy/staging.compose.yaml'),
                       '--rendered', str(Path(directory) / 'absent.json'),
                       '--nginx-config', str(ROOT / 'docker/nginx/default.conf')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10,
                                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
            self.assertIn('staging_release=HOLD', result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [authority])

    def test_altered_compose_and_render_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'compose.yaml'
            path.write_bytes((ROOT / 'deploy/staging.compose.yaml').read_bytes() + b'\n')
            with self.assertRaises(gate.shared.GateError):
                gate.validate_compose(path, {}, ROOT / 'docker/nginx/default.conf')
        with self.assertRaises(gate.shared.GateError):
            gate.validate_compose(ROOT / 'deploy/staging.compose.yaml',
                                  {'services': {'db': {'ports': ['3306:3306']}}},
                                  ROOT / 'docker/nginx/default.conf')

    def test_new_published_nginx_is_the_only_local_recipe(self):
        expected_image = 'ghcr.io/cahangeorge/limesurvey-nginx@sha256:a8eeb20f935ef074537bdafe1151dae2892ce381f97305edc448af1647a061f4'
        self.assertIn('image: ' + expected_image, (ROOT / 'deploy/staging.compose.yaml').read_text())
        directory, release_hash, actual_image, source, run = gate.COMPONENTS['nginx']
        self.assertEqual((directory, release_hash, actual_image, source, run), (
            'nginx-tiff-publication-20261010/release-evidence',
            '71c01dd5ca3f76310ab1a67d568a4044bcc75bfbb47ad9ac1c070ee1b87131a9',
            expected_image,
            '2b7abac451afb0ce74aae735fe8b62d5ce171b41', 38053603034))

    def test_exact_thirty_synthetic_findings_keep_raw_fail(self):
        p, i, r, d = fixture()
        p['findings'] = []
        findings = r['Results'][1]['Vulnerabilities'] = []
        for n, severity in enumerate(['CRITICAL'] + ['HIGH'] * 24 + ['UNKNOWN'] * 5):
            p['findings'].append({'id': 'CVE-SYNTHETIC-' + str(n), 'package': 'stdlib',
                                  'version': 'v1.24.6', 'severity': severity,
                                  'applicability': 'NO_REACHABLE_AFFECTED_SYMBOL_FOUND'})
            findings.append({'VulnerabilityID': 'CVE-SYNTHETIC-' + str(n), 'PkgName': 'stdlib',
                             'InstalledVersion': 'v1.24.6', 'Severity': severity})
        self.assertEqual(gate.validate_db(r, i, d, p, NOW)['blocking_findings'], 30)
        for change in ('extra', 'missing', 'changed_severity'):
            altered = copy.deepcopy(r)
            fs = altered['Results'][1]['Vulnerabilities']
            if change == 'extra': fs.append(dict(fs[0], VulnerabilityID='CVE-UNLISTED'))
            elif change == 'missing': fs.pop()
            else: fs[0]['Severity'] = 'HIGH'
            with self.subTest(change=change), self.assertRaises(gate.shared.GateError):
                gate.validate_db(altered, i, d, p, NOW)

    def test_go_refresh_retains_nonblocking_records_and_exact_accepted_subset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'go-records').mkdir()
            entries = []
            for go_id, cve, severity in [('GO-SYNTHETIC', 'CVE-SYNTHETIC', 'HIGH'),
                                          ('GO-LOWERED', 'CVE-LOWERED', 'MEDIUM')]:
                record = {'id': go_id, 'aliases': [cve], 'modified': '2026-10-09T12:00:00Z'}
                raw = json.dumps(record).encode()
                (root / 'go-records' / (go_id + '.json')).write_bytes(raw)
                entries.append({'cve': cve, 'go_id': go_id, 'sha256': hashlib.sha256(raw).hexdigest(),
                                'unchanged_from_9Oct': True, 'modified': record['modified'],
                                'withdrawn': None, 'current_severity': severity,
                                'currently_blocking': severity == 'HIGH'})
            refresh = {'status': 'PASS_OFFICIAL_RECORD_REFRESH_ONLY_NO_RISK_ACCEPTANCE',
                       'checked_at': NOW.isoformat(), 'records': entries}
            policy = {'findings': [{'id': 'CVE-SYNTHETIC', 'go_id': 'GO-SYNTHETIC', 'severity': 'HIGH',
                                    'record_sha256': entries[0]['sha256']}]}
            self.assertEqual(gate.validate_records(root, refresh, policy, NOW),
                             {'refreshed_records': 2, 'accepted_records': 1})
            for change in ('missing', 'duplicate', 'changed_record', 'changed_hash', 'withdrawn',
                           'changed_severity', 'false_blocking', 'stale'):
                altered = copy.deepcopy(refresh)
                records = altered['records']
                if change == 'missing': records.pop(0)
                elif change == 'duplicate': records.append(copy.deepcopy(records[0]))
                elif change == 'changed_record': records[0]['modified'] = '2026-10-10T01:00:00Z'
                elif change == 'changed_hash': records[0]['sha256'] = '0' * 64
                elif change == 'withdrawn': records[0]['withdrawn'] = NOW.isoformat()
                elif change == 'changed_severity': records[0]['current_severity'] = 'UNKNOWN'
                elif change == 'false_blocking': records[1]['currently_blocking'] = True
                else: altered['checked_at'] = (NOW - timedelta(days=2)).isoformat()
                with self.subTest(change=change), self.assertRaises(gate.shared.GateError):
                    gate.validate_records(root, altered, policy, NOW)

    def test_path_escape_rejected(self):
        with self.assertRaises(gate.shared.GateError):
            gate.within(ROOT, '../authority.json')


if __name__ == '__main__':
    unittest.main()
