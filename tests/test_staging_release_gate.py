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
NOW = datetime(2026, 10, 7, 19, tzinfo=timezone.utc)


def fixture():
    finding = {'id': 'CVE-SYNTHETIC', 'package': 'stdlib', 'version': 'v1.24.6',
               'severity': 'HIGH', 'go_id': 'GO-SYNTHETIC',
               'applicability': 'NO_REACHABLE_AFFECTED_SYMBOL_FOUND'}
    policy = {'image': gate.DB_REF, 'image_config_digest': gate.DB_CONFIG,
              'index_digest': gate.DB_INDEX, 'gosu_sha256': gate.GOSU,
              'platform': 'linux/arm64', 'target': 'usr/local/bin/gosu', 'findings': [finding]}
    inventory = {'image_leaf': gate.DB_REF.split('@')[1], 'gosu_sha256': gate.GOSU,
                 'installed_packages': [{'name': 'bsdutils', 'version': '1:2.39.3-9ubuntu6.6',
                                         'architecture': 'arm64'}]}
    package = {'Name': 'bsdutils', 'Version': '2.39.3', 'Release': '9ubuntu6.6',
               'Epoch': 1, 'Arch': 'arm64', 'ID': 'bsdutils@1:2.39.3-9ubuntu6.6',
               'Identifier': {'PURL': 'pkg:deb/ubuntu/bsdutils@2.39.3-9ubuntu6.6?arch=arm64&distro=ubuntu-24.04&epoch=1'}}
    go = [{'Name': name, 'Version': version, 'ID': name + '@' + version,
           'Identifier': {'PURL': 'pkg:golang/' + name + '@' + version}}
          for name, version in gate.GO_MODULES.items()]
    report = {'SchemaVersion': 2, 'Trivy': {'Version': '0.75.0'}, 'ArtifactName': gate.DB_REF,
              'ArtifactType': 'container_image', 'CreatedAt': NOW.isoformat(),
              'Metadata': {'ImageID': gate.DB_CONFIG, 'RepoDigests': [gate.DB_REF],
                           'ImageConfig': {'architecture': 'arm64', 'os': 'linux'},
                           'OS': {'Family': 'ubuntu', 'Name': '24.04'}},
              'Results': [{'Class': 'os-pkgs', 'Type': 'ubuntu',
                           'Target': gate.DB_REF + ' (ubuntu 24.04)', 'Packages': [package]},
                          {'Class': 'lang-pkgs', 'Type': 'gobinary', 'Target': 'usr/local/bin/gosu',
                           'Packages': go, 'Vulnerabilities': [
                               {'VulnerabilityID': finding['id'], 'PkgName': finding['package'],
                                'InstalledVersion': finding['version'], 'Severity': finding['severity']}]}]}
    db = {'Version': 2, 'UpdatedAt': NOW.isoformat(), 'DownloadedAt': NOW.isoformat()}
    return policy, inventory, report, db


class StagingGateTests(unittest.TestCase):
    def accepted(self):
        return {'status': 'ACCEPTED', 'owner': 'gion', 'scope': 'isolated-synthetic-staging',
                'proposal_sha256': gate.PROPOSAL_SHA, 'review_at': gate.REVIEW_AT,
                'expires_at': gate.EXPIRES_AT}

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
                           ('expires_at', '2027-01-01T00:00:00Z')]:
            record = self.accepted(); record[key] = value
            with self.subTest(key=key), self.assertRaises(gate.shared.GateError):
                gate.validate_authority(record, NOW)
        for at in (gate.REVIEW_AT, gate.EXPIRES_AT):
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
                evidence = root / name; evidence.mkdir()
                (evidence / 'release.json').write_text(json.dumps({
                    'image': image, 'source_commit': sha, 'release_run': {'id': run, 'attempt': 1},
                    'platform': 'linux/arm64', 'scan': {'status': 'PASS'}}))
                with self.subTest(kind=kind), self.assertRaises(gate.shared.GateError):
                    gate.component(root, kind)

    def test_component_provenance_mismatch_even_with_trusted_input(self):
        for kind, (_, _, image, _, run) in gate.COMPONENTS.items():
            release = {'image': image, 'source_commit': '0' * 40,
                       'release_run': {'id': run, 'attempt': 1},
                       'platform': 'linux/arm64', 'scan': {'status': 'PASS'}}
            with self.subTest(kind=kind), patch.object(gate, 'checked', return_value=release), \
                    self.assertRaises(gate.shared.GateError):
                gate.component(ROOT, kind)

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

    def test_path_escape_rejected(self):
        with self.assertRaises(gate.shared.GateError):
            gate.within(ROOT, '../authority.json')


if __name__ == '__main__':
    unittest.main()
