"""Adversarial MariaDB identity, build and cleanup contracts."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import tempfile
import subprocess
from unittest.mock import patch
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('mariadb_gate', Path(__file__).parents[1] / 'scripts/ci/mariadb-release.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class MariaDBTests(unittest.TestCase):
    def build(self):
        return {'source': gate.GOSU_SHA, 'archive_sha256': gate.ARCHIVE, 'compiler': 'go1.27.2',
                'modules': dict(gate.MODULES), 'settings': dict(gate.SETTINGS), 'main': '(devel)',
                'path': 'github.com/tianon/gosu', 'sha256': 'a' * 64, 'static_arm64': True, 'version': '1.19'}

    def test_strict_binary_build_identity(self):
        expected = self.build()
        expected['settings']['DefaultGODEBUG'] = 'tracebacklabels=0,x509sslcertoverrideplatform=0'
        gate.validate_build(expected)
        for value in (None, 'tracebacklabels=1,x509sslcertoverrideplatform=0', 'arbitrary=1'):
            build = self.build()
            if value is None: build['settings'].pop('DefaultGODEBUG', None)
            else: build['settings']['DefaultGODEBUG'] = value
            with self.subTest(default_godebug=value), self.assertRaises(ValueError): gate.validate_build(build)
        for key, bad in [('source', 'b' * 40), ('compiler', 'go1.27.1'), ('static_arm64', False),
                         ('version', '1.18'), ('modules', {}), ('settings', {}), ('sha256', 'unknown'),
                         ('path', 'other/module')]:
            with self.subTest(key=key):
                build = self.build(); build[key] = bad
                with self.assertRaises(ValueError): gate.validate_build(build)
        build = self.build(); build['modules']['golang.org/x/sys'] = ['v0.48.0', 'wrong']
        with self.assertRaises(ValueError): gate.validate_build(build)

    def test_missing_or_failed_cleanup_never_passes(self):
        proof = {'image_id': 'sha256:' + 'a' * 64, 'binary_sha256': 'a' * 64,
                 'checks': list(gate.REGRESSION_CHECKS), 'cleanup': True, 'status': 'PASS'}
        gate.validate_regression(proof, proof['image_id'], self.build())
        for key, bad in [('cleanup', False), ('checks', []), ('image_id', 'sha256:' + 'b' * 64),
                         ('binary_sha256', 'b' * 64), ('status', 'FAIL')]:
            broken = copy.deepcopy(proof); broken[key] = bad
            with self.assertRaises(ValueError): gate.validate_regression(broken, proof['image_id'], self.build())

    def test_parent_runtime_configuration_is_preserved(self):
        parent = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'arm64',
                  'RepoDigests': [gate.BASE], 'Config': {'Entrypoint': ['docker-entrypoint.sh'], 'Cmd': ['mariadbd'], 'Env': ['A=B'], 'Labels': {'org.opencontainers.image.version': '24.04', 'maintainer': 'official'}}, 'RootFS': {'Layers': ['sha256:' + 'b' * 64]}}
        child = copy.deepcopy(parent); child['Id'] = 'sha256:' + 'a' * 64
        child['RootFS']['Layers'].append('sha256:' + 'c' * 64)
        child['Config']['Labels']['org.opencontainers.image.version'] = '11.4.13-noble-gosu1.19'
        gate.validate_parent([parent], child)
        broken = copy.deepcopy(child); broken['Config']['Labels']['maintainer'] = 'substituted'
        with self.assertRaises(ValueError): gate.validate_parent([parent], broken)
        for key in ('Entrypoint', 'Cmd', 'Env', 'User', 'WorkingDir', 'Healthcheck'):
            broken = copy.deepcopy(child); broken['Config'][key] = ['changed']
            with self.assertRaises(ValueError): gate.validate_parent([parent], broken)
        parent['RepoDigests'] = ['other@sha256:' + 'b' * 64]
        with self.assertRaises(ValueError): gate.validate_parent([parent], child)

    def test_parent_digest_allows_only_exact_official_full_and_familiar_names(self):
        parent = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'arm64',
                  'RepoDigests': [gate.BASE], 'Config': {'Labels': {}},
                  'RootFS': {'Layers': ['sha256:' + 'b' * 64]}}
        child = copy.deepcopy(parent); child['RootFS']['Layers'].append('sha256:' + 'c' * 64)
        familiar = 'mariadb@' + gate.BASE.split('@')[1]
        for refs in ([gate.BASE], [familiar], [gate.BASE, familiar]):
            parent['RepoDigests'] = refs
            with self.subTest(valid=refs): gate.validate_parent([parent], child)
        for refs in (None, [], gate.BASE, {'digest': gate.BASE}, [None], [17],
                     ['other@' + gate.BASE.split('@')[1]], ['ghcr.io/library/mariadb@' + gate.BASE.split('@')[1]],
                     ['docker.io/other/mariadb@' + gate.BASE.split('@')[1]], ['mariadb@sha256:' + 'e' * 64],
                     [gate.BASE, 'other@' + gate.BASE.split('@')[1]], [gate.BASE, gate.BASE]):
            parent['RepoDigests'] = refs
            with self.subTest(invalid=refs), self.assertRaises(ValueError): gate.validate_parent([parent], child)

    def test_parent_and_child_require_complete_valid_single_copy_layer_chain(self):
        parent = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'arm64',
                  'RepoDigests': [gate.BASE], 'Config': {'Labels': {}},
                  'RootFS': {'Layers': ['sha256:' + 'b' * 64]}}
        child = copy.deepcopy(parent); child['RootFS']['Layers'].append('sha256:' + 'c' * 64)
        gate.validate_parent([parent], child)
        for target in ('parent', 'child'):
            for bad in (None, {}, {'Layers': None}, {'Layers': []}, {'Layers': 'unknown'},
                        {'Layers': ['unknown']}, {'Layers': [None]}, {'Layers': ['sha256:' + 'a' * 63]}):
                p, c = copy.deepcopy(parent), copy.deepcopy(child)
                (p if target == 'parent' else c)['RootFS'] = bad
                with self.subTest(target=target, rootfs=bad), self.assertRaises(ValueError): gate.validate_parent([p], c)
            p, c = copy.deepcopy(parent), copy.deepcopy(child)
            del (p if target == 'parent' else c)['RootFS']
            with self.subTest(target=target, rootfs='omitted'), self.assertRaises(ValueError): gate.validate_parent([p], c)
        for layers in ([*parent['RootFS']['Layers']], ['sha256:' + 'd' * 64, 'sha256:' + 'c' * 64],
                       [*child['RootFS']['Layers'], 'sha256:' + 'e' * 64]):
            c = copy.deepcopy(child); c['RootFS']['Layers'] = layers
            with self.subTest(layers=layers), self.assertRaises(ValueError): gate.validate_parent([parent], c)

    def test_temporary_initialization_server_is_not_final_daemon_readiness(self):
        status = 'Name: mariadbd\nUid: 999 999 999 999\n'
        self.assertTrue(gate.daemon_ready('mariadbd\n', '/usr/sbin/mariadbd\n', status, '999'))
        self.assertFalse(gate.daemon_ready('bash\n', '/usr/bin/bash\n', status, '999'))
        self.assertFalse(gate.daemon_ready('mariadbd\n', '/usr/bin/other\n', status, '999'))
        self.assertFalse(gate.daemon_ready('mariadbd\n', '/usr/sbin/mariadbd\n', status.replace('999', '0'), '999'))

    def test_regression_never_accepts_healthy_temporary_server_with_shell_pid1(self):
        def fake_run(args, timeout=120):
            if 'gosu' in args:
                command = args[args.index('gosu') + 3:]
                if 'missing-gosu-user' in args: raise subprocess.CalledProcessError(1, args)
                if 'exit 37' in args: raise subprocess.CalledProcessError(37, args)
                if command[:1] == ['id']: return '998\n' if '-G' in command else '999\n'
                if 'printf %s "$HOME"' in args: return '/nonexistent'
                if 'test "$$" = 1 && printf exec' in args: return 'exec'
            if 'getent' in args: return 'mysql:x:999:998::/nonexistent:/bin/false'
            if 'id' in args: return '998\n' if '-g' in args else '999\n'
            if any(path in args for path in ('/proc/1/comm', '/proc/1/exe', '/proc/1/status')):
                self.assertIn('--user', args)
                self.assertEqual(args[args.index('--user') + 1], '999:998')
            if '/proc/1/comm' in args: return 'bash\n'
            if '/proc/1/exe' in args: return '/usr/bin/bash\n'
            if '/proc/1/status' in args: return 'Uid: 999 999 999 999\n'
            if 'mariadb' in args or 'healthcheck.sh' in args:
                self.fail('temporary initialization server cannot reach SQL/health acceptance')
            return ''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(gate, 'binary_info', return_value=self.build()), patch.object(gate, 'run', side_effect=fake_run), patch.object(gate.time, 'sleep') as sleep:
                with self.assertRaises(ValueError): gate.regression('sha256:' + 'a' * 64, root)
            self.assertEqual(sleep.call_count, 60)
            self.assertFalse((root / 'regression.json').exists())

    def fixtures(self):
        now = datetime.now(timezone.utc)
        image_id = 'sha256:' + 'a' * 64
        inventory = {'image_id': image_id, 'os_family': 'ubuntu', 'os_version': '24.04',
                     'os': [['mariadb-server', '1:11.4.13-1', 'arm64']], 'gosu': self.build()}
        inventory['gosu']['entrypoint_sha256'] = 'c' * 64
        packages = [{'Name': 'mariadb-server', 'Version': '11.4.13', 'Epoch': 1, 'Release': '1', 'Arch': 'arm64',
                     'Identifier': {'PURL': 'pkg:deb/ubuntu/mariadb-server@11.4.13-1?arch=arm64&distro=ubuntu-24.04&epoch=1'}}]
        go = [{'Name': name, 'Version': value[0], 'Identifier': {'PURL': 'pkg:golang/' + name + '@' + value[0]}}
              for name, value in gate.MODULES.items()]
        go.append({'Name': 'stdlib', 'Version': 'v1.27.2', 'Identifier': {'PURL': 'pkg:golang/stdlib@v1.27.2'}})
        report = {'SchemaVersion': 2, 'ArtifactName': '/owned/candidate.tar', 'ArtifactType': 'container_image',
                  'ArtifactID': image_id, 'Trivy': {'Version': '0.75.0'},
                  'Metadata': {'ImageID': image_id, 'ImageConfig': {'architecture': 'arm64', 'os': 'linux'},
                               'OS': {'Family': 'ubuntu', 'Name': '24.04'}},
                  'Results': [{'Class': 'os-pkgs', 'Type': 'ubuntu', 'Target': '/owned/candidate.tar (ubuntu 24.04)', 'Packages': packages},
                              {'Class': 'lang-pkgs', 'Type': 'gobinary', 'Target': 'usr/local/bin/gosu', 'Packages': go}]}
        db = {'Version': 2, 'UpdatedAt': now.isoformat(), 'DownloadedAt': now.isoformat()}
        return inventory, report, db, now

    def scan(self, inventory, report, db, now):
        return gate.validate_scan(report, inventory, db, inventory['image_id'], '/owned/candidate.tar', now)

    def test_complete_os_compiler_dependency_scan_coverage(self):
        inventory, report, db, now = self.fixtures()
        self.assertEqual(len(self.scan(inventory, report, db, now)), 4)
        report['Results'][1]['Packages'].append({'Name': 'github.com/tianon/gosu', 'Version': '(devel)',
            'Identifier': {'PURL': 'pkg:golang/github.com/tianon/gosu@(devel)'}})
        self.assertEqual(len(self.scan(inventory, report, db, now)), 5)

    def test_gated_severities_and_missing_severity_fail(self):
        for severity in ('HIGH', 'CRITICAL', 'UNKNOWN', None, ''):
            inventory, report, db, now = self.fixtures()
            report['Results'][1]['Vulnerabilities'] = [{'Severity': severity}]
            with self.subTest(severity=severity), self.assertRaises(ValueError): self.scan(inventory, report, db, now)
        inventory, report, db, now = self.fixtures()
        report['Results'][0]['Vulnerabilities'] = [{'Severity': 'MEDIUM'}]
        self.scan(inventory, report, db, now)

    def test_stale_db_missing_packages_substituted_versions_and_purls_fail(self):
        mutations = [lambda r: r['Results'].pop(),
                     lambda r: r['Results'][0]['Packages'].clear(),
                     lambda r: r['Results'][1]['Packages'].pop(),
                     lambda r: r['Results'][1]['Packages'][0].update(Version='v0.4.0'),
                     lambda r: r['Results'][0]['Packages'][0]['Identifier'].update(PURL='pkg:deb/ubuntu/mariadb-server@wrong?arch=arm64&distro=ubuntu-24.04'),
                     lambda r: r['Results'][0]['Packages'].append(copy.deepcopy(r['Results'][0]['Packages'][0])),
                     lambda r: r['Metadata'].update(ImageID='sha256:' + 'b' * 64),
                     lambda r: r['Metadata']['OS'].update(Family='debian'),
                     lambda r: r['Trivy'].update(Version='0.74.0')]
        for mutate in mutations:
            inventory, report, db, now = self.fixtures(); mutate(report)
            with self.assertRaises(ValueError): self.scan(inventory, report, db, now)
        inventory, report, db, now = self.fixtures(); db['UpdatedAt'] = '2020-01-01T00:00:00+00:00'
        with self.assertRaises(ValueError): self.scan(inventory, report, db, now)
        inventory, report, db, now = self.fixtures(); inventory['os'].append(['substituted', '1'])
        with self.assertRaises(ValueError): self.scan(inventory, report, db, now)

    def test_real_trivy_epoch_purl_requires_exact_epoch_and_architecture(self):
        valid = 'pkg:deb/ubuntu/mariadb-server@11.4.13-1?arch=arm64&distro=ubuntu-24.04&epoch=1'
        gate.purl_identity(valid, 'ubuntu', 'mariadb-server', '1:11.4.13-1', 'arm64')
        for bad in (valid.replace('&epoch=1', ''), valid.replace('epoch=1', 'epoch=2'),
                    valid.replace('arch=arm64', 'arch=all'), valid.replace('11.4.13-1', '1%3A11.4.13-1'),
                    valid + '&epoch=1', valid + '&unknown=1'):
            with self.subTest(purl=bad), self.assertRaises(ValueError):
                gate.purl_identity(bad, 'ubuntu', 'mariadb-server', '1:11.4.13-1', 'arm64')

    def release_fixture(self, root):
        inventory, report, db, now = self.fixtures(); sha = 'd' * 40
        raw = json.dumps({'schemaVersion': 2, 'mediaType': gate.shared.MANIFEST_TYPES[0],
                          'config': {'digest': inventory['image_id']}, 'layers': [{'digest': 'sha256:' + 'e' * 64}]}).encode()
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest(); ref = gate.IMAGE + '@' + digest
        parent = {'Id': 'sha256:' + 'b' * 64, 'Os': 'linux', 'Architecture': 'arm64',
                  'RepoDigests': [gate.BASE], 'Config': {'Entrypoint': ['docker-entrypoint.sh'], 'Cmd': ['mariadbd'], 'Labels': {}},
                  'RootFS': {'Layers': ['sha256:' + 'b' * 64]}}
        image = copy.deepcopy(parent); image['Id'] = inventory['image_id']; image['RepoDigests'] = [ref]
        image['RootFS']['Layers'].append('sha256:' + 'c' * 64)
        image['Config']['Labels'] = {'org.opencontainers.image.source': gate.shared.SOURCE,
            'org.opencontainers.image.revision': sha, 'org.opencontainers.image.version': '11.4.13-noble-gosu1.19',
            'io.omnestack.limesurvey.component': 'mariadb'}
        final_report = copy.deepcopy(report); final_report['ArtifactName'] = ref; final_report['Results'][0]['Target'] = ref + ' (ubuntu 24.04)'
        final_report['Metadata']['RepoDigests'] = [ref]
        components = []
        for result in report['Results']:
            for pkg in result['Packages']:
                purl = pkg['Identifier']['PURL']; version = '1:11.4.13-1' if pkg['Name'] == 'mariadb-server' else pkg['Version']
                components.append({'type': 'library', 'name': pkg['Name'], 'version': version, 'purl': purl, 'bom-ref': purl})
        components.append({'type': 'application', 'name': 'usr/local/bin/gosu', 'properties': [
            {'name': 'aquasecurity:trivy:Class', 'value': 'lang-pkgs'}, {'name': 'aquasecurity:trivy:Type', 'value': 'gobinary'}]})
        ci = {'id': 1, 'run_attempt': 1, 'head_sha': sha, 'event': 'push', 'path': '.github/workflows/release-gate.yml'}
        run = {**ci, 'head_branch': 'main', 'repository': {'full_name': gate.shared.REPOSITORY}, 'status': 'completed', 'conclusion': 'success'}
        files = {'inventory.json': inventory, 'final-inventory.json': inventory, 'buildinfo.json': inventory['gosu'],
            'candidate-image.json': [image], 'image.json': [image], 'parent-image.json': [parent],
            'parent-binary.json': {'sha256': 'b' * 64, 'entrypoint_sha256': 'c' * 64},
            'candidate-scan.json': report, 'scan.json': final_report, 'candidate-db.json': db, 'db.json': db,
            'tested.json': {'image_id': inventory['image_id'], 'artifact': '/owned/candidate.tar'},
            'regression.json': {'status': 'PASS', 'cleanup': True, 'image_id': inventory['image_id'], 'binary_sha256': 'a' * 64, 'checks': list(gate.REGRESSION_CHECKS)},
            'branch.json': {'protected': True, 'commit': {'sha': sha}}, 'runs.json': {'workflow_runs': [run]}, 'ci.json': ci,
            'sbom.cdx.json': {'bomFormat': 'CycloneDX', 'specVersion': '1.7', 'metadata': {'component': {'type': 'container', 'name': ref,
                 'properties': [{'name': 'aquasecurity:trivy:ImageID', 'value': inventory['image_id']}]}}, 'components': components}}
        for name, value in files.items(): (root / name).write_text(json.dumps(value))
        (root / 'registry-manifest.json').write_bytes(raw)
        return digest, sha, now

    def test_manifest_binds_parent_binary_regression_inventory_and_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); digest, sha, now = self.release_fixture(root)
            result = gate.manifest(root, digest, sha, 123, 1, now)
            self.assertEqual(result['status'], 'DATABASE_ARTIFACT_VERIFIED')
            self.assertIn('regression.json', result['evidence_sha256'])
            self.assertEqual(result['parent'], gate.BASE)
            with self.assertRaises(ValueError): gate.manifest(root, digest, 'e' * 40, 123, 1, now)
            self.assertFalse((root / 'release.json').exists())

    def test_substituted_sbom_and_parent_binary_or_runtime_proof_fail(self):
        for filename, mutate in [
            ('sbom.cdx.json', lambda v: v['components'].pop()),
            ('sbom.cdx.json', lambda v: v['components'][0].update(version='wrong')),
            ('parent-binary.json', lambda v: v.update(entrypoint_sha256='e' * 64)),
            ('final-inventory.json', lambda v: v['gosu'].update(sha256='e' * 64)),
            ('buildinfo.json', lambda v: v.update(compiler='go1.27.1')),
            ('regression.json', lambda v: v.update(cleanup=False)),
            ('candidate-image.json', lambda v: v[0]['Config'].update(Cmd=['changed'])),
        ]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory); digest, sha, now = self.release_fixture(root)
                value = json.loads((root / filename).read_text()); mutate(value); (root / filename).write_text(json.dumps(value))
                with self.subTest(filename=filename), self.assertRaises(ValueError): gate.manifest(root, digest, sha, 123, 1, now)
                self.assertFalse((root / 'release.json').exists())

    def test_runtime_failure_captures_stderr_and_never_writes_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'regression.json').write_text('{"status":"PASS"}')
            with patch.object(gate, 'binary_info', return_value=self.build()), patch.object(gate, 'run', side_effect=OSError('private failure')):
                with self.assertRaises((OSError, ValueError)): gate.regression('sha256:' + 'a' * 64, root)
            self.assertFalse((root / 'regression.json').exists())

    def test_every_owned_cleanup_is_attempted_even_when_removal_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def fake_run(args, timeout=120):
                calls.append(args)
                if 'id' in args: return '998\n' if '-g' in args else '999\n'
                if 'mysql' in args and 'gosu' in args: raise OSError('synthetic failure')
                if args[1:3] == ['rm', '-f']: raise OSError('synthetic cleanup failure')
                return ''
            with patch.object(gate, 'binary_info', return_value=self.build()), patch.object(gate, 'run', side_effect=fake_run):
                with self.assertRaises(ValueError): gate.regression('sha256:' + 'a' * 64, Path(directory))
            self.assertTrue(any(args[1:4] == ['volume', 'rm', '-f'] for args in calls))
            self.assertFalse((Path(directory) / 'regression.json').exists())

if __name__ == '__main__': unittest.main()
