"""Offline contract tests; synthetic evidence is never runtime acceptance."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('nginx_release', ROOT / 'scripts/ci/nginx-release.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
SHA = 'a' * 40
ID = 'sha256:' + 'b' * 64
NOW = datetime.now(timezone.utc)
# Public raw manifest of the fixed approved FPM artifact (byte-exact digest fixture).
FPM_RAW = b'{\n   "schemaVersion": 2,\n   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",\n   "config": {\n      "mediaType": "application/vnd.docker.container.image.v1+json",\n      "size": 16734,\n      "digest": "sha256:ecad9df832a2f9e20585922ece061d2527f117a9436c8271ca27efe33c1fb4da"\n   },\n   "layers": [\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 4187659,\n         "digest": "sha256:a9986cd6f37dbddae7862a6d4be71683472e7c2ea708e87db14f8a6393c00f00"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 3501051,\n         "digest": "sha256:5757d1518c525f076c4a08716d579b93d5e7e425579a2703360c4661c6216506"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 932,\n         "digest": "sha256:defadd1b609b14b2ff5dd0bd3cf7597a407f7f7358a79b89b3a23350166894e7"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 214,\n         "digest": "sha256:84017befb376b5c1e3032d5d0591de12b9f2c0d5f1ada13ac306a01bde564afa"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 12645619,\n         "digest": "sha256:44dfdd165011df9aebd316332b06e45524eb32fdf4a3f066cdbc94b47130f963"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 487,\n         "digest": "sha256:14899fe4be4a1c5e4301a64af96aa06c85e7583d7ea98893b9b726715ad5c2cd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 13319961,\n         "digest": "sha256:c2bf577f098a104b8a9cc16abb305fcdddfae6311ab11a9182d6b8e759cf209e"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 2448,\n         "digest": "sha256:c1aef74c7b783472b06594cddea789cc0ea011722895deeb31458260d346a787"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 22239,\n         "digest": "sha256:f56e18b463ab1517c669ff833ca6bc988fcd3f67cdc13ac2e6efe240ef9e2a43"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 22259,\n         "digest": "sha256:068e362aeaacabefe7f300945d4b13abb40907b4efb18cd8e1809544fa91b687"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 32,\n         "digest": "sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 9251,\n         "digest": "sha256:99f5e2ba749c6d5adace028a8dc8dd7d29e7c76b3dc5c9bd63f889ef14c5cafd"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 23649484,\n         "digest": "sha256:17a7d307572c7575849ffcf959c36f0d2380eb35ba725fa61673f27338ad7241"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 32,\n         "digest": "sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 112363600,\n         "digest": "sha256:e8d38000db6e3b0894dab00aeadeb7988da131f25d013a834c979a1822cac9b8"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 3260079,\n         "digest": "sha256:491a44e0c1a1ed4614e1f037665b7079bc6e399e38e4116262a2326cb5d36f2a"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 597,\n         "digest": "sha256:6dd6933f0d8c37da2e1329f491f37c5394a34d11b2ea1f42a2a713b5be5a6ec4"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 3715,\n         "digest": "sha256:f5be78882209e7036e3302032b3e319b0425f238ccac426d9db2f8ea491a1368"\n      },\n      {\n         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",\n         "size": 604,\n         "digest": "sha256:923daff9c3ade8d8364d9c8663b2f131af823f06bc1c26c34808a2de20cdce6f"\n      }\n   ]\n}'


def fixture():
    raw = json.dumps({'schemaVersion': 2, 'mediaType': gate.shared.MANIFEST_TYPES[0],
                      'config': {'digest': ID}, 'layers': [{'digest': 'sha256:' + 'c' * 64}]}).encode()
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    ref = gate.IMAGE + '@' + digest
    labels = {'org.opencontainers.image.source': gate.shared.SOURCE,
              'org.opencontainers.image.revision': SHA, 'org.opencontainers.image.version': gate.VERSION,
              'io.omnestack.limesurvey.component': 'nginx'}
    image = [{'Id': ID, 'Os': 'linux', 'Architecture': 'arm64', 'Config': {'Labels': labels}, 'RepoDigests': [ref]}]
    inventory = {'os_family': 'alpine', 'os_version': '3.24.2', 'os': [['libexpat', '2.8.5-r0'], ['libpng', '1.6.59-r0'],
                   ['pcre2', '10.49-r0'], ['tiff', '4.7.2-r0']]}
    packages = [{'Name': n, 'Version': v, 'Identifier': {'PURL': 'pkg:apk/alpine/' + n + '@' + v + '?arch=aarch64&distro=3.24.2'}} for n, v in inventory['os']]
    report = {'SchemaVersion': 2, 'ArtifactName': ref, 'ArtifactType': 'container_image', 'Trivy': {'Version': '0.75.0'},
              'Metadata': {'ImageID': ID, 'RepoDigests': [ref], 'ImageConfig': {'architecture': 'arm64', 'os': 'linux'},
                           'OS': {'Family': 'alpine', 'Name': '3.24.2', 'Eosl': False}},
              'Results': [{'Target': ref + ' (alpine 3.24.2)', 'Class': 'os-pkgs', 'Type': 'alpine', 'Packages': packages, 'Vulnerabilities': [{'Severity': 'LOW'}, {'Severity': 'MEDIUM'}]}]}
    db = {'Version': 2, 'UpdatedAt': NOW.isoformat(), 'DownloadedAt': NOW.isoformat()}
    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.7', 'metadata': {'component': {'type': 'container', 'name': ref,
             'properties': [{'name': 'aquasecurity:trivy:ImageID', 'value': ID}]}}, 'components': [{'type': 'library', 'name': p['Name'], 'version': p['Version'],
              'purl': p['Identifier']['PURL'], 'bom-ref': p['Identifier']['PURL']} for p in packages]}
    return [raw, digest, image, report, inventory, db, sbom, SHA, NOW]


def fpm_image():
    return [{'Id': gate.FPM_ID, 'Os': 'linux', 'Architecture': 'arm64', 'RepoDigests': [gate.FPM_REF],
             'Config': {'Labels': {'org.opencontainers.image.source': gate.shared.SOURCE,
                                   'org.opencontainers.image.revision': gate.FPM_SHA}}}]


def write_evidence(root):
    raw, digest, image, report, inventory, db, sbom, sha, now = fixture()
    candidate = copy.deepcopy(report)
    candidate['ArtifactName'] = '/tmp/nginx-candidate.tar'
    candidate['ArtifactID'] = ID
    candidate['Results'][0]['Target'] = candidate['ArtifactName'] + ' (alpine 3.24.2)'
    branch = {'protected': True, 'commit': {'sha': sha}}
    runs = {'workflow_runs': [{'id': 42, 'run_attempt': 1, 'head_sha': sha, 'head_branch': 'main',
                              'event': 'push', 'path': '.github/workflows/release-gate.yml',
                              'repository': {'full_name': gate.shared.REPOSITORY},
                              'status': 'completed', 'conclusion': 'success'}]}
    files = {'image.json': image, 'candidate-image.json': image, 'scan.json': report,
             'candidate-scan.json': candidate, 'inventory.json': inventory, 'db.json': db,
             'candidate-db.json': db, 'sbom.cdx.json': sbom, 'fpm-image.json': fpm_image(),
             'tested.json': {'nginx_config_id': ID, 'fpm_config_id': gate.FPM_ID, 'artifact': '/tmp/nginx-candidate.tar'},
             'branch.json': branch, 'runs.json': runs,
             'ci.json': gate.shared.preflight(branch, runs, sha, 'refs/heads/main')}
    for name, content in files.items():
        (root / name).write_text(json.dumps(content))
    (root / 'registry-manifest.json').write_bytes(raw)
    (root / 'fpm-manifest.json').write_bytes(FPM_RAW)
    (root / 'smoke.log').write_text('NGINX_IMAGE=' + ID + '\nFPM_IMAGE=' + gate.FPM_ID +
        '\nPASS: health, config, static, FastCGI HTTPS/path/proxy, 7 protected paths, PHP deny\n')
    return digest


class NginxReleaseGateTest(unittest.TestCase):
    def test_valid_final_preserves_low_medium(self):
        self.assertEqual(gate.validate_image(*fixture()), {'os_packages': 4})

    def test_rejects_unfixed_tiff_with_consistent_inventory_scan_and_sbom(self):
        data = fixture()
        for package in data[4]['os']:
            if package[0] == 'tiff':
                package[1] = '4.7.1-r0'
        old_purl = 'pkg:apk/alpine/tiff@4.7.1-r0?arch=aarch64&distro=3.24.2'
        for package in data[3]['Results'][0]['Packages']:
            if package['Name'] == 'tiff':
                package['Version'] = '4.7.1-r0'
                package['Identifier']['PURL'] = old_purl
        for component in data[6]['components']:
            if component['name'] == 'tiff':
                component.update(version='4.7.1-r0', purl=old_purl)
                component['bom-ref'] = old_purl
        with self.assertRaisesRegex(ValueError, 'missing patched APK versions'):
            gate.validate_image(*data)

    def test_rejects_missing_tiff_with_consistent_inventory_scan_and_sbom(self):
        data = fixture()
        data[4]['os'] = [package for package in data[4]['os'] if package[0] != 'tiff']
        packages = data[3]['Results'][0]['Packages']
        data[3]['Results'][0]['Packages'] = [package for package in packages if package['Name'] != 'tiff']
        data[6]['components'] = [component for component in data[6]['components'] if component['name'] != 'tiff']
        with self.assertRaisesRegex(ValueError, 'missing patched APK versions'):
            gate.validate_image(*data)

    def test_rejects_identity_coverage_and_severity_mutations(self):
        mutations = [
            lambda x: x.__setitem__(0, b'{}'), lambda x: x.__setitem__(1, 'sha256:' + 'd' * 64),
            lambda x: x[2][0].__setitem__('Id', 'sha256:' + 'd' * 64),
            lambda x: x[2][0].__setitem__('Architecture', 'amd64'),
            lambda x: x[2][0]['Config']['Labels'].__setitem__('org.opencontainers.image.revision', 'd' * 40),
            lambda x: x[3].__setitem__('ArtifactName', 'wrong'),
            lambda x: x[3]['Metadata'].__setitem__('ImageID', 'wrong'),
            lambda x: x[3]['Metadata']['OS'].__setitem__('Eosl', True),
            lambda x: x[3]['Metadata']['OS'].__setitem__('EOSL', True),
            lambda x: x[3]['Metadata']['ImageConfig'].__setitem__('created', 'wrong'),
            lambda x: x[3]['Metadata']['ImageConfig'].__setitem__('rootfs', {'diff_ids': ['wrong']}),
            lambda x: x[3]['Metadata']['ImageConfig'].__setitem__('config', {'Labels': {}}),
            lambda x: x[3]['Results'].append(copy.deepcopy(x[3]['Results'][0])),
            lambda x: x[3]['Metadata']['OS'].__setitem__('Name', '3.24.1'),
            lambda x: x[3].__setitem__('Results', []),
            lambda x: x[3]['Results'][0]['Packages'].pop(),
            lambda x: x[3]['Results'][0]['Packages'].append(copy.deepcopy(x[3]['Results'][0]['Packages'][0])),
            lambda x: x[4]['os'][0].__setitem__(1, 'old'),
            lambda x: x[4]['os'].append(copy.deepcopy(x[4]['os'][0])),
            lambda x: x[6]['components'].pop(),
            lambda x: x[6].__setitem__('specVersion', '1.6'),
            lambda x: x[6]['metadata']['component'].__setitem__('name', 'wrong'),
        ]
        for severity in ['HIGH', 'CRITICAL', 'UNKNOWN', None, 0, 'low']:
            mutations.append(lambda x, s=severity: x[3]['Results'][0].__setitem__('Vulnerabilities', [{'Severity': s}]))
        for field, age in [('UpdatedAt', 49), ('DownloadedAt', 25), ('UpdatedAt', -1)]:
            mutations.append(lambda x, f=field, a=age: x[5].__setitem__(f, (NOW - timedelta(hours=a)).isoformat()))
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = fixture()
                mutate(data)
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    gate.validate_image(*data)

    def test_rejects_target_purl_and_sbom_identity_mutations(self):
        mutations = [
            lambda x: x[3]['Results'][0].pop('Target'),
            lambda x: x[3]['Results'][0].__setitem__('Target', 'wrong (alpine 3.24.2)'),
            lambda x: x[6]['components'][0].__setitem__('type', 'container'),
            lambda x: x[6]['components'][0].pop('name'),
            lambda x: x[6]['components'][0].__setitem__('name', 'wrong'),
            lambda x: x[6]['components'][0].__setitem__('version', 'old'),
            lambda x: x[6]['components'][0].pop('bom-ref'),
            lambda x: x[6]['components'].append(copy.deepcopy(x[6]['components'][0])),
        ]
        bad_purls = ['pkg:broken', 'pkg:apk/alpine/wrong@2.8.5-r0?arch=aarch64&distro=3.24.2',
                     'pkg:apk/alpine/libexpat@old?arch=aarch64&distro=3.24.2',
                     'pkg:apk/alpine/libexpat@2.8.5-r0?arch=amd64&distro=3.24.2',
                     'pkg:apk/alpine/libexpat@2.8.5-r0?arch=aarch64&distro=3.24.1',
                     'pkg:apk/alpine/libexpat@2.8.5-r0?arch=aarch64&arch=aarch64&distro=3.24.2',
                     'pkg:apk/alpine/libexpat@2.8.5-r0?arch=aarch64&distro=3.24.2#fragment']
        for purl in bad_purls:
            mutations.append(lambda x, p=purl: x[3]['Results'][0]['Packages'][0]['Identifier'].__setitem__('PURL', p))
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = fixture()
                mutate(data)
                with self.assertRaises(ValueError):
                    gate.validate_image(*data)
        data = fixture()
        for package in data[3]['Results'][0]['Packages']:
            package['Identifier']['PURL'] = 'pkg:broken'
        data[6]['components'] = [{'purl': 'pkg:broken'}]
        with self.assertRaises(ValueError):
            gate.validate_image(*data)
        data = fixture()
        data[3]['Results'][0]['Packages'][1]['Identifier']['PURL'] = data[3]['Results'][0]['Packages'][0]['Identifier']['PURL']
        with self.assertRaises(ValueError):
            gate.validate_image(*data)

    def test_accepts_encoded_apk_name_and_real_os_component(self):
        data = fixture()
        purl = 'pkg:apk/alpine/libstdc%2B%2B@16.1.0-r0?arch=aarch64&distro=3.24.2'
        data[4]['os'].append(['libstdc++', '16.1.0-r0'])
        data[3]['Results'][0]['Packages'].append({'Name': 'libstdc++', 'Version': '16.1.0-r0', 'Identifier': {'PURL': purl}})
        data[6]['components'].extend([{'type': 'library', 'name': 'libstdc++', 'version': '16.1.0-r0', 'purl': purl, 'bom-ref': purl},
                                      {'type': 'operating-system', 'name': 'alpine', 'version': '3.24.2', 'bom-ref': 'os-reference'}])
        self.assertEqual(gate.validate_image(*data), {'os_packages': 5})

    def test_approved_fpm_mutations(self):
        raw = FPM_RAW
        image = fpm_image()
        self.assertEqual(gate.validate_fpm(raw, image)['config_id'], gate.FPM_ID)
        for label in ['org.opencontainers.image.source', 'org.opencontainers.image.revision']:
            wrong = copy.deepcopy(image)
            wrong[0]['Config']['Labels'][label] = 'wrong'
            with self.assertRaises(ValueError):
                gate.validate_fpm(raw, wrong)
        for field, value in [('Id', ID), ('Architecture', 'amd64'), ('RepoDigests', [])]:
            wrong = copy.deepcopy(image)
            wrong[0][field] = value
            with self.assertRaises(ValueError):
                gate.validate_fpm(raw, wrong)

    def test_candidate_export_and_complete_cli_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = write_evidence(root)
            self.assertEqual(gate.candidate(root, SHA, NOW)['nginx_config_id'], ID)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/ci/nginx-release.py'),
                                     'manifest', directory, digest, SHA, '1', '1'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((root / 'release.json').read_text())
            self.assertEqual(manifest['status'], 'COMPANION_ARTIFACT_VERIFIED')
            self.assertEqual(manifest['production']['status'], 'HOLD')
            self.assertEqual(manifest['image_config_digest'], ID)
            for name, replacement in [('candidate-scan.json', {}), ('ci.json', {}), ('tested.json', {}),
                                      ('fpm-image.json', []), ('scan.json', {})]:
                write_evidence(root)
                (root / 'release.json').write_text(json.dumps(manifest))
                (root / name).write_text(json.dumps(replacement))
                failure = subprocess.run([sys.executable, str(ROOT / 'scripts/ci/nginx-release.py'),
                                          'manifest', directory, digest, SHA, '1', '1'], capture_output=True)
                self.assertNotEqual(failure.returncode, 0, name)
                self.assertFalse((root / 'release.json').exists(), name)

    def test_export_scan_exact_artifact_and_id(self):
        data = fixture()
        report = data[3]
        report['ArtifactName'] = '/tmp/candidate.tar'
        report['ArtifactID'] = ID
        report['Results'][0]['Target'] = report['ArtifactName'] + ' (alpine 3.24.2)'
        gate.validate_scan(report, data[4], data[5], ID, '/tmp/candidate.tar', NOW)
        for field, wrong in [('ArtifactName', '/tmp/another.tar'), ('ArtifactID', 'wrong')]:
            mutated = copy.deepcopy(report)
            mutated[field] = wrong
            with self.assertRaises(ValueError):
                gate.validate_scan(mutated, data[4], data[5], ID, '/tmp/candidate.tar', NOW)

    def test_candidate_rejects_wrong_export_id_smoke_and_fpm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mutate in [lambda: (root / 'smoke.log').write_text('PASS'),
                           lambda: (root / 'fpm-manifest.json').write_bytes(b'{}'),
                           lambda: (root / 'candidate-scan.json').write_text('{}')]:
                write_evidence(root)
                mutate()
                with self.assertRaises((ValueError, KeyError)):
                    gate.candidate(root, SHA, NOW)

    def test_cli_failure_removes_previous_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'release.json'
            output.write_text('{"status":"COMPANION_ARTIFACT_VERIFIED"}')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/ci/nginx-release.py'), 'manifest', directory,
                                     'sha256:' + 'c' * 64, SHA, '1', '1'], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
