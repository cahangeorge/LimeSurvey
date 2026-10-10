"""Offline operational guards: no real Docker, network, credentials or services."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import io
import tarfile
import types
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('operate', ROOT / 'scripts/delivery/operate.py')
gate = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(gate)


def write(path, value):
    path.write_text(json.dumps(value)); path.chmod(0o600)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OperationalGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = 'a' * 24
        repository = self.root / 'repository'; (repository / 'docker/nginx').mkdir(parents=True)
        nginx = repository / 'docker/nginx/default.conf'; nginx.write_text('synthetic nginx configuration')
        (repository / 'deploy').mkdir()
        adapter = repository / 'deploy/staging.compose.yaml'
        adapter.write_bytes((ROOT / 'deploy/staging.compose.yaml').read_bytes())
        subprocess.run(['git', 'init', '-q', str(repository)], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(repository), 'add', '.'], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(repository), '-c', 'user.name=Synthetic',
                        '-c', 'user.email=probe@example.invalid', '-c', 'commit.gpgsign=false',
                        'commit', '-qm', 'Synthetic fixture'], check=True, capture_output=True)
        self.configuration_commit = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', 'HEAD']).decode().strip()
        configs = {kind: 'sha256:' + str(index + 3) * 64 for index, kind in enumerate(gate.REPOSITORIES, 1)}
        images = {}; self.artifact_images = {}; self.registry_manifests = {}
        for kind, repository_name in gate.REPOSITORIES.items():
            layer = 'sha256:' + hashlib.sha256(kind.encode()).hexdigest()
            raw = {'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
                   'config': {'digest': configs[kind]}, 'layers': [{'digest': layer}]}
            self.registry_manifests[kind] = raw
            images[kind] = repository_name + '@sha256:' + hashlib.sha256(json.dumps(raw).encode()).hexdigest()
            self.artifact_images[kind] = {'Id': configs[kind], 'Os': 'linux', 'Architecture': 'arm64',
                'RepoDigests': [images[kind]], 'RootFS': {'Type': 'layers', 'Layers': [layer]},
                'Config': {'Labels': {'org.opencontainers.image.revision': 'b' * 40},
                           'Env': ['PATH=/usr/bin'], 'Cmd': ['fixed-command'], 'Entrypoint': ['fixed-entrypoint'],
                           'User': '', 'WorkingDir': '/var/www/html'}}
        self.target_images = copy.deepcopy(self.artifact_images)
        full = images['php'].split(':')[-1]
        self.value = {'schema_version': 1, 'environment': 'staging', 'project': self.project,
                      'configuration_commit': self.configuration_commit, 'adapter_sha256': digest(adapter), 'repository_root': str(repository),
                      'nginx_sha256': digest(nginx), 'port': 18481, 'images': images, 'config_digests': configs,
                      'volumes': {kind: self.project + '-stage-' + kind + ('-' + full if kind not in ('db', 'upload') else '') for kind in gate.VOLUMES},
                      'networks': {kind: self.project + '-stage-' + kind for kind in ('backend', 'frontend')},
                      'state_file': str(self.root / 'state.json')}
        now = datetime.now(timezone.utc).isoformat()
        bundle = {'schema_version': 1, 'source_commit': 'b' * 40,
                  'upstream_commit': 'c5a2ac817396220e054efc3fd26b84cafb92b36f', 'components': {}}
        accepted = {}
        for kind in gate.REPOSITORIES:
            evidence = self.root / kind; evidence.mkdir()
            files = {'scan.json': {'CreatedAt': now}, 'db.json': {'UpdatedAt': now, 'DownloadedAt': now},
                     'registry-manifest.json': self.registry_manifests[kind], 'image.json': [self.artifact_images[kind]]}
            for name, value in files.items(): write(evidence / name, value)
            release = evidence / 'release.json'; write(release, {'synthetic': True})
            item = {'image': images[kind], 'image_config_digest': configs[kind], 'release_sha256': digest(release),
                    'release_run': {'id': 123, 'attempt': 1}, 'evidence_directory': str(evidence),
                    'evidence_sha256': {name: digest(evidence / name) for name in files}}
            bundle['components'][kind] = item
            accepted[kind] = {key: item[key] for key in ('image', 'image_config_digest', 'release_sha256', 'release_run')}
            accepted[kind].update(source_commit=bundle['source_commit'], scan='PASS', signatures='PASS')
        bundle_path = self.root / 'bundle.json'; write(bundle_path, bundle)
        receipt_path = self.root / 'admission.json'
        receipt = {'schema_version': 1, 'status': 'ARTIFACT_BUNDLE_ADMITTED', 'staging_deployable': False,
                   'source_commit': bundle['source_commit'], 'upstream_commit': bundle['upstream_commit'],
                   'expected_bundle_sha256': digest(bundle_path), 'components': accepted, 'checked_at': now}
        write(receipt_path, receipt)
        self.value['admission'] = {'receipt': str(receipt_path), 'receipt_sha256': digest(receipt_path),
                                   'bundle': str(bundle_path), 'bundle_sha256': digest(bundle_path)}
        self.path = self.root / 'manifest.json'; self.bind()
        self.resources = {}
        for index, (kind, names) in enumerate((('volume', self.value['volumes']), ('network', self.value['networks']))):
            for name in names.values():
                self.resources[name] = {'name': name, 'id': name if kind == 'volume' else hashlib.sha256(name.encode()).hexdigest(),
                                        'created_at': 'synthetic-created-at', 'labels': {gate.LABEL: self.value['_manifest_sha256']},
                                        'internal': True if kind == 'network' else None}
        self.state = {'manifest_sha256': self.value['_manifest_sha256'], 'resources': self.resources,
                      'status': 'PREPARED', 'containers': {}, 'seed_container': None}
        self.inspect = self.runtime_fixture()
        (repository / '.env').write_text('STAGING_DB_NAME=synthetic\n'); (repository / '.env').chmod(0o600)
        (repository / 'docker-compose.yaml').write_bytes(adapter.read_bytes())
        self.rendered_config = {'name': self.project, 'services': {service: {'image': self.value['images'][kind]} for service, kind in gate.IMAGES.items()}}
        self.expected_config = copy.deepcopy(self.rendered_config)
        original_command = gate.command
        def render_command(arguments, **kwargs):
            if arguments[:2] == ['docker', 'compose']:
                self.assertEqual(kwargs['env']['DELIVERY_PROJECT'], self.project)
                self.assertEqual(kwargs['env']['DELIVERY_APP_IMAGE'], self.value['images']['php'])
                source = Path(arguments[arguments.index('-f') + 1])
                if source.name == 'adapter.yaml':
                    self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                    return json.dumps(self.expected_config).encode()
                return json.dumps(self.rendered_config).encode()
            return original_command(arguments, **kwargs)
        mocked = patch.object(gate, 'command', side_effect=render_command)
        mocked.start(); self.addCleanup(mocked.stop)

    def bind(self):
        self.value.pop('_manifest_sha256', None)
        write(self.path, self.value)
        self.value = gate.manifest(self.path, digest(self.path))

    def runtime_fixture(self):
        result = []
        for index, (service, kind) in enumerate(gate.IMAGES.items(), 1):
            volumes = set(gate.VOLUMES) - {'db'} if service == 'app' else ({'db'} if service == 'db' else {'code', 'upload', 'plugins', 'themes', 'runtime'})
            mounts = [{'Type': 'volume', 'Destination': gate.VOLUMES[name], 'Name': self.value['volumes'][name], 'RW': service != 'nginx'} for name in volumes]
            if service == 'nginx':
                mounts.append({'Type': 'bind', 'Destination': '/etc/nginx/conf.d/default.conf',
                               'Source': self.value['repository_root'] + '/docker/nginx/default.conf', 'RW': False})
            networks = {'backend', 'frontend'} if service == 'nginx' else {'backend'}
            result.append({'Id': str(index) * 64, 'Image': self.value['config_digests'][kind],
                'Config': {'Image': self.value['images'][kind], 'Labels': {'com.docker.compose.project': self.project,
                          'com.docker.compose.service': service},
                          **{field: self.artifact_images[kind]['Config'].get(field) for field in ('Cmd', 'Entrypoint', 'User', 'WorkingDir', 'StopSignal')},
                          'Healthcheck': {'Test': {'app': ['CMD-SHELL', 'kill -0 1 && php-fpm -t'], 'db': ['CMD', 'healthcheck.sh', '--connect', '--innodb_initialized'], 'nginx': ['CMD', 'wget', '--quiet', '--spider', 'http://127.0.0.1/healthz']}[service],
                           'Interval': 10000000000, 'Timeout': 5000000000, 'Retries': 12 if service == 'db' else 6,
                           'StartPeriod': {'app': 20000000000, 'db': 30000000000, 'nginx': 10000000000}[service]}, 'Env': ['='.join(('RESEND_API_KEY', '')), 'DB_HOST=db']},
                'State': {'Health': {'Status': 'healthy'}}, 'Mounts': mounts,
                'HostConfig': {'ReadonlyRootfs': service == 'nginx', 'Privileged': False,
                               'Memory': {'app': 536870912, 'db': 1073741824, 'nginx': 134217728}[service],
                               'NanoCpus': 250000000 if service == 'nginx' else 1000000000,
                               'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}},
                'NetworkSettings': {'Networks': {self.value['networks'][name]: {'NetworkID': self.resources[self.value['networks'][name]]['id']} for name in networks},
                                    'Ports': {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(self.value['port'])}]} if service == 'nginx' else {}}})
        return result

    def docker(self, *arguments, **kwargs):
        if arguments[:2] == ('image', 'inspect'):
            kind = next(kind for kind in gate.REPOSITORIES if self.value['images'][kind] == arguments[2])
            return json.dumps([self.target_images[kind]]).encode()
        if arguments[:2] == ('ps', '-aq'): return '\n'.join(item['Id'] for item in self.inspect).encode()
        if arguments[0] == 'inspect': return json.dumps(self.inspect).encode()
        if len(arguments) > 1 and arguments[1] == 'inspect':
            record = self.resources[arguments[2]]
            item = {'Name': record['name'], 'Id': record['id'], 'CreatedAt': record['created_at'],
                    'Labels': record['labels']}
            if arguments[0] == 'network': item['Internal'] = record['internal']
            return json.dumps([item]).encode()
        if arguments[0] == 'exec':
            if arguments[-1] == '/etc/nginx/conf.d/default.conf':
                return (Path(self.value['repository_root']) / 'docker/nginx/default.conf').read_bytes()
            if 'SELECT stg_value' in arguments[-1]: return b'717\n'
            return b''
        if arguments[0] == 'restart': return b''
        raise AssertionError('unexpected Docker command')

    def check_runtime(self):
        with patch.object(gate, 'docker', side_effect=self.docker): return gate.runtime(self.value, self.state)

    def test_trusted_manifest_allows_distinct_configuration_and_build_source(self):
        self.assertEqual(self.value['configuration_commit'], self.configuration_commit)
        self.assertNotEqual(self.value['configuration_commit'], json.loads(Path(self.value['admission']['bundle']).read_text())['source_commit'])
        environment = gate.adapter_environment(self.value)
        self.assertFalse(any('PASSWORD' in name or 'KEY' in name for name in environment))
        self.assertEqual(environment['DELIVERY_APP_IMAGE'], self.value['images']['php'])

    def test_manifest_production_substituted_digest_names_and_config_fail(self):
        original = copy.deepcopy(self.value)
        for mutate in (lambda v: v.update(environment='production'),
                       lambda v: v['images'].update(php='ghcr.io/cahangeorge/limesurvey:latest'),
                       lambda v: v['config_digests'].update(php='sha256:' + '0' * 64),
                       lambda v: v['volumes'].update(db='production-db'),
                       lambda v: v['networks'].update(backend='coolify'),
                       lambda v: v.update(nginx_sha256='0' * 64),
                       lambda v: v.update(port=80)):
            value = copy.deepcopy(original); value.pop('_manifest_sha256'); mutate(value); write(self.path, value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): gate.manifest(self.path, digest(self.path))

    def test_configuration_source_requires_head_and_exact_committed_adapter(self):
        original = self.value['configuration_commit']
        self.value['configuration_commit'] = '0' * 40
        with self.assertRaises(ValueError): gate.configuration_source(self.value)
        self.value['configuration_commit'] = original
        adapter = Path(self.value['repository_root']) / 'deploy/staging.compose.yaml'
        original_bytes = adapter.read_bytes()
        adapter.write_bytes(original_bytes + b'\n# changed source adapter\n')
        with self.assertRaises(ValueError): gate.configuration_source(self.value)
        # Even updating the candidate hash cannot hide an uncommitted adapter change.
        self.value['adapter_sha256'] = digest(adapter)
        with self.assertRaises(ValueError): gate.configuration_source(self.value)
        adapter.write_bytes(original_bytes); self.value['adapter_sha256'] = digest(adapter)
        gate.configuration_source(self.value)

    def test_rendered_configuration_only_tolerates_exact_raw_provider_labels(self):
        expected = {'name': self.project, 'services': {service: {'image': self.value['images'][kind]} for service, kind in gate.IMAGES.items()}}
        actual = copy.deepcopy(expected)
        provider = {'coolify.managed': 'true', 'coolify.applicationUuid': self.project, 'coolify.type': 'application'}
        for service in actual['services'].values(): service['labels'] = dict(provider)
        gate.compare_configuration(expected, actual, self.project)
        for mutate in (lambda v: v['services']['db'].update(networks=['external-uuid']),
                       lambda v: v['services']['app'].update(env_file=['unexpected.env']),
                       lambda v: v['services']['nginx'].update(command=['wrong']),
                       lambda v: v['services']['db']['labels'].update({'coolify.applicationUuid': 'wrong'}),
                       lambda v: v['services']['db']['labels'].update({'extra': 'unsafe'}),
                       lambda v: v['services']['db']['labels'].pop('coolify.type')):
            changed = copy.deepcopy(actual); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                gate.compare_configuration(expected, changed, self.project)

    def test_runtime_rejects_changed_rendered_compose_before_inspecting_resources(self):
        self.rendered_config['services']['db']['networks'] = ['extra-coolify-network']
        with patch.object(gate, 'docker', side_effect=AssertionError('runtime inspection must not begin')):
            with self.assertRaises(ValueError): gate.runtime(self.value, self.state)

    def test_runtime_rejects_changed_execution_and_resource_options(self):
        original = copy.deepcopy(self.inspect)
        for service_index in range(3):
            changes = [('Config', 'Cmd', ['unexpected']), ('Config', 'Entrypoint', ['sh']),
                       ('HostConfig', 'SecurityOpt', ['seccomp=unconfined']),
                       ('HostConfig', 'CapDrop', ['ALL']), ('HostConfig', 'Memory', 0),
                       ('HostConfig', 'NanoCpus', 0), ('HostConfig', 'RestartPolicy', {'Name': 'always', 'MaximumRetryCount': 0}),
                       ('Config', 'Healthcheck', {'Test': ['NONE']})]
            for section, field, replacement in changes:
                self.inspect = copy.deepcopy(original)
                self.inspect[service_index][section][field] = replacement
                with self.subTest(service=service_index, field=field), self.assertRaises(ValueError):
                    self.check_runtime()
        self.inspect = original

    def test_initialize_keeps_admin_password_only_in_stdin_and_php_memory(self):
        write(Path(self.value['state_file']), self.state)
        credentials = self.root / 'credentials.json'
        password = 'synthetic-private-password-' * 3
        write(credentials, {'admin_user': 'syntheticadmin', 'admin_password': password})
        with patch.object(gate, 'docker', side_effect=self.docker) as mocked:
            gate.initialize(self.value, credentials)
        calls = [call for call in mocked.call_args_list if 'php' in call.args]
        self.assertEqual(len(calls), 1)
        self.assertNotIn(password, repr(calls[0].args))
        self.assertIn(password, calls[0].kwargs['data'].decode())
        bootstrap = calls[0].args[-1]
        self.assertNotIn('proc_open', bootstrap)
        self.assertNotIn('getenv', bootstrap)
        self.assertIn('$_SERVER["argv"]=$GLOBALS["argv"]', bootstrap)
        self.assertIn('require "application/commands/console.php"', bootstrap)

    def test_expired_admission_or_changed_raw_artifact_blocks(self):
        path = Path(self.value['admission']['receipt'])
        original = path.read_bytes(); receipt = json.loads(original)
        receipt['checked_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        write(path, receipt); self.value['admission']['receipt_sha256'] = digest(path)
        with self.assertRaises(ValueError): self.bind()
        path.write_bytes(original); self.value['admission']['receipt_sha256'] = digest(path)
        (self.root / 'php' / 'scan.json').write_text('{}')
        with self.assertRaises(ValueError): self.bind()

    def test_private_mode_and_hash_required(self):
        with self.assertRaises(ValueError): gate.manifest(self.path, '0' * 64)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): gate.manifest(self.path, digest(self.path))

    def test_runtime_snapshot_checks_ids_mounts_networks_schema_config(self):
        write(Path(self.value['state_file']), self.state)
        with patch.object(gate, 'docker', side_effect=self.docker): result = gate.snapshot(self.value)
        self.assertEqual(result['schema'], 717)
        self.assertEqual(set(result['containers']), {'app', 'db', 'nginx'})
        self.assertEqual(result['mail'], 'DISABLED')
        # JSON persistence retains exact mount identities across later operations.
        self.state['containers'] = result['containers']; write(Path(self.value['state_file']), self.state)
        with patch.object(gate, 'docker', side_effect=self.docker): self.assertEqual(gate.snapshot(self.value)['containers'], result['containers'])

    def test_snapshot_wrong_schema_and_changed_mounted_nginx_bytes_fail(self):
        write(Path(self.value['state_file']), self.state)
        def wrong_schema(*args, **kwargs):
            if args[0] == 'exec' and 'SELECT stg_value' in args[-1]: return b'712\n'
            return self.docker(*args, **kwargs)
        with patch.object(gate, 'docker', side_effect=wrong_schema):
            with self.assertRaises(ValueError): gate.snapshot(self.value)
        def wrong_config(*args, **kwargs):
            if args[0] == 'exec' and args[-1] == '/etc/nginx/conf.d/default.conf': return b'substituted'
            return self.docker(*args, **kwargs)
        with patch.object(gate, 'docker', side_effect=wrong_config):
            with self.assertRaises(ValueError): gate.snapshot(self.value)

    def use_containerd_images(self):
        for kind, image in self.target_images.items():
            image['Id'] = self.value['images'][kind].split('@')[1]
            image['Descriptor'] = {'digest': image['Id'], 'mediaType': self.registry_manifests[kind]['mediaType'],
                                   'platform': {'os': 'linux', 'architecture': 'arm64'}}
        for item in self.inspect: item['Image'] = self.target_images[gate.IMAGES[item['Config']['Labels']['com.docker.compose.service']]]['Id']

    def test_classic_and_containerd_ids_bind_same_signed_config_and_layers(self):
        for containerd in (False, True):
            if containerd: self.use_containerd_images()
            with self.subTest(containerd=containerd):
                result = self.check_runtime()
                for service, record in result.items():
                    kind = gate.IMAGES[service]
                    self.assertEqual(record['image_id'], self.target_images[kind]['Id'])
                    self.assertEqual(record['image_config_digest'], self.value['config_digests'][kind])

    def test_image_identity_rejects_wrong_descriptor_config_layers_ref_and_platform(self):
        for containerd in (False, True):
            if containerd: self.use_containerd_images()
            original = copy.deepcopy(self.target_images)
            changes = [lambda i: i['php'].update(Descriptor={'digest': 'sha256:' + '0' * 64}),
                       lambda i: i['php'].update(Id='sha256:' + '0' * 64),
                       lambda i: i['php']['Config'].update(Env=['WRONG_CONFIG=true']),
                       lambda i: i['php']['RootFS'].update(Layers=['sha256:' + '0' * 64]),
                       lambda i: i['php'].update(RepoDigests=['ghcr.io/wrong/image@sha256:' + '0' * 64]),
                       lambda i: i['php'].update(Architecture='amd64'),
                       lambda i: i['php'].update(Os='windows')]
            if containerd: changes.append(lambda i: i['php'].pop('Descriptor'))
            for mutate in changes:
                self.target_images = copy.deepcopy(original); mutate(self.target_images)
                with self.subTest(containerd=containerd, mutate=mutate), self.assertRaises(ValueError): self.check_runtime()
            self.target_images = original

    def test_containerd_null_default_string_fields_preserve_identity(self):
        self.use_containerd_images()
        for kind, image in self.target_images.items():
            for field in ('User', 'WorkingDir'):
                expected = self.artifact_images[kind]['Config'].get(field)
                if expected in (None, ''):
                    image['Config'][field] = None
        self.check_runtime()
        for field, replacement in (('User', 'unexpected-user'), ('WorkingDir', '/unexpected')):
            original = copy.deepcopy(self.target_images)
            self.target_images['php']['Config'][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check_runtime()
            self.target_images = original

    def test_published_raw_manifest_or_image_inspection_tamper_blocks_identity(self):
        for name in ('registry-manifest.json', 'image.json'):
            path = self.root / 'php' / name; original = path.read_bytes()
            path.write_text('{}')
            with self.subTest(name=name), self.assertRaises(ValueError): self.check_runtime()
            path.write_bytes(original)

    def test_container_image_must_equal_actual_inspected_store_id(self):
        self.use_containerd_images()
        self.inspect[0]['Image'] = self.value['config_digests']['php']
        with self.assertRaises(ValueError): self.check_runtime()

    def test_runtime_extra_proxy_network_wrong_image_mount_mail_and_port_fail(self):
        original = copy.deepcopy(self.inspect)
        changes = [lambda i: i[0]['NetworkSettings']['Networks'].update(coolify={'NetworkID': 'x'}),
                   lambda i: i[0].update(Image='sha256:' + '0' * 64),
                   lambda i: i[0]['Mounts'][0].update(Name='production-data'),
                   lambda i: i[0]['Config'].update(Env=['='.join(('RESEND_API_KEY', 'synthetic-enabled')), 'DB_HOST=db']),
                   lambda i: i[1]['NetworkSettings']['Ports']['80/tcp'][0].update(HostIp='0.0.0.0'),
                   lambda i: i[0]['HostConfig'].update(Privileged=True),
                   lambda i: i[0]['Mounts'].append({'Type': 'tmpfs', 'Destination': '/var/www/html'})]
        for mutate in changes:
            self.inspect = copy.deepcopy(original); mutate(self.inspect)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.check_runtime()

    def test_resource_ownership_and_internal_boundary_required(self):
        name = self.value['networks']['backend']; original = copy.deepcopy(self.resources[name])
        self.resources[name]['labels'] = {}
        with self.assertRaises(ValueError): self.check_runtime()
        self.resources[name] = original; self.resources[name]['internal'] = False
        with self.assertRaises(ValueError): self.check_runtime()

    def test_prepare_refuses_preexisting_resource_before_any_creation(self):
        responses = [self.value['volumes']['db'].encode(), b'']
        with patch.object(gate, 'docker', side_effect=responses) as mocked:
            with self.assertRaises(ValueError): gate.prepare(self.value)
        self.assertEqual(mocked.call_count, 2)
        self.assertFalse(Path(self.value['state_file']).exists())

    def test_prepare_seeds_exact_image_without_network_and_cleans_seed_id(self):
        calls = []
        def fake(*arguments, **kwargs):
            calls.append(arguments)
            if len(arguments) > 1 and arguments[1] == 'ls': return b''
            if arguments[:2] == ('image', 'inspect'):
                kind = next(kind for kind in gate.REPOSITORIES if self.value['images'][kind] == arguments[2])
                return json.dumps([self.target_images[kind]]).encode()
            if arguments[0] == 'create': return ('f' * 64).encode()
            if arguments[0] == 'inspect':
                return json.dumps([{'State': {'Status': 'exited', 'ExitCode': 0},
                                    'Image': self.target_images['php']['Id'],
                                    'Config': {'Image': self.value['images']['php'],
                                               'Labels': {gate.LABEL: self.value['_manifest_sha256']}}}]).encode()
            if arguments[0] in ('start', 'rm') or arguments[1] == 'create': return b''
            return self.docker(*arguments, **kwargs)
        with patch.object(gate, 'docker', side_effect=fake): result = gate.prepare(self.value)
        self.assertEqual(result['status'], 'PREPARED')
        state = gate.load_private(self.value['state_file'])
        self.assertIsNone(state['seed_container']); self.assertEqual(len(state['resources']), 9)
        create = [args for args in calls if args[0] == 'create'][0]
        self.assertIn('none', create); self.assertIn(self.value['images']['php'], create)
        self.assertIn('cp -a /var/www/html/. /seed/code/', create[-1])
        self.assertIn('cp -a /opt/limesurvey-managed-plugins/ResendEmail', create[-1])
        self.assertIn(('rm', 'f' * 64), calls)

    def test_initialize_requires_empty_database_and_records_failed_state(self):
        write(Path(self.value['state_file']), self.state)
        credentials = self.root / 'credentials.json'
        write(credentials, {'admin_user': 'syntheticadmin', 'admin_password': 'synthetic-password-' * 3})
        calls = []
        def fake(*args, **kwargs):
            calls.append(args)
            if args[0] == 'exec' and 'SHOW TABLES' in args[-1]: return b'existing_survey_table\n'
            return self.docker(*args, **kwargs)
        with patch.object(gate, 'docker', side_effect=fake):
            with self.assertRaises(ValueError): gate.initialize(self.value, credentials)
        failed = gate.load_private(self.value['state_file'])
        self.assertEqual(failed['status'], 'INITIALIZING'); self.assertEqual(len(failed['containers']), 3)
        self.assertFalse(any('php' in args for args in calls))

    def test_persistence_requires_completed_export_and_same_runtime_resources(self):
        containers = self.check_runtime()
        previous = {'status': 'PROBE_BEFORE_PASS', 'manifest_sha256': self.value['_manifest_sha256'],
                    'url': 'http://127.0.0.1:18481', 'containers': containers, 'resources': self.resources,
                    'export_sha256': 'a' * 64, 'response_id_sha256': hashlib.sha256(b'1').hexdigest()}
        proof = {'containers': containers, 'resources': self.resources, 'restart': 'PASS'}
        gate.persistence_before(self.value, previous, proof, previous['url'])
        gate.persistence_after(previous, '1', 'a' * 64)
        for response, export in [('2', 'a' * 64), ('1', 'b' * 64)]:
            with self.assertRaises(ValueError): gate.persistence_after(previous, response, export)
        changed = copy.deepcopy(proof); changed['containers']['app']['id'] = '0' * 64
        with self.assertRaises(ValueError): gate.persistence_before(self.value, previous, changed, previous['url'])
        changed = copy.deepcopy(proof); changed.pop('restart')
        with self.assertRaises(ValueError): gate.persistence_before(self.value, previous, changed, previous['url'])

    def test_finite_project_lock_refuses_parallel_operation(self):
        with gate.lock(self.value):
            with self.assertRaises(ValueError):
                with gate.lock(self.value): pass

    def test_restart_rejects_uninitialized_and_requires_same_ids(self):
        write(Path(self.value['state_file']), self.state)
        with self.assertRaises(ValueError): gate.restart(self.value)
        self.state['containers'] = self.check_runtime(); self.state['status'] = 'INITIALIZED'
        write(Path(self.value['state_file']), self.state)
        with patch.object(gate, 'docker', side_effect=self.docker): self.assertEqual(gate.restart(self.value)['restart'], 'PASS')
        self.inspect[0]['Id'] = 'f' * 64
        with self.assertRaises(ValueError): self.check_runtime()

    def test_cleanup_does_not_remove_unrecorded_runtime(self):
        write(Path(self.value['state_file']), self.state)
        with patch.object(gate, 'docker', side_effect=self.docker) as mocked:
            with self.assertRaises(ValueError): gate.cleanup_stage(self.value)
        self.assertFalse(any(call.args[0] == 'rm' for call in mocked.call_args_list))

    def test_probe_rejects_external_urls_before_http_or_browser(self):
        for url in ('https://example.invalid', 'http://localhost:18481', 'http://127.0.0.1:18481/?external=yes'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                gate.probe(self.value, 'before', url, self.root/'none', self.root/'receipt', self.root/'snapshot', '0'*64)

    def probe_attempt(self, phase, release_ok, observe_pending=False):
        smoke = gate.smoke_module()
        url = 'http://127.0.0.1:18481'
        receipt = self.root / ('probe-' + phase + '-' + str(release_ok) + '.json')
        proof = {'status': 'RUNTIME_SNAPSHOT_VERIFIED', 'manifest_sha256': self.value['_manifest_sha256'],
                 'configuration_commit': self.value['configuration_commit'], 'adapter_sha256': self.value['adapter_sha256'],
                 'schema': 717, 'nginx_sha256': self.value['nginx_sha256'], 'mail': 'DISABLED',
                 'checked_at': datetime.now(timezone.utc).isoformat(), 'containers': self.check_runtime(),
                 'resources': self.resources, 'restart': 'PASS'}
        snapshot = self.root / 'snapshot.json'; write(snapshot, proof)
        credentials = self.root / 'credentials.json'
        write(credentials, {'admin_user': 'syntheticadmin', 'admin_password': 'synthetic-password-' * 3})
        encoded = base64.b64encode(b'id;submitdate;SMOKE\n1;2026-10-11 08:00:00;operational-fixture\n').decode()
        response_id, export_sha = smoke.exported(encoded, 'operational-fixture')
        previous = {'status': 'PROBE_BEFORE_PASS', 'manifest_sha256': self.value['_manifest_sha256'],
                    'url': url, 'containers': proof['containers'], 'resources': proof['resources'],
                    'survey_id': 123, 'marker': 'operational-fixture', 'export_sha256': export_sha,
                    'response_id_sha256': hashlib.sha256(response_id.encode()).hexdigest()}
        if phase == 'after': write(receipt, previous)
        transport_calls = []
        def transport(request, **kwargs):
            payload = json.loads(request.data); method = payload['method']; transport_calls.append(method)
            if observe_pending:
                pending = gate.load_private(receipt)
                self.assertEqual(pending['status'], 'PROBE_PENDING')
            if method == 'release_session_key' and not release_ok: raise gate.GateError('synthetic release failure')
            values = {'get_session_key': 'a' * 32, 'add_survey': 123, 'add_group': 124, 'import_question': 125,
                      'set_survey_properties': {'showwelcome': True, 'usecaptcha': True, 'access_mode': True},
                      'activate_survey': {'status': 'OK'}, 'export_responses': encoded, 'release_session_key': 'OK'}
            response = MagicMock(); response.status = 200; response.geturl.return_value = request.full_url
            response.read.return_value = json.dumps({'id': 1, 'result': values[method]}).encode()
            manager = MagicMock(); manager.__enter__.return_value = response
            return manager
        browser = MagicMock(); page = browser.new_context.return_value.new_page.return_value
        page.locator.return_value.count.return_value = 0; page.screenshot.return_value = b'synthetic-png'
        playwright = MagicMock(); playwright.chromium.launch.return_value = browser
        browser_manager = MagicMock(); browser_manager.__enter__.return_value = playwright
        sync_api = types.ModuleType('playwright.sync_api'); sync_api.sync_playwright = lambda: browser_manager
        package = types.ModuleType('playwright'); package.__path__ = []
        result = None; failure = None
        with patch.object(gate, 'smoke_module', return_value=smoke), \
                patch.object(smoke, 'browser_options', return_value=({'chromium_sandbox': True}, 'synthetic Chrome')), \
                patch.object(gate.secrets, 'token_hex', return_value='fixture'), \
                patch.object(gate.urllib.request, 'urlopen', side_effect=transport), \
                patch.dict(sys.modules, {'playwright': package, 'playwright.sync_api': sync_api}):
            try:
                result = gate.probe(self.value, phase, url, credentials, receipt, snapshot, digest(snapshot))
            except gate.GateError as error: failure = error
        return result, gate.load_private(receipt), previous, transport_calls, failure

    def test_release_failure_never_leaves_current_pass_for_before_or_after(self):
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                result, receipt, previous, calls, failure = self.probe_attempt(phase, False)
                self.assertIsNotNone(failure); self.assertIsNone(result)
                self.assertEqual(calls[-1], 'release_session_key')
                self.assertEqual(receipt['status'], 'PROBE_PENDING')
                if phase == 'after': self.assertEqual(receipt['previous_before'], previous)

    def test_pending_precedes_authentication_and_success_follows_release(self):
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                result, receipt, previous, calls, failure = self.probe_attempt(phase, True, observe_pending=True)
                self.assertIsNone(failure); self.assertEqual(calls[0], 'get_session_key')
                self.assertEqual(calls[-1], 'release_session_key')
                self.assertEqual(receipt['status'], 'PROBE_' + phase.upper() + '_PASS')
                self.assertEqual(result['status'], receipt['status'])
                self.assertEqual(receipt['export_sha256'], previous['export_sha256'])
                self.assertNotIn('previous_before', receipt)

    def test_candidate_database_resolves_real_classic_and_containerd_identity(self):
        gate.save_private(self.value['state_file'], self.state)
        db = next(item for item in self.inspect if item['Config']['Labels']['com.docker.compose.service'] == 'db')
        db['State']['Running'] = True
        def transport(*args, **kwargs):
            if args[0] == 'inspect': return json.dumps([db]).encode()
            return self.docker(*args, **kwargs)
        plan = {'_candidate': self.value}
        for containerd in (False, True):
            with self.subTest(containerd=containerd):
                if containerd:
                    target = self.target_images['mariadb']
                    target['Id'] = self.value['images']['mariadb'].split('@')[1]
                    target['Descriptor'] = {'digest': target['Id'], 'mediaType': self.registry_manifests['mariadb']['mediaType'],
                                            'platform': {'os': 'linux', 'architecture': 'arm64'}}
                    db['Image'] = target['Id']
                with patch.object(gate, 'docker', side_effect=transport): gate.candidate_database(plan, db['Id'])
        self.target_images['mariadb']['RootFS']['Layers'] = ['sha256:' + 'f' * 64]
        with patch.object(gate, 'docker', side_effect=transport):
            with self.assertRaises(gate.GateError): gate.candidate_database(plan, db['Id'])

    def test_production_runtime_uses_real_signed_identity_for_all_three_images(self):
        gate.save_private(self.value['state_file'], self.state)
        for item in self.inspect: item['State']['Running'] = True
        plan = {'_candidate': self.value, 'application_uuid': self.project,
                '_legacy': {item['Config']['Labels']['com.docker.compose.service']: copy.deepcopy(item) for item in self.inspect}}
        def transport(*args, **kwargs):
            if args[:2] == ('network', 'inspect') and args[2] not in self.resources:
                name = next(name for name, record in self.resources.items() if record['id'] == args[2])
                return self.docker('network', 'inspect', name)
            return self.docker(*args, **kwargs)
        with patch.object(gate, 'docker', side_effect=transport):
            proof = gate.production_runtime(plan, {}, fenced=False)
        self.assertEqual(set(proof), {'app', 'db', 'nginx'})
        self.target_images['php']['RootFS']['Layers'] = ['sha256:' + 'f' * 64]
        with patch.object(gate, 'docker', side_effect=transport):
            with self.assertRaises(gate.GateError): gate.production_runtime(plan, {}, fenced=False)

    def test_production_db_uses_private_backend_with_preserved_app_route_networks(self):
        gate.save_private(self.value['state_file'], self.state)
        legacy = {}
        for item in self.inspect:
            service = item['Config']['Labels']['com.docker.compose.service']; item['State']['Running'] = True
            old = copy.deepcopy(item)
            old['NetworkSettings']['Networks'] = {name: {'NetworkID': name + '-id'} for name in
                (('legacy-provider', 'legacy-backend') if service != 'nginx' else ('legacy-provider', 'legacy-backend', 'legacy-frontend'))}
            legacy[service] = old
            if service == 'app': item['NetworkSettings']['Networks'].update(old['NetworkSettings']['Networks'])
            if service == 'nginx': item['NetworkSettings']['Networks'] = copy.deepcopy(old['NetworkSettings']['Networks'])
        plan = {'_candidate': self.value, 'application_uuid': self.project, '_legacy': legacy}
        private = self.value['networks']['backend']; private_id = self.resources[private]['id']
        def transport(*args, **kwargs):
            if args[:3] == ('network', 'inspect', private_id):
                return json.dumps([{'Internal': True, 'Containers': {item['Id']: {} for item in self.inspect}}]).encode()
            return self.docker(*args, **kwargs)
        with patch.object(gate, 'docker', side_effect=transport):
            self.assertEqual(set(gate.production_runtime(plan, {}, fenced=False)), set(gate.IMAGES))
        db = next(item for item in self.inspect if item['Config']['Labels']['com.docker.compose.service'] == 'db')
        for alteration in ('old-network', 'published-port', 'wrong-private-id'):
            original = copy.deepcopy(db['NetworkSettings'])
            if alteration == 'old-network': db['NetworkSettings']['Networks']['legacy-provider'] = {'NetworkID': 'external-id'}
            if alteration == 'published-port': db['NetworkSettings']['Ports'] = {'3306/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '3306'}]}
            if alteration == 'wrong-private-id': db['NetworkSettings']['Networks'][private]['NetworkID'] = 'foreign-id'
            with self.subTest(alteration=alteration), patch.object(gate, 'docker', side_effect=transport):
                with self.assertRaises(gate.GateError): gate.production_runtime(plan, {}, fenced=False)
            db['NetworkSettings'] = original
        def foreign_member(*args, **kwargs):
            if args[:3] == ('network', 'inspect', private_id):
                return json.dumps([{'Internal': True, 'Containers': {'f' * 64: {}}}]).encode()
            return self.docker(*args, **kwargs)
        with patch.object(gate, 'docker', side_effect=foreign_member):
            with self.assertRaises(gate.GateError): gate.production_runtime(plan, {}, fenced=False)

    def test_adapter_has_no_build_or_egress_and_explicit_external_resources(self):
        text = (ROOT / 'deploy/staging.compose.yaml').read_text()
        self.assertNotIn('build:', text); self.assertNotIn('egress', text)
        self.assertIn("RESEND_API_KEY: ''", text)
        self.assertIn("127.0.0.1:${DELIVERY_PORT:?required}:80", text)
        self.assertEqual(text.count('external: true'), 9)
        self.assertEqual(text.count('image: ${DELIVERY_'), 3)
        self.assertIn('source: ./docker/nginx/default.conf', text)

    def test_cli_secret_safe_failure(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/delivery/operate.py'), 'snapshot',
                                 '--manifest', str(self.path), '--manifest-sha256', '0' * 64], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1); self.assertEqual(result.stdout, '')
        self.assertIn('operational_delivery=HOLD', result.stderr)
        self.assertNotIn(str(self.root), result.stderr)


class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = {'application_uuid': 'p' * 24, '_plan_sha256': 'b' * 64,
                     'directory': str(self.root / 'transaction'), 'state_file': str(self.root / 'state.json'),
                     'custom_plugins': ['Custom'], 'custom_themes': [], 'operator_config_files': []}
        self.before = {'schema': 712, 'prefix': 'custom_', 'permissions': [[1, 'survey', 'read', 1, 0, 1, 0, 0, 0, 0]],
                       'counts': {'custom_surveys': 1, 'custom_users': 1, 'custom_plugins': 2, 'custom_responses_7': 1},
                       'active_response_tables': ['custom_responses_7']}

    def test_legacy_network_allows_only_live_exact_bound_proxy(self):
        proxy = {'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64, 'Name': '/coolify-proxy',
                 'compose_project': 'coolify-proxy', 'compose_service': 'traefik'}
        services = {}
        for index, service in enumerate(gate.IMAGES, 1):
            services[service] = {'Id': str(index) * 64, 'Image': 'sha256:' + str(index) * 64,
                'Config': {'Labels': {'com.docker.compose.project': self.plan['application_uuid'], 'com.docker.compose.service': service}},
                'Mounts': [], 'State': {'Running': True, 'Health': {'Status': 'healthy'}},
                'NetworkSettings': {'Networks': {'legacy-provider': {'NetworkID': 'external'}, 'legacy-backend': {'NetworkID': 'internal'}}, 'Ports': {}}}
        self.plan.update(_legacy=services, trusted_proxy=proxy)
        live_proxy = {'Id': proxy['Id'], 'Image': proxy['Image'], 'Name': proxy['Name'], 'State': {'Running': True},
                      'Config': {'Labels': {'com.docker.compose.project': proxy['compose_project'], 'com.docker.compose.service': proxy['compose_service']}}}
        members = set(item['Id'] for item in services.values()) | {proxy['Id']}
        def transport(*args, **kwargs):
            if args[0] == 'ps': return '\n'.join(item['Id'] for item in services.values()).encode()
            if args[:2] == ('network', 'inspect'):
                return json.dumps([{'Internal': args[2] == 'internal', 'Containers': {identifier: {} for identifier in members}}]).encode()
            if args[:2] == ('inspect', proxy['Id']): return json.dumps([live_proxy]).encode()
            return json.dumps(list(services.values())).encode()
        with patch.object(gate, 'docker', side_effect=transport): gate.legacy_state(self.plan)
        members.add('f' * 64)
        with patch.object(gate, 'docker', side_effect=transport):
            with self.assertRaises(gate.GateError): gate.legacy_state(self.plan)
        members.remove('f' * 64); live_proxy['Image'] = 'sha256:' + 'c' * 64
        with patch.object(gate, 'docker', side_effect=transport):
            with self.assertRaises(gate.GateError): gate.legacy_state(self.plan)

    def test_production_compose_restricts_db_to_private_network(self):
        candidate = {'project': 'candidate', 'repository_root': str(self.root), 'images': {kind: 'signed-' + kind for kind in gate.REPOSITORIES},
                     'volumes': {key: 'fresh-' + key for key in gate.VOLUMES}, 'networks': {'backend': 'owned-internal'}}
        source = {'services': {}, 'networks': {'old': {'name': 'old-provider'}, 'backend': {'name': 'old-backend'}}}
        for service in gate.IMAGES:
            source['services'][service] = {'labels': {'preserved-route': 'exact'}, 'networks': {'old': {}, 'backend': {}},
                'environment': {}, 'volumes': [{'type': 'volume', 'source': 'old', 'target': gate.VOLUMES['db' if service == 'db' else 'code']} ]}
        source['services']['nginx']['volumes'].append({'type': 'bind', 'source': 'old-config', 'target': '/etc/nginx/conf.d/default.conf'})
        self.plan.update(_candidate=candidate, _source=source)
        result = gate.selected_compose(self.plan, False)
        self.assertEqual(result['services']['db']['networks'], {'delivery-private': {}})
        self.assertEqual(set(result['services']['app']['networks']), {'old', 'backend', 'delivery-private'})
        self.assertEqual(set(result['services']['nginx']['networks']), {'old', 'backend'})
        self.assertEqual(result['networks']['delivery-private'], {'external': True, 'name': 'owned-internal'})
        self.assertEqual(result['services']['nginx']['labels'], source['services']['nginx']['labels'])

    def test_lock_is_stable_across_receipts_and_excludes_concurrent_writer(self):
        with patch.object(gate, 'LOCK_DIRECTORY', self.root):
            with gate.production_lock(self.plan['application_uuid']):
                with self.assertRaises(gate.GateError):
                    with gate.production_lock(self.plan['application_uuid']): pass
                with gate.production_lock('q' * 24): pass
            with gate.production_lock(self.plan['application_uuid']): pass

    def archive(self, members):
        path = self.root / 'files.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, content in members.items():
                raw = content.encode(); member = tarfile.TarInfo(name); member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        path.chmod(0o600); return path

    def test_paired_archive_requires_security_and_rejects_traversal(self):
        for entries in ({'application/config/config.php': 'config'},
                        {'application/config/config.php': 'config', 'application/config/security.php': 'security', '../foreign': 'bad'}):
            with self.subTest(entries=list(entries)):
                with self.assertRaises(gate.GateError): gate.archive_inventory(self.archive(entries))
        path = self.archive({'application/config/config.php': 'config', 'application/config/security.php': 'security',
                             'upload/file': 'upload', 'plugins/Custom/file': 'custom', 'application/config/internal.php': 'old defaults'})
        inventory = gate.archive_inventory(path); selected = gate.restore_paths(self.plan, inventory)
        self.assertIn('upload/file', selected); self.assertIn('plugins/Custom/file', selected)
        self.assertNotIn('application/config/internal.php', selected)

    def test_installed_config_bootstrap_defines_basepath_before_guarded_includes(self):
        configuration = self.root / 'application/config'; configuration.mkdir(parents=True)
        (configuration / 'config.php').write_text('<?php if (!defined("BASEPATH")) { exit(0); } return ["components"=>["db"=>["tablePrefix"=>"custom_"]]];')
        (configuration / 'security.php').write_text('<?php if (!defined("BASEPATH")) { exit(0); } return ["encryptionnonce"=>"synthetic", "encryptionsecretboxkey"=>"synthetic"];')
        php = shutil.which('php')
        def execute(*args, **kwargs):
            self.assertEqual(args[:4], ('exec', 'synthetic-app', 'php', '-r'))
            code = args[4]
            bootstrap = 'define("BASEPATH", "/var/www/html/");'
            self.assertIn(bootstrap, code)
            self.assertLess(code.index(bootstrap), code.index('include "application/config/config.php"'))
            self.assertLess(code.index(bootstrap), code.index('include "application/config/security.php"'))
            if php:
                result = subprocess.run([php, '-r', code], cwd=self.root, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0); return result.stdout
            return json.dumps({'prefix': 'custom_', 'security': {'encryptionnonce': True, 'encryptionsecretboxkey': True}}).encode()
        with patch.object(gate, 'docker', side_effect=execute):
            metadata = gate.config_metadata('synthetic-app')
        self.assertEqual(metadata['prefix'], 'custom_')
        self.assertEqual(metadata['security'], {'encryptionnonce': True, 'encryptionsecretboxkey': True})

    def test_missing_installed_encryption_keys_rejects_before_backup(self):
        for metadata in ({'prefix': 'custom_', 'security': {'encryptionnonce': True, 'encryptionsecretboxkey': False}},
                         {'prefix': 'bad;prefix', 'security': {'encryptionnonce': True, 'encryptionsecretboxkey': True}}):
            with patch.object(gate, 'docker', return_value=json.dumps(metadata).encode()):
                with self.assertRaises(gate.GateError): gate.config_metadata('synthetic-app')

    def test_actual_response_table_name_is_in_inventory(self):
        def query(identifier, sql):
            if 'TABLE_NAME,TABLE_TYPE,ENGINE' in sql:
                return ['custom_responses_7\tBASE TABLE\tMyISAM', 'custom_settings_global\tBASE TABLE\tMyISAM']
            if 'information_schema.TRIGGERS' in sql: return ['0\t0\t0']
            if 'stg_value' in sql: return ['712']
            if 'JSON_ARRAY' in sql: return []
            if 'SELECT sid' in sql: return ['7']
            return ['1']
        with patch.object(gate, 'database', side_effect=query):
            self.assertEqual(gate.db_inventory('db', 'custom_')['active_response_tables'], ['custom_responses_7'])

    def postcheck(self, missing_quota=False, missing_inheritance=False):
        after = copy.deepcopy(self.before); after['schema'] = 717
        calls = []
        def query(identifier, sql):
            calls.append(sql)
            if 'quota_exit' in sql: return [] if missing_quota else ['int(11)\tYES']
            if 'COLUMN_DEFAULT' in sql: return ["'N'"]
            if 'session_token' in sql: return ['varchar(64)\tYES']
            if 'STATISTICS' in sql: return ['entity_id\t0', 'entity\t0', 'permission\t0', 'uid\t0']
            if 'information_schema.COLUMNS' in sql: return ['1']
            if 'gsid <> 0' in sql and missing_inheritance: return ['1']
            return ['0']
        with patch.object(gate, 'db_inventory', return_value=after), patch.object(gate, 'database', side_effect=query):
            result = gate.migration_postconditions('db', self.before)
        return result, calls

    def test_schema717_does_not_mask_missing_active_response_quota_column(self):
        with self.assertRaises(gate.GateError): self.postcheck(missing_quota=True)
        result, calls = self.postcheck()
        self.assertEqual(result['schema'], 717)
        self.assertTrue(any('custom_responses_7' in sql for sql in calls))

    def test_global_group_zero_and_non_global_group_one_are_checked(self):
        _, calls = self.postcheck()
        self.assertTrue(any('gsid <> 0' in sql for sql in calls))
        with self.assertRaises(gate.GateError): self.postcheck(missing_inheritance=True)

    def test_newer_or_already_migrated_schema_never_runs_updater(self):
        for schema in (717, 718, 0):
            with patch.object(gate, 'candidate_database'), patch.object(gate, 'db_inventory', return_value={'schema': schema}), \
                 patch.object(gate, 'compose') as command:
                with self.assertRaises(gate.GateError):
                    gate.migrate_candidate(self.plan, {'backup': {'inventory': self.before}}, 'db', self.root / 'compose')
                command.assert_not_called()

    def test_original_or_foreign_db_mount_rejects_before_any_restore_sql(self):
        candidate = {'state_file': str(self.root / 'candidate.json'), 'project': 'candidate',
                     'images': {'mariadb': 'bound-reference'}, 'volumes': {'db': 'fresh-owned-db'},
                     'networks': {'backend': 'internal'}}
        write(Path(candidate['state_file']), {'resources': {'internal': {'id': 'network-id'}}})
        self.plan['_candidate'] = candidate
        inspected = {'Id': 'db', 'Image': 'image-id', 'Config': {'Image': 'bound-reference',
                     'Labels': {'com.docker.compose.project': 'candidate', 'com.docker.compose.service': 'db'}},
                     'State': {'Running': True, 'Health': {'Status': 'healthy'}},
                     'Mounts': [{'Type': 'volume', 'Name': 'original-production-db', 'Destination': '/var/lib/mysql', 'RW': True}]}
        def docker(*args, **kwargs):
            return json.dumps([{'Id': 'image-id'}] if args[0] == 'image' else [inspected]).encode()
        with patch.object(gate, 'owned_resources'), patch.object(gate, 'image_identity'), \
             patch.object(gate, 'docker', side_effect=docker), patch.object(gate, 'database') as sql:
            with self.assertRaises(gate.GateError): gate.import_database('db', self.plan, {'sha256': {}}, reset=True)
            sql.assert_not_called()

    def test_publication_blocks_legacy_rescue_even_with_valid_old_backup(self):
        with patch.object(gate, 'docker') as docker:
            with self.assertRaises(gate.GateError): gate.legacy_rescue(self.plan, {'public_unfenced': True})
            docker.assert_not_called()

    def test_relative_adapter_bind_resolves_in_exact_candidate_repository(self):
        repository = self.root / 'repository'; (repository / 'docker/nginx').mkdir(parents=True)
        config = repository / 'docker/nginx/default.conf'; config.write_text('synthetic canonical nginx')
        candidate = {'project': 'candidate', 'repository_root': str(repository), 'nginx_sha256': digest(config),
                     '_manifest_sha256': 'a' * 64, 'images': {kind: 'signed-' + kind for kind in gate.REPOSITORIES},
                     'port': 18481, 'volumes': {}, 'networks': {}}
        self.plan.update(_candidate=candidate, _source={'services': {'db': {'environment': {
            'MARIADB_DATABASE': 'synthetic', 'MARIADB_USER': 'synthetic',
            'MARIADB_PASSWORD': 'synthetic-only-password', 'MARIADB_ROOT_PASSWORD': 'synthetic-only-root'}}}})
        observed = []
        def render(arguments, **kwargs):
            observed.append(arguments)
            directory = Path(arguments[arguments.index('--project-directory') + 1]) if '--project-directory' in arguments else ROOT / 'deploy'
            return json.dumps({'name': candidate['project'], 'services': {
                service: {'image': candidate['images'][kind], 'volumes': [{'type': 'bind', 'source': str(directory / 'docker/nginx/default.conf'),
                          'target': '/etc/nginx/conf.d/default.conf', 'read_only': True}] if service == 'nginx' else []}
                for service, kind in gate.IMAGES.items()}}).encode()
        with patch.object(gate, 'command', side_effect=render): rendered = gate.selected_compose(self.plan, True)
        self.assertEqual(rendered['services']['nginx']['volumes'][0]['source'], str(config))
        args = observed[0]; self.assertEqual(args[args.index('--project-name') + 1], candidate['project'])
        self.assertNotIn('synthetic-only-password', args); self.assertNotIn('synthetic-only-root', args)
        bad = copy.deepcopy(rendered); bad['services']['nginx']['volumes'][0]['source'] = str(ROOT / 'deploy/docker/nginx/default.conf')
        with patch.object(gate, 'command', return_value=json.dumps(bad).encode()):
            with self.assertRaises(gate.GateError): gate.selected_compose(self.plan, True)

    def test_promotion_requires_rehearsal_before_any_writer_mutation(self):
        with patch.object(gate, 'docker') as docker:
            with self.assertRaises(gate.GateError): gate.recovery_transaction(self.plan)
            docker.assert_not_called(); self.assertFalse(Path(self.plan['directory']).exists())

    def test_fence_keeps_health_static_and_token_private(self):
        directory = Path(self.plan['directory']); directory.mkdir(mode=0o700)
        repository = self.root / 'repository'; (repository / 'docker/nginx').mkdir(parents=True)
        config = repository / 'docker/nginx/default.conf'
        config.write_bytes((ROOT / 'docker/nginx/default.conf').read_bytes())
        self.plan['_candidate'] = {'repository_root': str(repository), 'nginx_sha256': digest(config)}
        controlled = {'services': {'nginx': {'volumes': [{'type': 'bind', 'source': str(config)}]}}}
        state = {}
        with patch.object(gate, 'selected_compose', return_value=controlled): result = gate.fenced_compose(self.plan, state)
        fenced = Path(result['services']['nginx']['volumes'][0]['source']); content = fenced.read_text()
        self.assertIn('"0:/healthz" 1', content); self.assertIn('return 503', content)
        self.assertIn('~^1: 1', content)
        token = gate.load_private(state['fence_token_file'])['token']
        self.assertEqual(len(token), 64); self.assertIn(token, content)
        self.assertNotIn(token, json.dumps(state)); self.assertEqual(fenced.stat().st_mode & 0o777, 0o600)

    def backup_attempt(self, matching=True):
        directory = Path(self.plan['directory']); directory.mkdir(mode=0o700)
        archive = self.archive({'application/config/config.php': 'config', 'application/config/security.php': 'security'})
        legacy = {service: {'Id': str(index) * 64, 'Image': 'sha256:' + str(index) * 64}
                  for index, service in enumerate(('app', 'db', 'nginx'), 1)}
        self.plan['_legacy'] = legacy; self.plan['ack_timeout'] = 30
        commands = []; state = {'transaction_id': 'attempt'}
        def docker(*args, **kwargs):
            commands.append(args)
            if args[0] == 'create': return b'a' * 64
            if args[0] == 'inspect':
                if len(args) == 3: return json.dumps([{'State': {'Running': False}}] * 2).encode()
                return json.dumps([{'Id': 'a' * 64, 'Config': {'Labels': {gate.LABEL: self.plan['_plan_sha256']}}, 'State': {'ExitCode': 0}}]).encode()
            if args[0] == 'cp':
                target = Path(args[2]); target.write_bytes(archive.read_bytes() if target.suffix == '.gz' else b'synthetic SQL')
            return b''
        def ack(plan, current, kind):
            return {'status': 'OFFHOST_HASH_VERIFIED', 'sha256': current['backup']['sha256'] if matching else {},
                    'destination_host_id': 'd' * 64}
        with patch.object(gate, 'legacy_state'), patch.object(gate, 'config_metadata', return_value={'prefix': 'custom_'}), \
             patch.object(gate, 'db_inventory', return_value=self.before), patch.object(gate, 'docker', side_effect=docker), \
             patch.object(gate, 'acknowledgement', side_effect=ack):
            failure = None
            try: gate.paired_backup(self.plan, state)
            except gate.GateError as error: failure = error
        return state, commands, failure

    def test_myisam_backup_fences_writers_and_requires_matching_offhost_pair(self):
        state, calls, failure = self.backup_attempt(matching=False)
        self.assertIsNotNone(failure); self.assertTrue(state['writers_fenced'])
        self.assertEqual(state['status'], 'BACKUP_READY')
        stop = next(index for index, call in enumerate(calls) if call[0] == 'stop')
        dump = next(index for index, call in enumerate(calls) if 'mariadb-dump' in str(call))
        self.assertLess(stop, dump); self.assertIn('--lock-all-tables', str(calls[dump]))
        self.assertNotIn('--single-transaction', str(calls[dump])); self.assertNotIn('--skip-lock-tables', str(calls[dump]))

    def test_valid_paired_backup_has_private_files_and_offhost_proof(self):
        state, _, failure = self.backup_attempt()
        self.assertIsNone(failure); self.assertEqual(state['status'], 'OFFHOST_VERIFIED')
        for name in ('database.sql', 'files.tar.gz'):
            path = Path(self.plan['directory']) / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(digest(path), state['backup']['sha256'][name])

    def test_migration_timeout_stops_only_recorded_owned_updater(self):
        Path(self.plan['directory']).mkdir(mode=0o700)
        self.plan['_candidate'] = {'project': 'candidate', 'images': {'php': 'signed-image'},
                                   'volumes': {key: 'owned-' + key for key in set(gate.VOLUMES) - {'db'}}}
        state = {'transaction_id': 'attempt', 'backup': {'inventory': self.before}}
        name = '/candidate-migration-attempt'; calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == 'ps': return b''
            if args[0] == 'wait': raise subprocess.TimeoutExpired('synthetic wait', 300)
            if args[0] == 'inspect': return json.dumps([{'Id': 'a' * 64, 'Name': name,
                'Config': {'Image': 'signed-image', 'Labels': {gate.LABEL: self.plan['_plan_sha256']}},
                'State': {'Running': False}, 'Mounts': [{'Type': 'volume', 'Name': 'owned-' + key,
                'Destination': target, 'RW': True} for key, target in gate.VOLUMES.items() if key != 'db']}]).encode()
            return b''
        with patch.object(gate, 'candidate_database'), patch.object(gate, 'db_inventory', return_value=self.before), \
             patch.object(gate, 'compose'), patch.object(gate, 'project_container', return_value='a' * 64), \
             patch.object(gate, 'load_private', return_value={'services': {'app': {}}, 'volumes': {}, 'networks': {}}), \
             patch.object(gate, 'docker', side_effect=docker), \
             patch.object(gate.subprocess, 'run'):
            with self.assertRaises(subprocess.TimeoutExpired): gate.migrate_candidate(self.plan, state, 'db', 'compose')
        self.assertIn(('stop', '-t', '10', 'a' * 64), calls)
        self.assertEqual(state['migration_container'], 'a' * 64)
        self.assertEqual((Path(self.plan['directory']) / 'migration.private.log').stat().st_mode & 0o777, 0o600)

    def test_valid_production_transaction_requires_fenced_and_open_proofs(self):
        candidate_path = self.root / 'candidate.json'; write(candidate_path, {'status': 'PREPARED'})
        candidate = {'project': 'candidate', 'state_file': str(candidate_path), 'images': {'php': 'signed-php'}, 'configuration_commit': 'c' * 40}
        self.plan.update(_candidate=candidate, rehearsal_receipt='proof', rehearsal_receipt_sha256='a' * 64,
                         candidate_manifest='candidate', candidate_manifest_sha256='b' * 64)
        selected = {'application/config/security.php': 'security-hash'}
        def backup(plan, state):
            state['backup'] = {'inventory': self.before}; state['writers_fenced'] = True
            return state['backup']
        def ack(plan, state, kind):
            common = {'admin': 'PASS', 'public': 'PASS', 'persistence': 'PASS', 'security_sha256': 'security-hash',
                      'default_theme_options': 'PASS'}
            if kind == 'restore-proof': return dict(common, status='RESTORE_FUNCTIONAL_PASS')
            if kind == 'production-proof': return dict(common, status='PRODUCTION_CORE_PASS', https='PASS', ordinary_requests_fenced='PASS', images=candidate['images'])
            self.assertEqual(kind, 'production-open-proof'); self.assertTrue(state['public_unfenced'])
            return {'status': 'PUBLIC_HEALTH_PASS', 'https': 'PASS'}
        with patch.object(gate, 'provider_gate'), patch.object(gate, 'manifest'), patch.object(gate, 'paired_backup', side_effect=backup), \
             patch.object(gate, 'prepare'), patch.object(gate, 'selected_compose', return_value={}), \
             patch.object(gate, 'fenced_compose', return_value={}), patch.object(gate, 'compose'), \
             patch.object(gate, 'wait_db', return_value='db'), patch.object(gate, 'import_database'), \
             patch.object(gate, 'restore_files', return_value=selected), patch.object(gate, 'migrate_candidate'), \
             patch.object(gate, 'wait_runtime', return_value={'db': {'id': 'db'}}), patch.object(gate, 'wait_production', return_value={}), patch.object(gate, 'acknowledgement', side_effect=ack):
            result = gate.recovery_transaction(self.plan)
        self.assertEqual(result, {'status': 'PROMOTED_CORE_VERIFIED', 'mail_delivery': 'UNKNOWN'})
        state = gate.load_private(self.plan['state_file'])
        self.assertEqual(state['status'], 'PROMOTED_CORE_VERIFIED'); self.assertFalse(state['writers_fenced'])
        self.assertTrue(state['public_unfenced']); self.assertIn('elapsed_seconds', state)

    def test_failed_promotion_stops_candidate_and_preserves_state(self):
        self.plan.update(rehearsal_receipt='proof', rehearsal_receipt_sha256='a' * 64,
                         _candidate={'project': 'candidate'})
        def backup(plan, state):
            state['writers_fenced'] = True
            Path(plan['directory'], 'production.compose.private.json').write_text('{}')
            raise gate.GateError('synthetic failed attempt')
        with patch.object(gate, 'provider_gate'), patch.object(gate, 'paired_backup', side_effect=backup), \
             patch.object(gate, 'compose') as command:
            with self.assertRaises(gate.GateError): gate.recovery_transaction(self.plan)
        self.assertEqual(command.call_args.args[2:], ('stop', 'app', 'nginx'))
        state = gate.load_private(self.plan['state_file'])
        self.assertEqual(state['status'], 'FAILED_PRESERVED'); self.assertTrue(state['fence_stop_verified'])
        self.assertTrue(state['writers_fenced'])


if __name__ == '__main__': unittest.main()
