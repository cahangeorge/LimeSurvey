"""Synthetic Docker observations; actual component validators and mocked Cosign transport."""
import copy
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


gate = module('nginx_maintenance', ROOT / 'scripts/delivery/nginx-maintenance.py')
fixtures = module('maintenance_component_fixture', ROOT / 'tests/test_staging_release_gate.py')
NOW = fixtures.NOW


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.StagingGateTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.project = 'ls-oci-example-20261022'
        self.adapter = self.root / 'compose.yaml'
        self.nginx_config = self.root / 'default.conf'
        self.proxy = self.root / 'proxy.yaml'
        for path in (self.adapter, self.nginx_config, self.proxy):
            path.write_text('synthetic non-secret configuration')
        self.config = {'name': self.project,
                       'services': {s: {'image': 'ghcr.io/example/' + s + '@sha256:' + 'f' * 64}
                                    for s in gate.SERVICES},
                       'networks': {n: {'name': self.project + '-' + n} for n in
                                    ('application', 'database', 'egress', 'proxy')},
                       'volumes': {'code': {'name': self.project + '-code'}}}
        self.config['services']['nginx'].update(
            image=gate.REPOSITORY + '@sha256:' + 'e' * 64,
            command=None, entrypoint=None, cpus=0.25, mem_limit='134217728',
            depends_on={'app': {'condition': 'service_healthy'}},
            healthcheck={'test': ['CMD', 'wget', '--spider', 'http://127.0.0.1/healthz']},
            labels={'traefik.enable': 'false'}, networks={'application': None, 'proxy': None},
            platform='linux/arm64', read_only=True, restart='unless-stopped',
            tmpfs=['/var/cache/nginx', '/var/run'],
            ports=[{'host_ip': '127.0.0.1', 'mode': 'ingress', 'protocol': 'tcp',
                    'published': '18871', 'target': 80}],
            volumes=[{'type': 'bind', 'source': str(self.nginx_config),
                      'target': '/etc/nginx/conf.d/default.conf', 'read_only': True}])
        for name in ('code', 'upload', 'plugins', 'themes', 'runtime'):
            self.config['volumes'][name] = {'name': self.project + '-' + name}
            self.config['services']['nginx']['volumes'].append(
                {'type': 'volume', 'source': name, 'target': '/var/www/html/' + name, 'read_only': True})
        self.hashes = dict(zip(('app', 'db', 'nginx'), ('a' * 64, 'b' * 64, 'c' * 64)))
        self.candidate = self.fixture.bundle['components']['nginx']
        self.changed = copy.deepcopy(self.config)
        self.changed['services']['nginx']['image'] = self.candidate['image']
        self.containers = {}
        for index, service in enumerate(('app', 'db', 'nginx', 'canary'), 1):
            identifier = str(index) * 64
            nets = {} if service == 'db' else {self.project + '-application':
                    {'Aliases': ['app'] if service == 'app' else [service], 'IPAddress': '10.0.0.' + str(index)}}
            self.containers[identifier] = {'Id': identifier, 'Name': '/' + self.project + '-' + service + '-1',
                'Image': 'sha256:' + str(index) * 64, 'RestartCount': 0,
                'Config': {'Image': self.config['services'].get(service, {}).get('image', self.candidate['image']),
                           'Labels': {'com.docker.compose.project': self.project,
                                      'com.docker.compose.service': service, 'traefik.enable': 'false',
                                      'com.docker.compose.config-hash': self.hashes.get(service, 'd' * 64)},
                           'Entrypoint': ['/docker-entrypoint.sh'], 'Cmd': ['nginx', '-g', 'daemon off;']},
                'HostConfig': {'ReadonlyRootfs': True, 'PortBindings': {},
                               'NanoCpus': 250000000, 'Memory': 134217728, 'MemorySwap': 268435456,
                               'NetworkMode': self.project + '-application',
                               'Tmpfs': {'/var/cache/nginx': '', '/var/run': ''},
                               'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}},
                'Mounts': [{'Type': 'bind', 'Source': str(self.nginx_config),
                            'Destination': '/etc/nginx/conf.d/default.conf', 'RW': False}],
                'NetworkSettings': {'Networks': nets},
                'State': {'Status': 'running', 'Health': {'Status': 'healthy'}, 'StartedAt': NOW.isoformat()}}
        for identifier in ('3' * 64, '4' * 64):
            self.containers[identifier]['Mounts'].extend(
                {'Type': 'volume', 'Name': self.project + '-' + name,
                 'Source': '/synthetic/' + name, 'Destination': '/var/www/html/' + name, 'RW': False}
                for name in ('code', 'upload', 'plugins', 'themes', 'runtime'))
        self.containers['3' * 64]['NetworkSettings']['Networks'][self.project + '-proxy'] = {'Aliases': ['nginx']}
        ports = {'80/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '18871'}]}
        self.containers['3' * 64]['NetworkSettings']['Ports'] = ports
        self.containers['3' * 64]['HostConfig']['PortBindings'] = ports
        self.containers['4' * 64]['Image'] = self.candidate['image_config_digest']
        self.containers['4' * 64]['Config']['Labels'] = {'traefik.enable': 'false'}
        self.containers['5' * 64] = copy.deepcopy(self.containers['3' * 64])
        self.containers['5' * 64].update(Id='5' * 64, Name='/synthetic-proxy')
        self.containers['5' * 64]['Mounts'][0]['Source'] = str(self.root)
        self.containers['5' * 64]['NetworkSettings']['Networks'] = {self.project + '-proxy': {'Aliases': ['proxy']}}
        self.networks = {n['name']: {'Name': n['name'], 'Containers': {
            cid: {} for cid, c in self.containers.items() if n['name'] in c['NetworkSettings']['Networks']}}
            for n in self.config['networks'].values()}
        self.volumes = {v['name']: {'Name': v['name']} for v in self.config['volumes'].values()}
        self.nginx_dump = b'# synthetic config\nfastcgi_pass app:9000;\n'
        self.body = b'<html>LimeSurvey<form><input type="password"></form></html>'
        self.expected = {'schema_version': 1, 'observed_at': NOW.isoformat(), 'project': self.project,
                         'source_commit': fixtures.SHA, 'gate_commit': 'b' * 40, 'candidate': self.candidate,
                         'adapter': str(self.adapter), 'proxy_config': str(self.proxy),
                         'current_env': str(self.root / 'old.env'), 'candidate_env': str(self.root / 'new.env'),
                         'compose_sha256': gate.fingerprint(self.config),
                         'proxy_container': {'id': '5' * 64, 'sha256': gate.container_fingerprint(self.containers['5' * 64])},
                         'rollback_image': self.config['services']['nginx']['image'],
                         'files_sha256': {str(p): gate.digest(p.read_bytes()) for p in
                                          (self.adapter, self.nginx_config, self.proxy)},
                         'containers': {s: {'id': str(i) * 64, 'sha256': gate.container_fingerprint(self.containers[str(i) * 64])}
                                        for i, s in enumerate(('app', 'db', 'nginx'), 1)},
                         'volumes': {n: gate.fingerprint(v) for n, v in self.volumes.items()},
                         'networks': {n: gate.fingerprint(v) for n, v in self.networks.items()},
                         'canary': {'id': '4' * 64,
                                    'sha256': gate.container_fingerprint(self.containers['4' * 64]),
                                    'nginx_config_sha256': gate.digest(self.nginx_dump)}}
        self.calls = []
        self.commands = patch.object(gate, 'command', side_effect=self.command)
        self.commands.start(); self.addCleanup(self.commands.stop)
        self.renders = patch.object(gate, 'render', side_effect=lambda a, e:
                                    copy.deepcopy(self.config if e.endswith('old.env') else self.changed))
        self.renders.start(); self.addCleanup(self.renders.stop)
        self.initializer = patch.object(gate, 'initialize', return_value=fixtures.gate)
        self.initializer.start(); self.addCleanup(self.initializer.stop)
        self.hash_reader = patch.object(gate, 'compose_hashes', side_effect=lambda a, e: self.hashes.copy())
        self.hash_reader.start(); self.addCleanup(self.hash_reader.stop)
        self.cosign = patch.object(fixtures.gate.signing, 'cosign', side_effect=self.fixture.cosign)
        self.cosign.start(); self.addCleanup(self.cosign.stop)
        self.clock = patch.object(gate, 'datetime')
        self.clock.start().now.return_value = NOW
        self.addCleanup(self.clock.stop)

    def command(self, args, env=None):
        self.calls.append(args)
        if args[1:3] == ['container', 'inspect']:
            return json.dumps([self.containers[args[3]]]).encode()
        if args[1:3] == ['image', 'inspect']:
            if args[3] == self.candidate['image']:
                return json.dumps([{'Id': self.candidate['image_config_digest'], 'RepoDigests': [self.candidate['image']]}]).encode()
            return json.dumps([{'Id': self.containers['3' * 64]['Image'],
                                'RepoDigests': [self.config['services']['nginx']['image']],
                                'Architecture': 'arm64', 'Os': 'linux',
                                'Config': {'Cmd': ['nginx', '-g', 'daemon off;'],
                                           'Entrypoint': ['/docker-entrypoint.sh']}}]).encode()
        if args[1:3] == ['network', 'inspect']:
            return json.dumps([self.networks[args[3]]]).encode()
        if args[1:3] == ['volume', 'inspect']:
            return json.dumps([self.volumes[args[3]]]).encode()
        if args[1] == 'ps':
            return ('\n'.join(str(i) * 64 for i in range(1, 4)) + '\n').encode()
        if args[1] == 'exec':
            return self.nginx_dump if args[3] == 'nginx' else self.body
        raise AssertionError(args)

    def check(self, sha=None, now=NOW):
        path = self.root / 'maintenance.json'
        path.write_text(json.dumps(self.expected)); path.chmod(0o600)
        return gate.evaluate(path, sha or gate.digest(path.read_bytes()), now, self.root, 'b' * 40)

    def rebind_canary(self):
        self.expected['canary']['sha256'] = gate.container_fingerprint(self.containers['4' * 64])

    def test_component_real_validators_pass_without_bundle_or_deploy(self):
        with patch.object(fixtures.gate, 'component', wraps=fixtures.gate.component) as component:
            result = self.check()
        self.assertEqual(result['status'], 'NGINX_MAINTENANCE_PREFLIGHT_PASS')
        self.assertEqual(result['production'], 'HOLD')
        self.assertEqual(component.call_args.args[1:3], ('nginx', fixtures.SHA))
        self.assertTrue(any(c[1] == 'exec' and c[3] == 'wget' for c in self.calls))
        self.assertFalse(any(c[1] in ('run', 'create', 'stop', 'rm', 'compose') for c in self.calls))

    def test_bad_external_manifest_hash(self):
        with self.assertRaises(ValueError): self.check('0' * 64)

    def test_stale_and_future_manifest(self):
        for offset in (-901, 1):
            with self.subTest(offset=offset):
                self.expected['observed_at'] = (NOW + timedelta(seconds=offset)).isoformat()
                with self.assertRaises(ValueError): self.check()

    def test_every_extra_compose_change_rejected(self):
        mutations = [lambda c: c['services']['app'].update(image='other'),
                     lambda c: c['services']['nginx'].update(command=['sh']),
                     lambda c: c['volumes']['code'].update(name='other'),
                     lambda c: c['networks']['proxy'].update(name='other'),
                     lambda c: c['services']['db'].update(environment={'password': 'other'})]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.changed); mutate(value)
                with self.assertRaises(ValueError): gate.compose_pair(self.config, value, self.expected)

    def test_runtime_identity_or_health_drift(self):
        for service in ('app', 'db', 'nginx'):
            identifier = self.expected['containers'][service]['id']
            original = copy.deepcopy(self.containers[identifier])
            for key, value in [('Image', 'sha256:' + '9' * 64), ('State', {'Status': 'exited'})]:
                with self.subTest(service=service, key=key):
                    self.containers[identifier][key] = value
                    with self.assertRaises((ValueError, KeyError)): self.check()
                    self.containers[identifier] = copy.deepcopy(original)

    def test_proxy_container_drift(self):
        self.containers['5' * 64]['RestartCount'] += 1
        with self.assertRaises(ValueError): self.check()

    def test_local_runtime_manifest_identity(self):
        original = self.command
        def image_changed(args, env=None):
            if args[1:3] == ['image', 'inspect'] and args[3] == self.candidate['image']:
                return json.dumps([{'Id': self.candidate['image_config_digest'], 'RepoDigests': ['different']}]).encode()
            return original(args, env)
        with patch.object(gate, 'command', side_effect=image_changed):
            with self.assertRaises(ValueError): self.check()

    def test_missing_or_changed_proxy_config(self):
        self.proxy.write_text('changed route')
        with self.assertRaises(ValueError): self.check()

    def test_network_or_volume_fingerprint_drift(self):
        for collection in (self.networks, self.volumes):
            name = next(iter(collection)); old = copy.deepcopy(collection[name])
            collection[name]['Driver'] = 'changed'
            with self.assertRaises(ValueError): self.check()
            collection[name] = old

    def test_signature_and_evidence_not_bypassed(self):
        for field in ('release_sha256', 'signing_sha256'):
            old = self.candidate[field]; self.candidate[field] = '0' * 64
            with self.assertRaises(ValueError): self.check()
            self.candidate[field] = old
        with patch.object(fixtures.gate.signing, 'cosign', side_effect=ValueError('denied')):
            with self.assertRaises(ValueError): self.check()

    def test_canary_runtime_constraints_even_with_rebound_fingerprint(self):
        mutations = [lambda c: c['Config'].update(Image=self.expected['rollback_image']),
                     lambda c: c.update(Image='sha256:' + '9' * 64),
                     lambda c: c['HostConfig'].update(PortBindings={'80/tcp': [{'HostPort': '8080'}]}),
                     lambda c: c['Config']['Labels'].update({'traefik.http.routers.bad.rule': 'Host(`example.test`)'}),
                     lambda c: c['HostConfig'].update(ExtraHosts=['app:10.1.2.3']),
                     lambda c: c['HostConfig'].update(Dns=['1.2.3.4']),
                     lambda c: c['HostConfig'].update(ReadonlyRootfs=False),
                     lambda c: c['Mounts'][0].update(RW=True),
                     lambda c: c['NetworkSettings'].update(Networks={'other': {}})]
        original = copy.deepcopy(self.containers['4' * 64])
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.containers['4' * 64] = copy.deepcopy(original)
                mutate(self.containers['4' * 64]); self.rebind_canary()
                with self.assertRaises(ValueError): self.check()
        self.containers['4' * 64] = original

    def test_ambiguous_or_wrong_fpm_alias(self):
        app = self.containers['1' * 64]
        app['NetworkSettings']['Networks'][self.project + '-application']['Aliases'] = ['other']
        self.expected['containers']['app']['sha256'] = gate.container_fingerprint(app)
        with self.assertRaises(ValueError): self.check()
        app['NetworkSettings']['Networks'][self.project + '-application']['Aliases'] = ['app']
        self.expected['containers']['app']['sha256'] = gate.container_fingerprint(app)
        self.containers['4' * 64]['NetworkSettings']['Networks'][self.project + '-application']['Aliases'] = ['app']
        self.rebind_canary()
        with self.assertRaises(ValueError): self.check()

    def test_static_health_or_error_page_insufficient(self):
        for body in (b'ok', b'502 Bad Gateway', b'<form>password</form>'):
            self.body = body
            with self.assertRaises(ValueError): self.check()

    def test_post_probe_runtime_drift_rejected(self):
        original = self.command
        def drift(args, env=None):
            output = original(args, env)
            if args[1] == 'exec' and args[3] == 'wget':
                self.containers['1' * 64]['Image'] = 'sha256:' + '9' * 64
            return output
        with patch.object(gate, 'command', side_effect=drift):
            with self.assertRaises(ValueError): self.check()

    def test_rebound_compose_cannot_change_live_command_or_public_port(self):
        for key, value in [('command', ['sh', '-c', 'serve unexpected content']),
                           ('ports', [{'host_ip': '0.0.0.0', 'mode': 'ingress',
                                       'protocol': 'tcp', 'published': '18871', 'target': 80}])]:
            original = copy.deepcopy(self.config['services']['nginx'])
            self.config['services']['nginx'][key] = value
            self.changed['services']['nginx'][key] = value
            self.expected['compose_sha256'] = gate.fingerprint(self.config)
            with self.subTest(key=key), self.assertRaises(ValueError): self.check()
            self.config['services']['nginx'] = original
            self.changed['services']['nginx'] = copy.deepcopy(original)
            self.changed['services']['nginx']['image'] = self.candidate['image']

    def test_each_live_compose_hash_required(self):
        for service in ('app', 'db', 'nginx'):
            original = self.hashes[service]
            self.hashes[service] = '9' * 64
            with self.subTest(service=service), self.assertRaises(ValueError): self.check()
            self.hashes[service] = original

    def test_unsupported_old_rendered_settings_rejected(self):
        self.config['services']['nginx']['security_opt'] = ['seccomp:unconfined']
        self.changed['services']['nginx']['security_opt'] = ['seccomp:unconfined']
        self.expected['compose_sha256'] = gate.fingerprint(self.config)
        with self.assertRaises(ValueError): self.check()

    def test_each_live_nginx_mapping_checked_after_rebound_fingerprint(self):
        original = copy.deepcopy(self.containers['3' * 64])
        mutations = [lambda c: c['HostConfig'].update(ReadonlyRootfs=False),
                     lambda c: c['HostConfig'].update(Tmpfs={}),
                     lambda c: c['HostConfig'].update(RestartPolicy={'Name': 'always', 'MaximumRetryCount': 0}),
                     lambda c: c['HostConfig'].update(NanoCpus=0),
                     lambda c: c['HostConfig'].update(Memory=0),
                     lambda c: c['HostConfig'].update(NetworkMode='host'),
                     lambda c: c['HostConfig'].update(PortBindings={}),
                     lambda c: c['Mounts'][0].update(Source='/different/config'),
                     lambda c: c['NetworkSettings']['Networks'].pop(self.project + '-proxy')]
        for mutate in mutations:
            self.containers['3' * 64] = copy.deepcopy(original)
            mutate(self.containers['3' * 64])
            self.expected['containers']['nginx']['sha256'] = gate.container_fingerprint(self.containers['3' * 64])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): self.check()

    def test_canary_namespaces_security_and_limits(self):
        original = copy.deepcopy(self.containers['4' * 64])
        mutations = [('PidMode', 'host'), ('PidMode', 'container:' + '1' * 64),
                     ('IpcMode', 'host'), ('IpcMode', 'container:' + '1' * 64),
                     ('NetworkMode', 'host'), ('NetworkMode', 'container:' + '1' * 64),
                     ('SecurityOpt', ['seccomp:unconfined']), ('SecurityOpt', ['apparmor:unconfined']),
                     ('Memory', 0), ('MemorySwap', -1), ('NanoCpus', 0), ('CpuQuota', -1)]
        for key, value in mutations:
            self.containers['4' * 64] = copy.deepcopy(original)
            self.containers['4' * 64]['HostConfig'][key] = value
            self.rebind_canary()
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): self.check()

    def test_omitted_docker_resource_controls_rejected_even_when_rebound(self):
        settings = [('PidsLimit', 64), ('MemorySwappiness', 0), ('CpuCount', 1),
                    ('CpuPercent', 50), ('BlkioWeight', 100),
                    ('BlkioWeightDevice', [{'Path': '/dev/synthetic', 'Weight': 100}]),
                    ('BlkioDeviceReadBps', [{'Path': '/dev/synthetic', 'Rate': 1024}]),
                    ('BlkioDeviceWriteBps', [{'Path': '/dev/synthetic', 'Rate': 1024}]),
                    ('BlkioDeviceReadIOps', [{'Path': '/dev/synthetic', 'Rate': 10}]),
                    ('BlkioDeviceWriteIOps', [{'Path': '/dev/synthetic', 'Rate': 10}]),
                    ('IOMaximumIOps', 10), ('IOMaximumBandwidth', 1024),
                    ('DeviceRequests', [{'Count': 1}]), ('DeviceCgroupRules', ['c 1:3 r']),
                    ('Rdma', {'synthetic': {'HcaHandles': 1}}), ('Unified', {'pids.max': '64'}),
                    ('Ulimits', [{'Name': 'nofile', 'Soft': 64, 'Hard': 64}]),
                    ('KernelMemoryTCP', 1024), ('CgroupParent', 'different'), ('OomScoreAdj', 1)]
        for identifier in ('3' * 64, '4' * 64):
            original = copy.deepcopy(self.containers[identifier])
            for key, value in settings:
                self.containers[identifier] = copy.deepcopy(original)
                self.containers[identifier]['HostConfig'][key] = value
                if identifier == '3' * 64:
                    self.expected['containers']['nginx']['sha256'] = gate.container_fingerprint(self.containers[identifier])
                else:
                    self.rebind_canary()
                with self.subTest(container=identifier[0], key=key), self.assertRaises(ValueError): self.check()
            self.containers[identifier] = original
            if identifier == '3' * 64:
                self.expected['containers']['nginx']['sha256'] = gate.container_fingerprint(original)
            else:
                self.rebind_canary()

    def test_canary_unhealthy_only_after_probe_rejected(self):
        original = self.command
        def unhealthy_after_probe(args, env=None):
            result = original(args, env)
            if args[1] == 'exec' and args[3] == 'wget':
                self.containers['4' * 64]['State']['Health']['Status'] = 'unhealthy'
            return result
        with patch.object(gate, 'command', side_effect=unhealthy_after_probe):
            with self.assertRaises(ValueError): self.check()

    def test_cli_errors_do_not_print_sensitive_input(self):
        result = subprocess.run(['python3', str(ROOT / 'scripts/delivery/nginx-maintenance.py'),
                                 '--expected', '/missing/operator-secret-value', '--expected-sha256', 'bad',
                                 '--gate-repository', '/missing/repository', '--gate-commit', 'bad'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('operator-secret-value', result.stderr + result.stdout)


class GateSourceTests(unittest.TestCase):
    def test_validator_import_cannot_run_before_source_identity(self):
        with patch.object(gate, 'reviewed_gate', side_effect=ValueError('wrong source')) as check, patch.object(
                gate.importlib.util, 'spec_from_file_location') as imports:
            with self.assertRaises(ValueError): gate.initialize(Path('/approved/repository'), 'b' * 40)
        check.assert_called_once()
        imports.assert_not_called()

    def test_clean_separate_gate_commit_and_all_transitive_files(self):
        commit = 'b' * 40
        def git(args, env=None):
            if 'rev-parse' in args: return commit.encode()
            if 'show' in args: return (ROOT / args[-1].split(':', 1)[1]).read_bytes()
            return b''
        with patch.object(gate, 'command', side_effect=git) as commands:
            gate.reviewed_gate(Path('/approved/repository'), commit)
        shown = {call.args[0][-1].split(':', 1)[1] for call in commands.call_args_list
                 if 'show' in call.args[0]}
        self.assertEqual(shown, set(gate.GATE_FILES))

    def test_wrong_gate_commit_dirty_source_and_untracked_source_rejected(self):
        def git(args, env=None):
            if 'rev-parse' in args: return ('b' * 40).encode()
            if 'ls-files' in args: return b'untracked-validator.py'
            return b''
        with patch.object(gate, 'command', side_effect=git):
            with self.assertRaises(ValueError): gate.reviewed_gate(Path('/approved/repository'), 'a' * 40)
            with self.assertRaises(ValueError): gate.reviewed_gate(Path('/approved/repository'), 'b' * 40)
        with patch.object(gate, 'command', side_effect=[('b' * 40).encode(), subprocess.CalledProcessError(1, 'git')]):
            with self.assertRaises(subprocess.SubprocessError):
                gate.reviewed_gate(Path('/approved/repository'), 'b' * 40)

    def test_changed_gate_file_rejected(self):
        with patch.object(gate, 'command', side_effect=[('b' * 40).encode(), b'', b'', b'changed script']):
            with self.assertRaises(ValueError): gate.reviewed_gate(Path('/approved/repository'), 'b' * 40)

    def test_compose_hash_transport_parses_exact_services(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / 'private.env'; env.write_text('synthetic'); env.chmod(0o600)
            valid = '\n'.join(s + ' ' + c * 64 for s, c in [('app', 'a'), ('db', 'b'), ('nginx', 'c')]).encode()
            with patch.object(gate, 'command', return_value=valid) as transport:
                self.assertEqual(set(gate.compose_hashes('/adapter', env)), gate.SERVICES)
            self.assertEqual(transport.call_args.args[0][-3:], ['config', '--hash', '*'])
            for invalid in (b'', valid + b'\napp ' + b'a' * 64, b'app invalid'):
                with patch.object(gate, 'command', return_value=invalid):
                    with self.assertRaises(ValueError): gate.compose_hashes('/adapter', env)


if __name__ == '__main__':
    unittest.main()
