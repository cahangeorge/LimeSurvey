"""Offline fail-closed schema717 transfer checks. No real Docker or private data."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('crosshost', ROOT / 'scripts/delivery/crosshost.py')
gate = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(gate)


class CrosshostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.plan = {'version': 1, 'schema': 717, 'transaction': 'synthetictransaction', 'prefix': 'lime_',
            'directory': str(self.root), 'hosts': {'source': 'a' * 64, 'target': 'b' * 64},
            'custom_plugins': [], 'custom_themes': []}
        for role, char in (('source', 'c'), ('target', 'd')):
            config = self.root / (role + '-nginx.conf'); config.write_text('synthetic config')
            self.plan[role] = {'nginx_config': {'path': str(config), 'sha256': gate.op.file_hash(config)}, 'volumes': {kind: role + '-' + kind for kind in gate.op.VOLUMES}, 'containers': {
                service: {'id': str(index) + char * 63, 'image_id': 'sha256:' + char * 64,
                          'image': 'example.invalid/' + service + '@sha256:' + char * 64,
                          'networks': [role + ('-frontend' if role == 'source' and service == 'nginx' else '-backend')]}
                for index, service in enumerate(('app', 'nginx', 'db'), 1)}}
        self.path = self.root / 'plan.json'
        self.write(self.path, self.plan)
        self.value = gate.load_plan(self.path, gate.op.file_hash(self.path))

    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def archive(self, extra=None):
        entries = {'application/config/config.php': b'synthetic config',
                   'application/config/security.php': b'synthetic encryption identity',
                   'upload/file.txt': b'synthetic upload', 'application/core/old.php': b'old code'}
        if extra: entries.update(extra)
        target = self.root / 'files.tar.gz'
        with tarfile.open(target, 'w:gz') as archive:
            for name, body in entries.items():
                member = tarfile.TarInfo(name); member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        target.chmod(0o600)
        return target

    def pair(self):
        self.archive()
        dump = self.root / 'database.sql'; dump.write_bytes(b'synthetic SQL'); dump.chmod(0o600)
        pair = {'status': 'PAIRED_SCHEMA717_BACKUP', 'transaction': self.value['transaction'],
                'plan_sha256': self.value['_sha256'], 'source_host': self.value['hosts']['source'],
                'inventory': {'schema': 717, 'prefix': 'lime_'},
                'files': gate.selected_files(self.value, self.root / 'files.tar.gz'),
                'sha256': {name: gate.op.file_hash(self.root / name) for name in ('database.sql', 'files.tar.gz')}}
        self.write(self.root / 'backup.json', pair)
        return pair

    def actual(self, role, service, stopped=True):
        expected = self.value[role]['containers'][service]
        kinds = ('db',) if service == 'db' else tuple(gate.op.VOLUMES)[1:] if service == 'app' else ('code', 'upload', 'plugins', 'themes', 'runtime')
        mounts = [{'Type': 'volume', 'Destination': gate.op.VOLUMES[kind],
                   'Name': self.value[role]['volumes'][kind], 'RW': service != 'nginx'} for kind in kinds]
        if service == 'nginx': mounts.append({'Type': 'bind', 'Source': self.value[role]['nginx_config']['path'], 'Destination': '/etc/nginx/conf.d/default.conf', 'RW': False})
        return {'Id': expected['id'], 'Image': expected['image_id'], 'Config': {'Image': expected['image'], 'Labels': {}},
                'Mounts': mounts, 'HostConfig': {'PortBindings': {}},
                'NetworkSettings': {'Networks': {name: {} for name in expected['networks']}},
                'State': {'Running': service == 'db' or not stopped}}

    def test_plan_schema_identity_and_permissions_reject_without_docker(self):
        changes = [lambda p: p.update(schema=712), lambda p: p['hosts'].update(target=p['hosts']['source']),
                   lambda p: p['target']['volumes'].update(db=p['source']['volumes']['db']),
                   lambda p: p['target']['containers']['db'].update(id='short'),
                   lambda p: p.update(custom_plugins=['../escape'])]
        with patch.object(gate.op, 'docker') as docker:
            for change in changes:
                value = copy.deepcopy(self.plan); change(value); self.write(self.path, value)
                with self.assertRaises(ValueError): gate.load_plan(self.path, gate.op.file_hash(self.path))
            self.write(self.path, self.plan); self.path.chmod(0o644)
            with self.assertRaises(ValueError): gate.load_plan(self.path, gate.op.file_hash(self.path))
            docker.assert_not_called()

    def test_directory_symlink_or_public_mode_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): gate.private_directory(self.root)
        self.root.chmod(0o700)
        link = self.root / 'alias'; link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): gate.private_directory(link)

    def test_archive_excludes_old_code_but_preserves_security(self):
        archive = self.archive(); selected = gate.selected_files(self.value, archive)
        self.assertEqual(set(selected), {'application/config/config.php', 'application/config/security.php', 'upload/file.txt'})
        self.assertEqual(selected['application/config/security.php'], hashlib.sha256(b'synthetic encryption identity').hexdigest())

    def test_archive_traversal_or_link_fails(self):
        with self.assertRaises(ValueError): gate.selected_files(self.value, self.archive({'../escape': b'bad'}))
        path = self.archive()
        with tarfile.open(path, 'w:gz') as archive:
            for name in ('application/config/config.php', 'application/config/security.php'):
                item = tarfile.TarInfo(name); item.size = 1; archive.addfile(item, io.BytesIO(b'x'))
            item = tarfile.TarInfo('upload/linked'); item.type = tarfile.SYMTYPE; item.linkname = '../application/config'; archive.addfile(item)
        with self.assertRaises(ValueError): gate.selected_files(self.value, path)

    def test_pair_corruption_or_mixed_schema_rejected_before_restore_mutation(self):
        self.pair()
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['target']), patch.object(gate.op, 'docker') as docker:
            (self.root / 'database.sql').write_bytes(b'changed')
            with self.assertRaises(ValueError): gate.restore(self.value)
            docker.assert_not_called()
        pair = self.pair(); pair['inventory']['schema'] = 718; self.write(self.root / 'backup.json', pair)
        with self.assertRaises(ValueError): gate.receipt(self.value)

    def test_inspect_rejects_wrong_identity_mount_network_port_or_writer(self):
        originals = {service: self.actual('target', service) for service in ('app', 'nginx', 'db')}
        def inspect(*args, **kwargs):
            if args[0] == 'ps': return b''
            if args[0] == 'network': return json.dumps([{'Name': args[2], 'Driver': 'bridge', 'Containers': {}}]).encode()
            return json.dumps([next(item for item in current.values() if item['Id'] == args[1])]).encode()
        changes = [lambda p: p['app'].update(Image='sha256:' + 'f' * 64),
                   lambda p: p['app']['Mounts'][0].update(Name='unrelated'),
                   lambda p: p['db']['HostConfig'].update(PortBindings={'3306/tcp': [{'HostIp': '0.0.0.0'}]}),
                   lambda p: p['nginx']['HostConfig'].update(PortBindings={'80/tcp': [{'HostIp': '0.0.0.0'}]}),
                   lambda p: p['app']['State'].update(Running=True),
                   lambda p: p['app']['NetworkSettings'].update(Networks={'unknown': {}}),
                   lambda p: p['nginx']['Config'].update(Labels={'traefik.enable': 'true'})]
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['target']), patch.object(gate.op, 'docker', side_effect=inspect) as docker:
            current = originals; gate.inspect_side(self.value, 'target', stopped=True)
            for change in changes:
                current = copy.deepcopy(originals); change(current)
                with self.assertRaises(ValueError): gate.inspect_side(self.value, 'target', stopped=True)
            self.assertTrue(all(call.args[0] in ('inspect', 'ps', 'network') for call in docker.call_args_list))

    def test_wrong_host_fails_before_docker(self):
        with patch.object(gate, 'host_id', return_value='f' * 64), patch.object(gate.op, 'docker') as docker:
            with self.assertRaises(ValueError): gate.backup(self.value)
            with self.assertRaises(ValueError): gate.restore(self.value)
            docker.assert_not_called()

    def test_nonempty_target_and_partial_attempt_are_not_reset(self):
        self.pair()
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['target']), patch.object(gate, 'inspect_side', return_value={'db': {'Id': 'synthetic'}}), patch.object(gate.op, 'database', return_value=['existing_table']), patch.object(gate.op, 'docker') as docker:
            with self.assertRaises(ValueError): gate.restore(self.value)
            docker.assert_not_called(); self.assertFalse((self.root / 'restore-started.json').exists())
            self.write(self.root / 'restore-started.json', {})
            with self.assertRaises(ValueError): gate.restore(self.value)
            docker.assert_not_called()

    def test_wrong_source_schema_never_stops_writers(self):
        state = {service: self.actual('source', service, stopped=False) for service in ('app', 'nginx', 'db')}
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['source']), patch.object(gate, 'inspect_side', return_value=state), patch.object(gate.op, 'config_metadata', return_value={'prefix': 'lime_'}), patch.object(gate.op, 'db_inventory', return_value={'schema': 718}), patch.object(gate.op, 'docker') as docker:
            with self.assertRaises(ValueError): gate.backup(self.value)
            docker.assert_not_called(); self.assertFalse((self.root / 'backup-started.json').exists())


    def test_backup_pairs_after_writer_stop_and_never_resumes(self):
        state = {service: self.actual('source', service, stopped=False) for service in ('app', 'nginx', 'db')}
        inventory = {'schema': 717, 'prefix': 'lime_'}
        calls = []
        def docker(*args, **kwargs):
            calls.append(args)
            if args[0] == 'create': return ('e' * 64).encode()
            if args[0] == 'inspect': return json.dumps([{'Id': 'e' * 64, 'Config': {'Labels': {gate.LABEL: self.value['_sha256']}}, 'State': {'ExitCode': 0}}]).encode()
            if args[0] == 'cp': self.archive()
            return b''
        def dump(arguments, **kwargs):
            self.assertIn('--lock-all-tables', arguments[-1])
            self.assertNotIn('--single-transaction', arguments[-1])
            self.assertTrue(any(call[0] == 'stop' for call in calls))
            kwargs['stdout'].write(b'synthetic SQL')
            return type('Result', (), {'returncode': 0})()
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['source']), patch.object(gate, 'inspect_side', return_value=state), patch.object(gate.op, 'config_metadata', return_value={'prefix': 'lime_'}), patch.object(gate.op, 'db_inventory', return_value=inventory), patch.object(gate.op, 'docker', side_effect=docker), patch.object(gate.subprocess, 'run', side_effect=dump):
            result = gate.backup(self.value)
            self.assertEqual(result['inventory'], inventory)
            self.assertEqual(result['status'], 'PAIRED_SCHEMA717_BACKUP')
            self.assertTrue(all(call[0] != 'restart' for call in calls))
            self.assertEqual([call for call in calls if call[0] == 'start'], [('start', '-a', 'e' * 64)])

    def test_restore_success_is_idempotent_without_reimport(self):
        pair = self.pair()
        completed = type('Result', (), {'returncode': 0})()
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['target']), patch.object(gate, 'inspect_side', return_value={'db': {'Id': 'synthetic'}}), patch.object(gate.op, 'database', return_value=[]), patch.object(gate.op, 'db_inventory', return_value=pair['inventory']), patch.object(gate, 'helper') as helper, patch.object(gate.subprocess, 'run', return_value=completed) as process:
            first = gate.restore(self.value)
            second = gate.restore(self.value)
            self.assertEqual(first, second)
            self.assertEqual(process.call_count, 1)
            self.assertEqual(helper.call_count, 2)
            self.assertTrue(all('updatedb' not in str(call) for call in process.call_args_list))
            self.assertIn('readonly', str(helper.call_args_list[-1]))


    def test_source_database_network_and_port_drift_fails_before_mutation(self):
        originals = {service: self.actual('source', service, stopped=False) for service in ('app', 'nginx', 'db')}
        source = self.value['source']['containers']
        baseline = {'Name': 'source-backend', 'Driver': 'bridge', 'Internal': True,
                    'Containers': {source['app']['id']: {}, source['db']['id']: {}}}
        def docker(*args, **kwargs):
            if args[0] == 'ps': return b''
            if args[0] == 'network': return json.dumps([network]).encode()
            return json.dumps([next(item for item in current.values() if item['Id'] == args[1])]).encode()
        changes = [lambda c, n: c['db']['HostConfig'].update(PortBindings={'3306/tcp': [{'HostIp': '127.0.0.1'}]}),
                   lambda c, n: c['db']['NetworkSettings'].update(Ports={'3306/tcp': [{'HostIp': '0.0.0.0'}]}),
                   lambda c, n: c['db']['HostConfig'].update(PublishAllPorts=True),
                   lambda c, n: n.update(Internal=False),
                   lambda c, n: n['Containers'].update({'f' * 64: {}}),
                   lambda c, n: n['Containers'].update({source['nginx']['id']: {}})]
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['source']), patch.object(gate.op, 'docker', side_effect=docker) as calls:
            current = copy.deepcopy(originals); network = copy.deepcopy(baseline)
            gate.inspect_side(self.value, 'source')
            for change in changes:
                current = copy.deepcopy(originals); network = copy.deepcopy(baseline); change(current, network)
                with self.assertRaises(ValueError): gate.inspect_side(self.value, 'source')
                current['app']['State']['Running'] = False; current['nginx']['State']['Running'] = False
                with self.assertRaises(ValueError): gate.inspect_side(self.value, 'source', stopped=True)
            self.assertTrue(all(call.args[0] in ('inspect', 'ps', 'network') for call in calls.call_args_list))

    def test_validate_checks_host_runtime_and_schema(self):
        state = {service: self.actual('source', service, stopped=False) for service in ('app', 'nginx', 'db')}
        with patch.object(gate, 'host_id', return_value='f' * 64), patch.object(gate, 'inspect_side') as inspect:
            with self.assertRaises(ValueError): gate.preflight(self.value)
            inspect.assert_not_called()
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['source']), patch.object(gate, 'inspect_side', return_value=state) as inspect, patch.object(gate.op, 'config_metadata', return_value={'prefix': 'lime_'}), patch.object(gate.op, 'db_inventory', return_value={'schema': 718}):
            with self.assertRaises(ValueError): gate.preflight(self.value)
            inspect.assert_called_once_with(self.value, 'source')
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['source']), patch.object(gate, 'inspect_side', side_effect=ValueError('runtime drift')):
            with self.assertRaises(ValueError): gate.preflight(self.value)
        with patch.object(gate, 'host_id', return_value=self.value['hosts']['target']), patch.object(gate, 'inspect_side', return_value=state) as inspect, patch.object(gate.op, 'database', return_value=[]):
            gate.preflight(self.value)
            inspect.assert_called_once_with(self.value, 'target', stopped=True)


if __name__ == '__main__': unittest.main()
