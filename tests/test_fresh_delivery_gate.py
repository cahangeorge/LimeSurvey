"""Offline adversarial preflight guards; no daemon or live secrets needed."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('fresh', ROOT / 'scripts/delivery/fresh.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class FreshInstallTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.env = Path(directory.name) / 'synthetic.env'
        self.receipt = {'status': 'ARTIFACT_BUNDLE_ADMITTED', 'components': {}}
        values = {'OCI_PROJECT': 'ls-oci-synthetic', 'OCI_PROXY_NETWORK': 'synthetic-proxy',
                  'OCI_PROBE_PORT': '18482', 'OCI_DB_NAME': 'synthetic', 'OCI_DB_USER': 'synthetic',
                  'OCI_DB_PASSWORD': 'synthetic-password', 'OCI_DB_ROOT_PASSWORD': 'synthetic-root',
                  'OCI_RESEND_API_KEY': 'synthetic-key', 'OCI_RESEND_FROM_EMAIL': 'probe@example.invalid'}
        for index, (kind, repository) in enumerate(gate.REPOSITORIES.items(), 1):
            image = repository + '@sha256:' + str(index) * 64
            self.receipt['components'][kind] = {'image': image, 'scan': 'PASS', 'signatures': 'PASS'}
            values[{'php': 'OCI_APP_IMAGE', 'nginx': 'OCI_NGINX_IMAGE', 'mariadb': 'OCI_DB_IMAGE'}[kind]] = image
        self.env.write_text(''.join(key + '=' + value + '\n' for key, value in values.items()))
        self.env.chmod(0o600)
        project = values['OCI_PROJECT']
        self.config = {'name': project, 'services': {}, 'volumes': {}, 'networks': {}}
        for name in ('database', 'application', 'egress'):
            self.config['networks'][name] = {'name': project + '-' + name, 'internal': name != 'egress'}
        self.config['networks']['proxy'] = {'name': 'synthetic-proxy', 'external': True}
        paths = {'db-data': '/var/lib/mysql', 'app-code': '/var/www/html',
                 'app-config': '/var/www/html/application/config', 'app-upload': '/var/www/html/upload',
                 'app-plugins': '/var/www/html/plugins', 'app-themes': '/var/www/html/themes',
                 'app-runtime': '/var/www/html/tmp'}
        for name in paths:
            self.config['volumes'][name] = {'name': project + '-fresh-' + ('db' if name == 'db-data' else name[4:])}
        service_networks = {'db': ['database'], 'app': ['database', 'application', 'egress'],
                            'nginx': ['application', 'proxy']}
        service_volumes = {'db': ['db-data'], 'app': list(paths)[1:],
                           'nginx': ['app-code', 'app-upload', 'app-plugins', 'app-themes', 'app-runtime']}
        for service, kind in {'db': 'mariadb', 'app': 'php', 'nginx': 'nginx'}.items():
            self.config['services'][service] = {
                'image': self.receipt['components'][kind]['image'], 'platform': 'linux/arm64',
                'restart': 'unless-stopped', 'healthcheck': {'test': ['CMD', 'synthetic']},
                'networks': dict.fromkeys(service_networks[service]),
                'volumes': [{'type': 'volume', 'source': name, 'target': paths[name],
                             'read_only': service == 'nginx'} for name in service_volumes[service]]}
        self.config['services']['db']['environment'] = {
            'MARIADB_DATABASE': 'synthetic', 'MARIADB_USER': 'synthetic',
            'MARIADB_PASSWORD': 'synthetic-password', 'MARIADB_ROOT_PASSWORD': 'synthetic-root'}
        self.config['services']['app']['environment'] = {
            'DB_HOST': 'db', 'DB_PORT': '3306', 'DB_NAME': 'synthetic', 'DB_USER': 'synthetic',
            'DB_PASSWORD': 'synthetic-password', 'RESEND_API_KEY': 'synthetic-key',
            'RESEND_FROM_EMAIL': 'probe@example.invalid'}
        nginx = self.config['services']['nginx']
        nginx.update(read_only=True, labels={'traefik.enable': 'false'},
                     ports=[{'host_ip': '127.0.0.1', 'target': 80, 'published': '18482', 'protocol': 'tcp'}])
        nginx['volumes'].append({'type': 'bind', 'source': str(ROOT / 'docker/nginx/default.conf'),
                                'target': '/etc/nginx/conf.d/default.conf', 'read_only': True})

    def reject(self, mutate):
        value = copy.deepcopy(self.config)
        mutate(value)
        with self.assertRaises(ValueError):
            gate.validate(value, self.receipt)

    def test_private_topology_matches_admitted_images(self):
        self.assertEqual(gate.validate(self.config, self.receipt), 'ls-oci-synthetic')

    def test_tags_and_substituted_digests_rejected(self):
        for image in ('ghcr.io/cahangeorge/limesurvey:latest',
                      'ghcr.io/cahangeorge/limesurvey@sha256:' + 'f' * 64):
            self.reject(lambda c: c['services']['app'].update(image=image))

    def test_unverified_artifact_rejected(self):
        self.receipt['components']['php']['signatures'] = 'HOLD'
        with self.assertRaises(ValueError):
            gate.validate(self.config, self.receipt)

    def test_database_publication_and_proxy_attachment_rejected(self):
        self.reject(lambda c: c['services']['db'].update(ports=[{'target': 3306}]))
        self.reject(lambda c: c['services']['db']['networks'].update(proxy={}))
        self.reject(lambda c: c['networks']['database'].update(internal=False))

    def test_app_requires_egress_and_no_public_port(self):
        self.reject(lambda c: c['services']['app']['networks'].pop('egress'))
        self.reject(lambda c: c['services']['app'].update(ports=[{'target': 9000}]))

    def test_public_installer_routing_rejected(self):
        self.reject(lambda c: c['services']['nginx']['ports'][0].update(host_ip='0.0.0.0'))
        self.reject(lambda c: c['services']['nginx']['labels'].update({'traefik.enable': 'true'}))

    def test_old_or_external_volume_rejected(self):
        self.reject(lambda c: c['volumes']['app-upload'].update(name='old-production-upload'))
        self.reject(lambda c: c['volumes']['db-data'].update(external=True))
        self.reject(lambda c: c['volumes']['db-data'].update(driver_opts={'device': '/old-data'}))

    def test_secret_file_permissions_and_inherited_override(self):
        with patch.dict('os.environ', {'OCI_DB_PASSWORD': 'unexpected-override'}), patch.object(
                gate, 'command', return_value=json.dumps(self.config).encode()) as render_command:
            gate.render(self.env)
            self.assertNotIn('OCI_DB_PASSWORD', render_command.call_args.kwargs['env'])
        self.env.chmod(0o644)
        with self.assertRaises(ValueError):
            gate.render(self.env)

    def test_existing_target_resources_rejected(self):
        for outputs in ((b'existing-container',),
                        (b'', b'ls-oci-synthetic-fresh-db\n'),
                        (b'', b'', b'ls-oci-synthetic-egress\nsynthetic-proxy\n')):
            with patch.object(gate, 'command', side_effect=outputs), self.assertRaises(ValueError):
                gate.empty_target(self.config)

    def test_empty_target_requires_existing_proxy(self):
        with patch.object(gate, 'command', side_effect=(b'', b'', b'synthetic-proxy\n')):
            gate.empty_target(self.config)
        with patch.object(gate, 'command', side_effect=(b'', b'', b'')), self.assertRaises(ValueError):
            gate.empty_target(self.config)

    def test_build_command_and_privileged_override_rejected(self):
        for key, value in (('build', {'context': '.'}), ('command', ['sh']), ('privileged', True)):
            self.reject(lambda c: c['services']['app'].update({key: value}))

    def test_reviewed_checkout_rejects_changed_nginx_bind(self):
        sha = 'a' * 40
        expected = (ROOT / 'docker/nginx/default.conf').read_bytes()
        with patch.object(gate, 'command', side_effect=[sha.encode(), b'', b'changed config']):
            with self.assertRaises(ValueError):
                gate.reviewed_checkout({'source_commit': sha})
        with patch.object(gate, 'command', side_effect=[sha.encode(), b'', expected,
                                                       (ROOT / 'deploy/compose.oci-fresh.yaml').read_bytes(),
                                                       (ROOT / 'scripts/delivery/fresh.py').read_bytes()]):
            gate.reviewed_checkout({'source_commit': sha})

    def test_reviewed_checkout_rejects_wrong_source_commit(self):
        with patch.object(gate, 'command', return_value=b'b' * 40):
            with self.assertRaises(ValueError):
                gate.reviewed_checkout({'source_commit': 'a' * 40})


if __name__ == '__main__':
    unittest.main()
