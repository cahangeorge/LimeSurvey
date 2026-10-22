#!/usr/bin/env python3
"""Read-only admission/topology/collision gate for an empty OCI installation."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'deploy/compose.oci-fresh.yaml'
SPEC = importlib.util.spec_from_file_location('fresh_admission', ROOT / 'scripts/ci/staging-release.py')
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)
KINDS = {'app': 'php', 'nginx': 'nginx', 'db': 'mariadb'}
REPOSITORIES = {'php': 'ghcr.io/cahangeorge/limesurvey',
                'nginx': 'ghcr.io/cahangeorge/limesurvey-nginx',
                'mariadb': 'ghcr.io/cahangeorge/limesurvey-mariadb'}
MOUNTS = {'db-data': '/var/lib/mysql', 'app-code': '/var/www/html',
          'app-config': '/var/www/html/application/config', 'app-upload': '/var/www/html/upload',
          'app-plugins': '/var/www/html/plugins', 'app-themes': '/var/www/html/themes',
          'app-runtime': '/var/www/html/tmp'}


def require(condition):
    if not condition:
        raise ValueError('fresh installation requirement failed')


def command(args, env=None):
    result = subprocess.run(args, capture_output=True, timeout=120, env=env)
    require(result.returncode == 0)
    return result.stdout


def render(env_file):
    info = env_file.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600)
    # The protected file is authoritative; inherited OCI_* values cannot override it.
    environment = {key: value for key, value in os.environ.items() if not key.startswith('OCI_')}
    return json.loads(command(['docker', 'compose', '--env-file', str(env_file),
                              '-f', str(ADAPTER), 'config', '--format', 'json'], env=environment))


def validate(config, receipt):
    project = config['name']
    require(re.fullmatch(r'ls-oci-[a-z0-9][a-z0-9-]{3,40}', project))
    require(receipt.get('status') == 'ARTIFACT_BUNDLE_ADMITTED'
            and set(receipt['components']) == set(REPOSITORIES))
    services = config['services']
    require(set(services) == set(KINDS))
    networks = config['networks']
    require(set(networks) == {'database', 'application', 'egress', 'proxy'})
    for name in ('database', 'application', 'egress'):
        require(networks[name]['name'] == project + '-' + name
                and not networks[name].get('external')
                and bool(networks[name].get('internal')) == (name != 'egress'))
    proxy = networks['proxy']
    require(proxy.get('external') is True and isinstance(proxy.get('name'), str)
            and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', proxy['name'])
            and proxy['name'] not in {networks[n]['name'] for n in networks if n != 'proxy'})
    require(set(config['volumes']) == set(MOUNTS))
    for name, volume in config['volumes'].items():
        suffix = 'db' if name == 'db-data' else name.removeprefix('app-')
        require(volume['name'] == project + '-fresh-' + suffix
                and not volume.get('external') and not volume.get('driver_opts'))
    expected_networks = {'db': {'database'}, 'app': {'database', 'application', 'egress'},
                         'nginx': {'application', 'proxy'}}
    for name, service in services.items():
        kind = KINDS[name]
        image = service['image']
        require(re.fullmatch(re.escape(REPOSITORIES[kind]) + r'@sha256:[0-9a-f]{64}', image)
                and image == receipt['components'][kind]['image']
                and receipt['components'][kind].get('scan') == 'PASS'
                and receipt['components'][kind].get('signatures') == 'PASS')
        require(service['platform'] == 'linux/arm64' and service['restart'] == 'unless-stopped'
                and set(service['networks']) == expected_networks[name]
                and service.get('healthcheck', {}).get('test'))
        require(not any(service.get(key) for key in ('build', 'command', 'entrypoint', 'privileged',
                    'network_mode', 'pid', 'ipc', 'devices', 'cap_add', 'volumes_from', 'configs', 'secrets')))
        require(not service.get('ports') if name != 'nginx' else len(service['ports']) == 1)
        mounts = service['volumes']
        required = set(MOUNTS) - {'db-data'} if name == 'app' else (
            {'db-data'} if name == 'db' else {'app-code', 'app-upload', 'app-plugins', 'app-themes', 'app-runtime'})
        volumes = [mount for mount in mounts if mount['type'] == 'volume']
        require(len(volumes) == len(required) and {m['source'] for m in volumes} == required)
        for mount in volumes:
            require(mount['target'] == MOUNTS[mount['source']]
                    and bool(mount.get('read_only')) == (name == 'nginx'))
        binds = [mount for mount in mounts if mount['type'] != 'volume']
        require(not binds if name != 'nginx' else len(binds) == 1)
        if name == 'nginx':
            require(binds[0]['type'] == 'bind' and binds[0]['read_only'] is True
                    and Path(binds[0]['source']) == ROOT / 'docker/nginx/default.conf'
                    and binds[0]['target'] == '/etc/nginx/conf.d/default.conf')
    nginx = services['nginx']
    port = nginx['ports'][0]
    require(port['host_ip'] == '127.0.0.1' and port['target'] == 80
            and 1024 <= int(port['published']) <= 65535 and port['protocol'] == 'tcp'
            and nginx.get('read_only') is True and nginx.get('labels') == {'traefik.enable': 'false'})
    app, db = services['app']['environment'], services['db']['environment']
    require(app['DB_HOST'] == 'db' and str(app['DB_PORT']) == '3306'
            and app['DB_NAME'] == db['MARIADB_DATABASE'] and app['DB_USER'] == db['MARIADB_USER']
            and app['DB_PASSWORD'] == db['MARIADB_PASSWORD']
            and all(db.get(key) for key in ('MARIADB_DATABASE', 'MARIADB_USER', 'MARIADB_PASSWORD', 'MARIADB_ROOT_PASSWORD'))
            and app.get('RESEND_API_KEY') and app.get('RESEND_FROM_EMAIL'))
    return project


def reviewed_checkout(receipt):
    """Bind mounted configuration and admission code to the signed source commit."""
    sha = receipt['source_commit']
    require(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha))
    require(command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip() == sha)
    command(['git', '-C', str(ROOT), 'diff', '--quiet', 'HEAD', '--'])
    for relative in ('docker/nginx/default.conf', 'deploy/compose.oci-fresh.yaml',
                     'scripts/delivery/fresh.py'):
        expected = command(['git', '-C', str(ROOT), 'show', sha + ':' + relative])
        require((ROOT / relative).read_bytes() == expected)


def empty_target(config):
    project = config['name']
    require(not command(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]).strip())
    existing_volumes = set(command(['docker', 'volume', 'ls', '--format', '{{.Name}}']).decode().splitlines())
    require(not existing_volumes.intersection(v['name'] for v in config['volumes'].values()))
    existing_networks = set(command(['docker', 'network', 'ls', '--format', '{{.Name}}']).decode().splitlines())
    require(not existing_networks.intersection(config['networks'][name]['name']
                                               for name in ('database', 'application', 'egress')))
    require(config['networks']['proxy']['name'] in existing_networks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', required=True, type=Path)
    parser.add_argument('--expected-bundle', required=True, type=Path)
    parser.add_argument('--expected-bundle-sha256', required=True)
    args = parser.parse_args()
    try:
        config = render(args.env_file)
        receipt = admission.evaluate(args.expected_bundle, args.expected_bundle_sha256, datetime.now(timezone.utc))
        validate(config, receipt)
        reviewed_checkout(receipt)
        empty_target(config)
        print('fresh_install_preflight=PASS; public routing and runtime acceptance pending')
        return 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        print('fresh_install_preflight=HOLD: configuration, admission or empty-target check failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
